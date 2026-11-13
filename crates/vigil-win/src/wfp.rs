//! Windows Filtering Platform (user-mode filters only, no callout drivers). See `docs/04`.
//!
//! Two engine sessions are used: a **dynamic** one (catch-all, permits, loopback exemption; every
//! object vanishes when the handle closes, so a crashed service never leaves the machine offline)
//! and a **persistent** one (explicit deny filters; survive service stop and reboot).
//! All multi-filter changes go through [`Engine::transaction`] (all-or-nothing) and every filter
//! key is derived from `sha256(identity_key)`, so retries never duplicate filters.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::field_reassign_with_default,
    clippy::redundant_closure_for_method_calls,
    clippy::must_use_candidate,
    clippy::ref_as_ptr
)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use windows::Win32::Foundation::{
    FILETIME, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT8, FWP_UINT32, FWP_VALUE0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS, FWPM_ENGINE_COLLECT_NET_EVENTS,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER_FLAGS, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT1,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmEngineSetOption0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

/// Errors from the WFP layer.
#[derive(Debug, thiserror::Error)]
pub enum WfpError {
    #[error("wfp api: {0}")]
    Api(#[from] windows::core::Error),
    #[error("{0} filters require a {1} session")]
    WrongSession(&'static str, &'static str),
}

type Result<T> = std::result::Result<T, WfpError>;

fn check(rc: u32) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(windows::core::Error::from(windows::core::HRESULT::from_win32(rc)).into())
    }
}

/// Like [`check`] but treats `tolerated` (an HRESULT) as success; returns whether it was hit.
fn check_tolerating(rc: u32, tolerated: windows::core::HRESULT) -> Result<bool> {
    if rc == tolerated.0 as u32 {
        return Ok(true);
    }
    check(rc).map(|()| false)
}

/// Fixed identifiers and deterministic filter keys.
pub mod ids {
    use sha2::{Digest, Sha256};
    use windows::core::GUID;

    pub const PROVIDER_DYNAMIC: GUID = GUID::from_u128(0x6f1d_8b2a_93c4_4e07_a5b1_2d7c_40e9_1a01);
    pub const PROVIDER_PERSISTENT: GUID =
        GUID::from_u128(0x6f1d_8b2a_93c4_4e07_a5b1_2d7c_40e9_1a02);
    pub const SUBLAYER_DYNAMIC: GUID = GUID::from_u128(0x3a9c_51e8_7d26_4b3f_8c40_b6e2_17f5_9d01);
    pub const SUBLAYER_PERSISTENT: GUID =
        GUID::from_u128(0x3a9c_51e8_7d26_4b3f_8c40_b6e2_17f5_9d02);
    /// Persistent denies are evaluated before dynamic permits/catch-all.
    pub const SUBLAYER_WEIGHT_PERSISTENT: u16 = 0xFFFF;
    pub const SUBLAYER_WEIGHT_DYNAMIC: u16 = 0xFF00;

    /// What a filter does. Determines action, weight, and which provider owns it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FilterKind {
        Deny,
        /// Explicit deny of incoming connections (`ALE_AUTH_RECV_ACCEPT`), opt-in (FR-017).
        InboundDeny,
        Loopback,
        Permit,
        CatchAll,
    }

    impl FilterKind {
        pub const ALL: [Self; 5] = [
            Self::Deny,
            Self::InboundDeny,
            Self::Loopback,
            Self::Permit,
            Self::CatchAll,
        ];

        /// Weight within the sublayer (`FWP_UINT8`, 0-15); higher is evaluated first.
        pub const fn weight(self) -> u8 {
            match self {
                Self::Deny | Self::InboundDeny => 15,
                Self::Loopback => 12,
                Self::Permit => 10,
                Self::CatchAll => 1,
            }
        }

        pub const fn is_block(self) -> bool {
            matches!(self, Self::Deny | Self::InboundDeny | Self::CatchAll)
        }

        /// Explicit denies live in the persistent provider, everything else in the dynamic one.
        pub const fn is_persistent(self) -> bool {
            matches!(self, Self::Deny | Self::InboundDeny)
        }

        /// Filters on the receive/accept layer instead of the connect layer.
        pub const fn is_inbound(self) -> bool {
            matches!(self, Self::InboundDeny)
        }

        pub const fn tag(self) -> &'static str {
            match self {
                Self::Deny => "deny",
                Self::InboundDeny => "inbound-deny",
                Self::Loopback => "loopback",
                Self::Permit => "permit",
                Self::CatchAll => "catch-all",
            }
        }
    }

    /// IP family of the ALE connect layer a filter is attached to.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Family {
        V4,
        V6,
    }

    impl Family {
        pub const BOTH: [Self; 2] = [Self::V4, Self::V6];

        const fn tag(self) -> &'static str {
            match self {
                Self::V4 => "v4",
                Self::V6 => "v6",
            }
        }
    }

    /// Identity key reserved for the machine-wide filters.
    pub const CATCH_ALL_IDENTITY: &str = "*catch-all*";
    pub const LOOPBACK_IDENTITY: &str = "*loopback*";

    /// Canonical identity key for an executable path (case-insensitive on Windows).
    pub fn path_identity_key(path: &std::path::Path) -> String {
        path.to_string_lossy().replace('/', "\\").to_lowercase()
    }

    /// `sha256("vigil.wfp.v1" | kind | family | identity_key)[..16]` shaped as a v5-style UUID.
    pub fn filter_key_for(identity_key: &str, kind: FilterKind, family: Family) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(b"vigil.wfp.v1\0")
            .chain_update(kind.tag())
            .chain_update([0])
            .chain_update(family.tag())
            .chain_update([0])
            .chain_update(identity_key.as_bytes())
            .finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        key[6] = (key[6] & 0x0F) | 0x50;
        key[8] = (key[8] & 0x3F) | 0x80;
        key
    }

    /// Key of the IPv4 filter for `identity_key` (see [`filter_keys`] for both families).
    pub fn filter_key(identity_key: &str, kind: FilterKind) -> [u8; 16] {
        filter_key_for(identity_key, kind, Family::V4)
    }

    /// Keys of the IPv4 and IPv6 filters for `identity_key`.
    pub fn filter_keys(identity_key: &str, kind: FilterKind) -> [[u8; 16]; 2] {
        Family::BOTH.map(|f| filter_key_for(identity_key, kind, f))
    }

    pub(super) fn guid(key: [u8; 16]) -> GUID {
        GUID::from_u128(u128::from_be_bytes(key))
    }
}

use ids::{Family, FilterKind};

/// Which provider's objects an operation addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Dynamic,
    Persistent,
}

impl Scope {
    const fn provider(self) -> GUID {
        match self {
            Self::Dynamic => ids::PROVIDER_DYNAMIC,
            Self::Persistent => ids::PROVIDER_PERSISTENT,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Dynamic => "dynamic",
            Self::Persistent => "persistent",
        }
    }
}

/// A filter as read back by enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterInfo {
    pub key: [u8; 16],
    pub id: u64,
    pub name: String,
}

/// Outcome of [`Engine::panic_remove_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PanicReport {
    pub removed: usize,
    pub failed: usize,
}

/// Outcome of [`Engine::rebuild_then_arm`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArmReport {
    pub permitted: usize,
    /// Paths with no resolvable app id (file missing); they get no permit.
    pub skipped: Vec<PathBuf>,
}

/// A WFP engine session handle.
pub struct Engine {
    handle: HANDLE,
    scope: Scope,
}

// SAFETY: a WFP engine handle is an RPC context handle; the WFP client library serialises calls on
// it, so it may be used from, and moved between, any thread.
unsafe impl Send for Engine {}
// SAFETY: see above; all methods take `&self` and only pass the handle to thread-safe WFP calls.
unsafe impl Sync for Engine {}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by a successful `FwpmEngineOpen0` and is closed once.
        let rc = unsafe { FwpmEngineClose0(self.handle) };
        if rc != 0 {
            tracing::warn!(rc, "FwpmEngineClose0 failed");
        }
    }
}

impl Engine {
    /// Dynamic session: provider, sublayer and filters disappear when this handle closes.
    pub fn open_dynamic() -> Result<Self> {
        Self::open(Scope::Dynamic)
    }

    /// Non-dynamic session for persistent deny filters.
    pub fn open_persistent() -> Result<Self> {
        Self::open(Scope::Persistent)
    }

    pub const fn scope(&self) -> Scope {
        self.scope
    }

    fn open(scope: Scope) -> Result<Self> {
        let engine = Self {
            handle: open_handle(scope == Scope::Dynamic)?,
            scope,
        };
        engine.enable_net_events()?;
        engine.register()?;
        Ok(engine)
    }

    /// Global engine option. Real behaviour (recorded in docs/04): WFP refuses
    /// `FwpmEngineSetOption0` from a dynamic session (`FWP_E_DYNAMIC_SESSION_IN_PROGRESS`), so a
    /// dynamic engine sets it through a short-lived non-dynamic handle.
    fn enable_net_events(&self) -> Result<()> {
        let temp = (self.scope == Scope::Dynamic)
            .then(|| {
                open_handle(false).map(|handle| Self {
                    handle,
                    scope: Scope::Persistent,
                })
            })
            .transpose()?;
        let handle = temp.as_ref().map_or(self.handle, |e| e.handle);
        let mut value = FWP_VALUE0::default();
        value.r#type = FWP_UINT32;
        value.Anonymous.uint32 = 1;
        // SAFETY: valid handle and a live, fully initialised FWP_VALUE0.
        check(unsafe {
            FwpmEngineSetOption0(handle, FWPM_ENGINE_COLLECT_NET_EVENTS, &raw const value)
        })
    }

    /// Idempotent: registers this session's provider and sublayer (already-exists is success).
    fn register(&self) -> Result<()> {
        let (persistent, sublayer_key, weight) = match self.scope {
            Scope::Dynamic => (false, ids::SUBLAYER_DYNAMIC, ids::SUBLAYER_WEIGHT_DYNAMIC),
            Scope::Persistent => (
                true,
                ids::SUBLAYER_PERSISTENT,
                ids::SUBLAYER_WEIGHT_PERSISTENT,
            ),
        };
        let mut provider_key = self.scope.provider();
        let name = crate::to_wide(&format!(
            "Vigil.{}",
            if persistent { "Persistent" } else { "Dynamic" }
        ));
        let display =
            windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_ptr().cast_mut()),
                description: PWSTR::null(),
            };
        self.transaction(|_| {
            let mut provider = FWPM_PROVIDER0::default();
            provider.providerKey = provider_key;
            provider.displayData = display;
            provider.flags = if persistent {
                FWPM_PROVIDER_FLAG_PERSISTENT
            } else {
                0
            };
            // SAFETY: valid handle; `provider`/`name` outlive the call; null SD means default.
            check_tolerating(
                unsafe {
                    FwpmProviderAdd0(
                        self.handle,
                        &raw const provider,
                        PSECURITY_DESCRIPTOR::default(),
                    )
                },
                FWP_E_ALREADY_EXISTS,
            )?;
            let mut sublayer = FWPM_SUBLAYER0::default();
            sublayer.subLayerKey = sublayer_key;
            sublayer.displayData = display;
            sublayer.flags = if persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            };
            sublayer.providerKey = &raw mut provider_key;
            sublayer.weight = weight;
            // SAFETY: as above; `provider_key` outlives the call.
            check_tolerating(
                unsafe {
                    FwpmSubLayerAdd0(
                        self.handle,
                        &raw const sublayer,
                        PSECURITY_DESCRIPTOR::default(),
                    )
                },
                FWP_E_ALREADY_EXISTS,
            )?;
            Ok(())
        })
    }

    /// Runs `f` inside `FwpmTransactionBegin0/Commit0`; any error (or panic) aborts everything.
    pub fn transaction<T>(&self, f: impl FnOnce(&Tx<'_>) -> Result<T>) -> Result<T> {
        // SAFETY: valid handle.
        check(unsafe { FwpmTransactionBegin0(self.handle, 0) })?;
        let outcome = catch_unwind(AssertUnwindSafe(|| f(&Tx { engine: self })));
        let result = match outcome {
            Ok(Ok(v)) => {
                // SAFETY: valid handle with an open transaction.
                check(unsafe { FwpmTransactionCommit0(self.handle) }).map(|()| v)
            }
            Ok(Err(e)) => Err(e),
            Err(panic) => {
                self.abort();
                resume_unwind(panic);
            }
        };
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn abort(&self) {
        // SAFETY: valid handle; aborting without an open transaction just returns an error.
        let rc = unsafe { FwpmTransactionAbort0(self.handle) };
        if rc != 0 {
            tracing::debug!(rc, "FwpmTransactionAbort0 returned an error");
        }
    }

    /// Permit `path` (dynamic session). Adds the IPv4 and IPv6 filters atomically.
    pub fn add_permit(&self, path: &Path) -> Result<()> {
        self.transaction(|tx| tx.put_permit(path))
    }

    /// Persistent deny for `path` (persistent session).
    pub fn add_deny(&self, path: &Path) -> Result<()> {
        self.transaction(|tx| tx.put_deny(path))
    }

    /// Machine-wide catch-all block, weight 1 (dynamic session). Call only via
    /// [`rebuild_then_arm`](Self::rebuild_then_arm) in production.
    pub fn add_catch_all_block(&self) -> Result<()> {
        self.transaction(|tx| tx.put_catch_all())
    }

    /// Loopback exemption permit, weight 12 (dynamic session).
    pub fn add_loopback_permit(&self) -> Result<()> {
        self.transaction(|tx| tx.put_loopback())
    }

    /// Removes one filter by key; `Ok(false)` when it did not exist (idempotent).
    pub fn remove_filter(&self, key: &[u8; 16]) -> Result<bool> {
        let guid = ids::guid(*key);
        // SAFETY: valid handle; `guid` outlives the call.
        let missing = check_tolerating(
            unsafe { FwpmFilterDeleteByKey0(self.handle, &raw const guid) },
            FWP_E_FILTER_NOT_FOUND,
        )?;
        Ok(!missing)
    }

    /// Removes the v4 and v6 filters of one identity/kind atomically.
    pub fn remove_identity(&self, identity_key: &str, kind: FilterKind) -> Result<()> {
        self.transaction(|_| {
            for key in ids::filter_keys(identity_key, kind) {
                self.remove_filter(&key)?;
            }
            Ok(())
        })
    }

    pub fn remove_all_dynamic(&self) -> Result<usize> {
        self.remove_all(Scope::Dynamic)
    }

    pub fn remove_all_persistent(&self) -> Result<usize> {
        self.remove_all(Scope::Persistent)
    }

    /// Uninstall: removes every persistent filter, then the persistent sublayer and provider so
    /// nothing of Vigil remains in `netsh wfp show filters`. Missing objects are not an error.
    pub fn remove_persistent_objects(&self) -> Result<usize> {
        let removed = self.remove_all(Scope::Persistent)?;
        self.transaction(|_| {
            let sub = ids::SUBLAYER_PERSISTENT;
            let prov = ids::PROVIDER_PERSISTENT;
            // SAFETY: valid handle; key pointers are valid for the call.
            check_tolerating(
                unsafe { FwpmSubLayerDeleteByKey0(self.handle, &raw const sub) },
                FWP_E_SUBLAYER_NOT_FOUND,
            )?;
            // SAFETY: as above.
            check_tolerating(
                unsafe { FwpmProviderDeleteByKey0(self.handle, &raw const prov) },
                FWP_E_PROVIDER_NOT_FOUND,
            )?;
            Ok(())
        })?;
        Ok(removed)
    }

    fn remove_all(&self, scope: Scope) -> Result<usize> {
        self.transaction(|_| {
            let filters = self.list_filters(scope)?;
            for f in &filters {
                self.remove_filter(&f.key)?;
            }
            Ok(filters.len())
        })
    }

    /// Panic button: removes every Vigil filter of both providers, best effort and without a
    /// transaction (one failure must not keep the rest in place).
    pub fn panic_remove_all(&self) -> PanicReport {
        let mut report = PanicReport::default();
        for scope in [Scope::Dynamic, Scope::Persistent] {
            match self.list_filters(scope) {
                Ok(filters) => {
                    for f in filters {
                        match self.remove_filter(&f.key) {
                            Ok(_) => report.removed += 1,
                            Err(e) => {
                                tracing::error!(error = %e, "panic: filter removal failed");
                                report.failed += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, scope = scope.label(), "panic: enumeration failed");
                    report.failed += 1;
                }
            }
        }
        report
    }

    /// Every filter owned by the given Vigil provider.
    pub fn list_filters(&self, scope: Scope) -> Result<Vec<FilterInfo>> {
        const BATCH: u32 = 100;
        let provider = scope.provider();
        let mut enum_handle = HANDLE::default();
        // SAFETY: valid handle; a null template enumerates all filters; out pointer is valid.
        check(unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &raw mut enum_handle) })?;
        let mut out = Vec::new();
        let result = (|| -> Result<()> {
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut n = 0u32;
                // SAFETY: valid handle/enum handle; out pointers are valid.
                check(unsafe {
                    FwpmFilterEnum0(
                        self.handle,
                        enum_handle,
                        BATCH,
                        &raw mut entries,
                        &raw mut n,
                    )
                })?;
                for i in 0..n as usize {
                    // SAFETY: WFP returned `n` valid entry pointers, valid until FwpmFreeMemory0.
                    let f = unsafe { &**entries.add(i) };
                    // SAFETY: `providerKey` is null or points to a GUID owned by the entry.
                    let owned = !f.providerKey.is_null() && unsafe { *f.providerKey } == provider;
                    if owned {
                        let name = if f.displayData.name.is_null() {
                            String::new()
                        } else {
                            // SAFETY: non-null, NUL-terminated wide string owned by the entry.
                            unsafe { f.displayData.name.to_string() }.unwrap_or_default()
                        };
                        out.push(FilterInfo {
                            key: f.filterKey.to_u128().to_be_bytes(),
                            id: f.filterId,
                            name,
                        });
                    }
                }
                if !entries.is_null() {
                    let mut p = entries.cast::<c_void>();
                    // SAFETY: `entries` was allocated by FwpmFilterEnum0.
                    unsafe { FwpmFreeMemory0(&raw mut p) };
                }
                if n < BATCH {
                    return Ok(());
                }
            }
        })();
        // SAFETY: `enum_handle` was created above and is destroyed once.
        let rc = unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
        if rc != 0 {
            tracing::debug!(rc, "FwpmFilterDestroyEnumHandle0 failed");
        }
        result.map(|()| out)
    }

    /// Startup ordering (docs/04 section 1): permits and loopback first (one transaction),
    /// catch-all only afterwards (its own transaction). Paths whose app id cannot be resolved are
    /// reported, not fatal. If any permit fails the catch-all is **not** armed.
    pub fn rebuild_then_arm(&self, permits: &[PathBuf]) -> Result<ArmReport> {
        let report = self.transaction(|tx| {
            tx.put_loopback()?;
            let mut report = ArmReport::default();
            for path in permits {
                match tx.put_permit(path) {
                    Ok(()) => report.permitted += 1,
                    Err(WfpError::Api(_)) if !path.exists() => {
                        tracing::warn!(path = %path.display(), "permit skipped: no app id");
                        report.skipped.push(path.clone());
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(report)
        })?;
        self.add_catch_all_block()?;
        Ok(report)
    }

    /// Subscribes to `CLASSIFY_DROP` events. Dropping the subscription unsubscribes.
    pub fn subscribe_drops(
        &self,
    ) -> Result<(NetEventSubscription<'_>, UnboundedReceiver<DropEvent>)> {
        let (tx, rx) = unbounded_channel();
        let ctx = Box::into_raw(Box::new(EventContext {
            tx,
            closed: AtomicBool::new(false),
            dos_map: Mutex::new(Vec::new()),
        }));
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut handle = HANDLE::default();
        // SAFETY: valid handle; `ctx` is a leaked Box that stays valid forever (never freed, see
        // `NetEventSubscription::drop`); the callback is `extern "system"` and never unwinds.
        let rc = unsafe {
            FwpmNetEventSubscribe0(
                self.handle,
                &raw const subscription,
                Some(on_net_event),
                Some(ctx.cast_const().cast::<c_void>()),
                &raw mut handle,
            )
        };
        if let Err(e) = check(rc) {
            // SAFETY: the subscription failed, so WFP holds no copy of `ctx`.
            drop(unsafe { Box::from_raw(ctx) });
            return Err(e);
        }
        Ok((
            NetEventSubscription {
                engine: self,
                handle,
                ctx,
            },
            rx,
        ))
    }
}

fn open_handle(dynamic: bool) -> Result<HANDLE> {
    let name = crate::to_wide("Vigil");
    let mut session = FWPM_SESSION0::default();
    session.displayData.name = PWSTR(name.as_ptr().cast_mut());
    session.flags = if dynamic {
        FWPM_SESSION_FLAG_DYNAMIC
    } else {
        0
    };
    session.txnWaitTimeoutInMSec = 10_000;
    let mut handle = HANDLE::default();
    // SAFETY: `session` and `name` outlive the call; `handle` is a valid out pointer.
    check(unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&raw const session),
            &raw mut handle,
        )
    })?;
    Ok(handle)
}

/// Filter operations valid inside [`Engine::transaction`].
pub struct Tx<'e> {
    engine: &'e Engine,
}

impl Tx<'_> {
    pub fn put_permit(&self, path: &Path) -> Result<()> {
        self.put_app(FilterKind::Permit, path, Scope::Dynamic)
    }

    pub fn put_deny(&self, path: &Path) -> Result<()> {
        self.put_app(FilterKind::Deny, path, Scope::Persistent)
    }

    /// Persistent deny of incoming connections to `path` (FR-017).
    pub fn put_inbound_deny(&self, path: &Path) -> Result<()> {
        self.put_app(FilterKind::InboundDeny, path, Scope::Persistent)
    }

    pub fn put_catch_all(&self) -> Result<()> {
        self.put_both(
            FilterKind::CatchAll,
            ids::CATCH_ALL_IDENTITY,
            Scope::Dynamic,
            &mut [],
            "",
        )
    }

    pub fn put_loopback(&self) -> Result<()> {
        let mut cond = FWPM_FILTER_CONDITION0::default();
        cond.fieldKey = FWPM_CONDITION_FLAGS;
        cond.matchType = FWP_MATCH_FLAGS_ALL_SET;
        cond.conditionValue.r#type = FWP_UINT32;
        cond.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        self.put_both(
            FilterKind::Loopback,
            ids::LOOPBACK_IDENTITY,
            Scope::Dynamic,
            &mut [cond],
            "",
        )
    }

    /// `scope` selects the owning provider; production callers always pass the kind's natural
    /// scope (`Deny` is persistent), tests may force a dynamic deny.
    fn put_app(&self, kind: FilterKind, path: &Path, scope: Scope) -> Result<()> {
        let app = AppId::from_path(path)?;
        let mut cond = FWPM_FILTER_CONDITION0::default();
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue = FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
        };
        let identity = ids::path_identity_key(path);
        let desc = path.display().to_string();
        self.put_both(kind, &identity, scope, &mut [cond], &desc)
    }

    fn put_both(
        &self,
        kind: FilterKind,
        identity: &str,
        scope: Scope,
        conds: &mut [FWPM_FILTER_CONDITION0],
        desc: &str,
    ) -> Result<()> {
        if self.engine.scope != scope {
            return Err(WfpError::WrongSession(kind.tag(), scope.label()));
        }
        for family in Family::BOTH {
            self.put_one(kind, identity, family, scope, conds, desc)?;
        }
        Ok(())
    }

    fn put_one(
        &self,
        kind: FilterKind,
        identity: &str,
        family: Family,
        scope: Scope,
        conds: &mut [FWPM_FILTER_CONDITION0],
        desc: &str,
    ) -> Result<()> {
        let persistent = scope == Scope::Persistent;
        let name = crate::to_wide(&format!("Vigil {kind:?} {family:?}"));
        let description = crate::to_wide(desc);
        let mut provider = scope.provider();
        let mut f = FWPM_FILTER0::default();
        f.filterKey = ids::guid(ids::filter_key_for(identity, kind, family));
        f.displayData.name = PWSTR(name.as_ptr().cast_mut());
        f.displayData.description = PWSTR(description.as_ptr().cast_mut());
        f.flags = if persistent {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            FWPM_FILTER_FLAGS(0)
        };
        f.providerKey = &raw mut provider;
        f.layerKey = match (kind.is_inbound(), family) {
            (false, Family::V4) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            (false, Family::V6) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            (true, Family::V4) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            (true, Family::V6) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        };
        f.subLayerKey = if persistent {
            ids::SUBLAYER_PERSISTENT
        } else {
            ids::SUBLAYER_DYNAMIC
        };
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = kind.weight();
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = if conds.is_empty() {
            ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        };
        f.action.r#type = action_type(kind);
        // SAFETY: valid handle; every pointer in `f` (name, provider, conditions and the app-id
        // blob they reference) outlives the call; null SD means default security; id is optional.
        check_tolerating(
            unsafe {
                FwpmFilterAdd0(
                    self.engine.handle,
                    &raw const f,
                    PSECURITY_DESCRIPTOR::default(),
                    None,
                )
            },
            FWP_E_ALREADY_EXISTS,
        )?;
        Ok(())
    }
}

const fn action_type(kind: FilterKind) -> FWP_ACTION_TYPE {
    if kind.is_block() {
        FWP_ACTION_BLOCK
    } else {
        FWP_ACTION_PERMIT
    }
}

/// RAII wrapper over the blob from `FwpmGetAppIdFromFileName0`.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn from_path(path: &Path) -> Result<Self> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `blob` is a valid out pointer.
        check(unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &raw mut blob) })?;
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        // SAFETY: the blob was allocated by WFP and is freed exactly once.
        unsafe { FwpmFreeMemory0(&raw mut p) };
    }
}

/// A blocked connection reported by WFP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropEvent {
    /// Win32 path (`C:\...`) when the NT device path could be mapped, else the raw NT path.
    pub app_path: String,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub filter_id: u64,
    pub timestamp: SystemTime,
}

struct EventContext {
    tx: UnboundedSender<DropEvent>,
    closed: AtomicBool,
    dos_map: Mutex<Vec<(String, String)>>,
}

/// Active `CLASSIFY_DROP` subscription; unsubscribes on drop.
pub struct NetEventSubscription<'e> {
    engine: &'e Engine,
    handle: HANDLE,
    ctx: *mut EventContext,
}

// SAFETY: `ctx` points to a leaked, `Sync` EventContext; `handle` is a thread-safe WFP handle.
unsafe impl Send for NetEventSubscription<'_> {}

impl Drop for NetEventSubscription<'_> {
    fn drop(&mut self) {
        // SAFETY: valid engine and subscription handles; unsubscribed once.
        let rc = unsafe { FwpmNetEventUnsubscribe0(self.engine.handle, self.handle) };
        if rc != 0 {
            tracing::warn!(rc, "FwpmNetEventUnsubscribe0 failed");
        }
        // SAFETY: the context is intentionally never freed (a callback may still be running when
        // unsubscribe returns), so the pointer is always valid; we only flag it closed.
        unsafe { (*self.ctx).closed.store(true, Ordering::Release) };
    }
}

unsafe extern "system" fn on_net_event(context: *mut c_void, event: *const FWPM_NET_EVENT1) {
    // Never unwind across the FFI boundary.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if context.is_null() || event.is_null() {
            return;
        }
        // SAFETY: `context` is the leaked EventContext passed at subscribe time; `event` is valid
        // for the duration of this callback.
        let (ctx, event) = unsafe { (&*context.cast::<EventContext>(), &*event) };
        if ctx.closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(drop_event) = parse_drop(event, ctx) {
            let _ = ctx.tx.send(drop_event);
        }
    }));
}

fn parse_drop(event: &FWPM_NET_EVENT1, ctx: &EventContext) -> Option<DropEvent> {
    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return None;
    }
    // SAFETY: for CLASSIFY_DROP the union member is `classifyDrop`, null or valid.
    let drop = unsafe { event.Anonymous.classifyDrop };
    if drop.is_null() {
        return None;
    }
    // SAFETY: non-null pointer owned by the event.
    let filter_id = unsafe { (*drop).filterId };
    let h = &event.header;
    if h.flags & FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET == 0
        || h.flags & FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET == 0
    {
        return None;
    }
    let remote_addr = if h.ipVersion == FWP_IP_VERSION_V6 {
        // SAFETY: IPv6 header, so `remoteAddrV6` is the active member.
        IpAddr::V6(Ipv6Addr::from(unsafe {
            h.Anonymous2.remoteAddrV6.byteArray16
        }))
    } else {
        // SAFETY: IPv4 header; the address is in host byte order.
        IpAddr::V4(Ipv4Addr::from(unsafe { h.Anonymous2.remoteAddrV4 }))
    };
    let nt_path = if h.appId.data.is_null() || h.appId.size < 2 {
        String::new()
    } else {
        // SAFETY: WFP guarantees `size` readable bytes at `data` for the callback's duration.
        let bytes = unsafe { std::slice::from_raw_parts(h.appId.data, h.appId.size as usize) };
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&wide)
            .trim_end_matches('\0')
            .to_owned()
    };
    Some(DropEvent {
        app_path: resolve_path(&nt_path, ctx),
        remote_addr,
        remote_port: h.remotePort,
        filter_id,
        timestamp: filetime_to_system(h.timeStamp),
    })
}

fn filetime_to_system(ft: FILETIME) -> SystemTime {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    UNIX_EPOCH + Duration::from_nanos(ticks.saturating_sub(EPOCH_DIFF_100NS).saturating_mul(100))
}

/// Maps `\device\harddiskvolumeN\rest` to `C:\rest` using `(device, "C:")` pairs.
fn nt_to_dos(nt: &str, map: &[(String, String)]) -> Option<String> {
    let lower = nt.to_lowercase();
    map.iter().find_map(|(device, drive)| {
        let rest = lower.strip_prefix(&device.to_lowercase())?;
        if !(rest.is_empty() || rest.starts_with('\\')) {
            return None;
        }
        // `to_lowercase` can change byte lengths only for exotic chars; guard the slice.
        nt.get(device.len()..).map(|tail| format!("{drive}{tail}"))
    })
}

fn query_dos_map() -> Vec<(String, String)> {
    ('A'..='Z')
        .filter_map(|letter| {
            let drive = format!("{letter}:");
            let wide = crate::to_wide(&drive);
            let mut buf = [0u16; 520];
            // SAFETY: `wide` is NUL-terminated; `buf` is writable for its full length.
            let n = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
            (n > 0).then(|| {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
                (String::from_utf16_lossy(&buf[..end]), drive)
            })
        })
        .collect()
}

fn resolve_path(nt: &str, ctx: &EventContext) -> String {
    resolve_with(nt, &ctx.dos_map)
}

/// `\Device\HarddiskVolumeN\rest` as `C:\rest` (ETW reports images this way); other paths
/// unchanged.
#[must_use]
pub fn dos_path(nt: &str) -> String {
    static MAP: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    resolve_with(nt, &MAP)
}

fn resolve_with(nt: &str, map: &Mutex<Vec<(String, String)>>) -> String {
    if !nt.to_lowercase().starts_with("\\device\\") {
        return nt.to_owned();
    }
    let mut map = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(p) = nt_to_dos(nt, &map) {
        return p;
    }
    *map = query_dos_map(); // volumes may have been mounted since the last event
    nt_to_dos(nt, &map).unwrap_or_else(|| nt.to_owned())
}

#[cfg(test)]
mod tests {
    use super::ids::{filter_key, filter_key_for, filter_keys};
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn weights_follow_docs_04() {
        let w: Vec<u8> = FilterKind::ALL.iter().map(|k| k.weight()).collect();
        assert_eq!(w, [15, 15, 12, 10, 1]);
        assert!(FilterKind::ALL.iter().all(|k| k.weight() <= 15));
    }

    #[test]
    fn only_denies_are_persistent_and_only_denies_and_catch_all_block() {
        for k in FilterKind::ALL {
            assert_eq!(
                k.is_persistent(),
                matches!(k, FilterKind::Deny | FilterKind::InboundDeny)
            );
            assert_eq!(k.is_inbound(), k == FilterKind::InboundDeny);
            assert_eq!(
                k.is_block(),
                matches!(
                    k,
                    FilterKind::Deny | FilterKind::InboundDeny | FilterKind::CatchAll
                )
            );
        }
        assert_eq!(action_type(FilterKind::CatchAll), FWP_ACTION_BLOCK);
        assert_eq!(action_type(FilterKind::Loopback), FWP_ACTION_PERMIT);
    }

    #[test]
    fn keys_are_deterministic_and_distinct() {
        let a = filter_key("c:\\app.exe", FilterKind::Permit);
        assert_eq!(a, filter_key("c:\\app.exe", FilterKind::Permit));
        let mut all = std::collections::HashSet::new();
        for id in ["c:\\a.exe", "c:\\b.exe"] {
            for k in FilterKind::ALL {
                for f in Family::BOTH {
                    assert!(all.insert(filter_key_for(id, k, f)), "collision");
                }
            }
        }
        assert_eq!(all.len(), 2 * FilterKind::ALL.len() * Family::BOTH.len());
        let [v4, v6] = filter_keys("c:\\a.exe", FilterKind::Deny);
        assert_ne!(v4, v6);
        assert_eq!(v4, filter_key("c:\\a.exe", FilterKind::Deny));
    }

    #[test]
    fn keys_carry_uuid_version_bits_and_fixed_vector() {
        let k = filter_key("x", FilterKind::Permit);
        assert_eq!(k[6] >> 4, 5);
        assert_eq!(k[8] >> 6, 0b10);
        // Regression vector: changing the derivation would orphan persistent filters on upgrade.
        let digest = Sha256::digest(b"vigil.wfp.v1\0permit\0v4\0x");
        assert_eq!(k[..6], digest[..6]);
        assert_eq!(k[7], digest[7]);
    }

    #[test]
    fn path_identity_is_case_and_slash_insensitive() {
        assert_eq!(
            ids::path_identity_key(Path::new("C:/Windows/System32/Curl.EXE")),
            ids::path_identity_key(Path::new("c:\\windows\\system32\\curl.exe"))
        );
    }

    #[test]
    fn fixed_guids_are_unique() {
        let g = [
            ids::PROVIDER_DYNAMIC,
            ids::PROVIDER_PERSISTENT,
            ids::SUBLAYER_DYNAMIC,
            ids::SUBLAYER_PERSISTENT,
        ];
        let set: std::collections::HashSet<u128> = g.iter().map(GUID::to_u128).collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn nt_paths_map_to_drive_letters() {
        let map = vec![
            ("\\Device\\HarddiskVolume3".to_owned(), "C:".to_owned()),
            ("\\Device\\HarddiskVolume30".to_owned(), "D:".to_owned()),
        ];
        assert_eq!(
            nt_to_dos("\\device\\harddiskvolume3\\Windows\\a.exe", &map).as_deref(),
            Some("C:\\Windows\\a.exe")
        );
        assert_eq!(
            nt_to_dos("\\Device\\HarddiskVolume30\\x.exe", &map).as_deref(),
            Some("D:\\x.exe")
        );
        assert_eq!(nt_to_dos("\\Device\\HarddiskVolume9\\x.exe", &map), None);
    }

    #[test]
    fn filetime_converts_to_unix_time() {
        let unix_epoch = FILETIME {
            dwLowDateTime: 0xD53E_8000,
            dwHighDateTime: 0x019D_B1DE,
        };
        assert_eq!(filetime_to_system(unix_epoch), UNIX_EPOCH);
    }
}

/// Live tests: dynamic sessions only, elevated shell required. Nothing here ever installs a
/// machine-wide block; the only block filter is scoped to a throwaway exe that is never run.
#[cfg(all(test, feature = "integration"))]
mod live {
    use super::*;

    struct Throwaway(PathBuf);

    impl Throwaway {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("vigil-wfp-{tag}-{}.exe", std::process::id()));
            std::fs::write(&p, b"not an executable").expect("write throwaway file");
            Self(p)
        }
    }

    impl Drop for Throwaway {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn keys(e: &Engine) -> Vec<[u8; 16]> {
        e.list_filters(Scope::Dynamic)
            .expect("enumerate")
            .into_iter()
            .map(|f| f.key)
            .collect()
    }

    #[test]
    fn open_and_register_are_idempotent() {
        let _a = Engine::open_dynamic().expect("first dynamic session");
        let _b = Engine::open_dynamic().expect("second dynamic session (provider exists)");
    }

    #[test]
    fn scoped_deny_appears_then_is_removed() {
        let engine = Engine::open_dynamic().expect("open");
        let file = Throwaway::new("deny");
        let id = ids::path_identity_key(&file.0);
        engine
            .transaction(|tx| tx.put_app(FilterKind::Deny, &file.0, Scope::Dynamic))
            .expect("add scoped deny");
        engine
            .transaction(|tx| tx.put_app(FilterKind::Deny, &file.0, Scope::Dynamic))
            .expect("idempotent");
        let present = keys(&engine);
        for k in filter_keys_of(&id, FilterKind::Deny) {
            assert!(present.contains(&k), "deny filter missing from enumeration");
        }
        engine
            .remove_identity(&id, FilterKind::Deny)
            .expect("remove");
        let after = keys(&engine);
        for k in filter_keys_of(&id, FilterKind::Deny) {
            assert!(!after.contains(&k), "deny filter still present");
        }
    }

    #[test]
    fn inbound_deny_is_added_on_the_accept_layer_and_removed() {
        let engine = Engine::open_dynamic().expect("open");
        let file = Throwaway::new("inbound");
        let id = ids::path_identity_key(&file.0);
        engine
            .transaction(|tx| tx.put_app(FilterKind::InboundDeny, &file.0, Scope::Dynamic))
            .expect("add inbound deny");
        let present = keys(&engine);
        for k in filter_keys_of(&id, FilterKind::InboundDeny) {
            assert!(present.contains(&k), "inbound deny missing");
        }
        for k in filter_keys_of(&id, FilterKind::Deny) {
            assert!(
                !present.contains(&k),
                "an inbound deny must not block outbound"
            );
        }
        engine
            .remove_identity(&id, FilterKind::InboundDeny)
            .expect("remove");
        assert!(
            filter_keys_of(&id, FilterKind::InboundDeny)
                .iter()
                .all(|k| !keys(&engine).contains(k))
        );
    }

    fn filter_keys_of(id: &str, kind: FilterKind) -> [[u8; 16]; 2] {
        ids::filter_keys(id, kind)
    }

    #[test]
    fn failed_transaction_rolls_back() {
        let engine = Engine::open_dynamic().expect("open");
        let file = Throwaway::new("rollback");
        let id = ids::path_identity_key(&file.0);
        let res: Result<()> = engine.transaction(|tx| {
            tx.put_permit(&file.0)?;
            tx.put_permit(Path::new("C:\\definitely\\missing\\vigil.exe"))
        });
        assert!(res.is_err());
        assert!(!keys(&engine).contains(&ids::filter_key(&id, FilterKind::Permit)));
    }

    #[test]
    fn permit_and_loopback_round_trip_and_wrong_session_is_refused() {
        let engine = Engine::open_dynamic().expect("open");
        let file = Throwaway::new("permit");
        engine.add_loopback_permit().expect("loopback");
        engine.add_permit(&file.0).expect("permit");
        let present = keys(&engine);
        assert!(present.contains(&ids::filter_key(
            ids::LOOPBACK_IDENTITY,
            FilterKind::Loopback
        )));
        assert!(matches!(
            engine.add_deny(&file.0),
            Err(WfpError::WrongSession(..))
        ));
        // Remove only our own keys: a real VigilSvc on this host must not be disturbed.
        engine
            .remove_identity(&ids::path_identity_key(&file.0), FilterKind::Permit)
            .expect("rm permit");
        engine
            .remove_identity(ids::LOOPBACK_IDENTITY, FilterKind::Loopback)
            .expect("rm loopback");
        assert!(!keys(&engine).contains(&ids::filter_key(
            ids::LOOPBACK_IDENTITY,
            FilterKind::Loopback
        )));
    }

    #[test]
    fn net_event_subscription_opens_and_closes() {
        let engine = Engine::open_dynamic().expect("open");
        let (sub, mut rx) = engine.subscribe_drops().expect("subscribe");
        assert!(rx.try_recv().is_err());
        drop(sub);
    }
}
