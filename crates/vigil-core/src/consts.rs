//! Fixed constants. Single source of truth; mirrored in `docs/03`, `CLAUDE.md` and `schemas/`.

/// Lowest possible score.
pub const SCORE_MIN: u8 = 0;
/// Highest possible score.
pub const SCORE_MAX: u8 = 100;
/// Starting score before any signal is applied.
pub const SCORE_BASELINE: u8 = 50;
/// Scores at or above this value are `safe`.
pub const SAFE_MIN: u8 = 80;
/// Scores at or below this value are `malicious`; `30..=79` is `unknown`.
pub const MALICIOUS_MAX: u8 = 29;

/// Operating modes.
pub const MODES: [&str; 3] = ["observe", "learning", "enforce"];
/// Verdicts.
pub const VERDICTS: [&str; 3] = ["safe", "unknown", "malicious"];
/// Decision actions.
pub const DECISION_ACTIONS: [&str; 3] = ["allow", "block", "kill"];
/// Decision scopes.
pub const DECISION_SCOPES: [&str; 4] = ["once", "1h", "24h", "forever"];
/// What a decision applies to.
pub const DECISION_APPLY_TO: [&str; 3] = ["file", "publisher", "package_source"];

/// Named pipe of the control channel.
pub const PIPE_NAME: &str = r"\.\pipe\vigil-control";
/// IPC protocol version.
pub const PROTOCOL_VERSION: u32 = 1;
/// Windows service name.
pub const SERVICE_NAME: &str = "VigilSvc";
/// Data directory (ACL: SYSTEM + Administrators only), under `%ProgramData%`.
pub const DATA_DIR_NAME: &str = "Vigil";
/// Command-line tool name.
pub const CLI_NAME: &str = "vigilctl";
/// Directory (under the data dir) holding rule-pack overrides.
pub const RULES_OVERRIDE_DIR: &str = "rules.d";
/// Maximum IPC frame size in bytes (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
