//! Host hardening posture (`docs/20 §3`): which Microsoft Defender Attack Surface Reduction (ASR)
//! rules are on. Vigil only reports; it never changes Defender settings (`CLAUDE.md` rule 4).

use std::fmt;

/// ASR rules that close the gaps Vigil's own rules cannot see (document and script launchers,
/// credential theft, persistence, vulnerable drivers). `(rule GUID, what it blocks)`.
pub const RECOMMENDED_ASR: &[(&str, &str)] = &[
    (
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
        "Credential theft from LSASS",
    ),
    (
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "Office apps starting child processes",
    ),
    (
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
        "Executable content from email",
    ),
    (
        "d3e037e1-3eb8-44c8-a917-57927947596d",
        "Scripts launching downloaded programs",
    ),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Obfuscated scripts"),
    (
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
        "Office macros calling Win32 APIs",
    ),
    (
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
        "Untrusted programs run from USB",
    ),
    (
        "e6db77e5-3df2-4cf1-b95a-636979351e5b",
        "Persistence through WMI subscriptions",
    ),
    (
        "56a863a9-875e-4185-98a7-b882c64b5ce5",
        "Abuse of vulnerable signed drivers",
    ),
    (
        "d1e49aac-8f56-4280-b9ba-993a6d77406c",
        "Process creation from PsExec and WMI",
    ),
    (
        "01443614-cd74-433a-b99e-2ecdc07bfc25",
        "Programs that are not widely used or trusted",
    ),
];

/// State of one ASR rule as Windows stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsrState {
    NotConfigured,
    Disabled,
    Block,
    Audit,
    Warn,
}

impl AsrState {
    /// From the stored value (`0` off, `1` block, `2` audit, `6` warn); anything else is unset.
    #[must_use]
    pub fn from_value(v: Option<u32>) -> Self {
        match v {
            Some(0) => Self::Disabled,
            Some(1) => Self::Block,
            Some(2) => Self::Audit,
            Some(6) => Self::Warn,
            _ => Self::NotConfigured,
        }
    }

    /// Whether the rule actually stops the behaviour.
    #[must_use]
    pub fn enforces(self) -> bool {
        matches!(self, Self::Block | Self::Warn)
    }
}

impl fmt::Display for AsrState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => "not configured",
            Self::Disabled => "off",
            Self::Block => "block",
            Self::Audit => "audit",
            Self::Warn => "warn",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_block_and_warn_enforce_and_unknown_values_are_unset() {
        let all = [
            (None, false),
            (Some(0), false),
            (Some(1), true),
            (Some(2), false),
            (Some(6), true),
            (Some(9), false),
        ];
        for (v, enforced) in all {
            assert_eq!(AsrState::from_value(v).enforces(), enforced, "{v:?}");
        }
        assert_eq!(AsrState::from_value(Some(9)), AsrState::NotConfigured);
    }

    #[test]
    fn recommended_guids_are_unique_lowercase_guids() {
        let mut seen = std::collections::HashSet::new();
        for (id, _) in RECOMMENDED_ASR {
            assert_eq!(id.len(), 36);
            assert_eq!(*id, id.to_lowercase());
            assert!(seen.insert(*id), "{id}");
        }
    }
}
