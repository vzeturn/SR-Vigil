//! Launch origin (`docs/18 §3`): did a person start this process, or did something else?
//! A UX gate only (whether to ask a question); it never lowers a score or overrides a rule.

/// Seconds of keyboard/mouse silence after which a launch no longer counts as a human action.
pub const INPUT_WINDOW_SECS: u64 = 5;
/// Children a signed parent must have started before it counts as an agent/IDE.
pub const AGENT_MIN_SPAWNS: u32 = 10;

const SHELLS: [&str; 5] = [
    "explorer.exe",
    "startmenuexperiencehost.exe",
    "searchhost.exe",
    "searchapp.exe",
    "shellexperiencehost.exe",
];
const SERVICE_HOSTS: [&str; 4] = [
    "services.exe",
    "svchost.exe",
    "taskeng.exe",
    "taskhostw.exe",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    User,
    Script,
    Autostart,
    Service,
    Agent,
}

impl Origin {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Script => "script",
            Self::Autostart => "autostart",
            Self::Service => "service",
            Self::Agent => "agent",
        }
    }
}

/// What is known about a newly seen process.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    pub parent_name: &'a str,
    pub parent_signed: bool,
    /// The image is listed in a Run key, startup folder or scheduled task.
    pub autostart: bool,
    /// Seconds since the last keyboard/mouse input in the interactive session.
    pub input_age_secs: u64,
    /// Children this parent has started before (from the local baseline).
    pub parent_spawns: u32,
}

/// Classify one launch. Anything that is not clearly a person, a service or a known agent is a
/// `Script`: the safe default, because it never opens a question.
#[must_use]
pub fn classify(e: &Evidence<'_>) -> Origin {
    let parent = e.parent_name.to_ascii_lowercase();
    if e.autostart {
        Origin::Autostart
    } else if SERVICE_HOSTS.contains(&parent.as_str()) {
        Origin::Service
    } else if SHELLS.contains(&parent.as_str()) && e.input_age_secs <= INPUT_WINDOW_SECS {
        Origin::User
    } else if e.parent_signed && e.parent_spawns >= AGENT_MIN_SPAWNS {
        Origin::Agent
    } else {
        Origin::Script
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Evidence<'static> = Evidence {
        parent_name: "explorer.exe",
        parent_signed: true,
        autostart: false,
        input_age_secs: 1,
        parent_spawns: 0,
    };

    #[test]
    fn a_double_click_is_the_user() {
        assert_eq!(classify(&BASE), Origin::User);
    }

    #[test]
    fn the_shell_without_recent_input_is_not_a_person() {
        let e = Evidence {
            input_age_secs: 60,
            ..BASE
        };
        assert_eq!(classify(&e), Origin::Script);
    }

    #[test]
    fn autostart_and_service_beat_the_shell() {
        let a = Evidence {
            autostart: true,
            ..BASE
        };
        assert_eq!(classify(&a), Origin::Autostart);
        let s = Evidence {
            parent_name: "SVCHOST.EXE",
            ..BASE
        };
        assert_eq!(classify(&s), Origin::Service);
    }

    #[test]
    fn a_busy_signed_parent_is_an_agent_and_a_script_host_is_a_script() {
        let ide = Evidence {
            parent_name: "kiro.exe",
            parent_spawns: 10,
            ..BASE
        };
        assert_eq!(classify(&ide), Origin::Agent);
        let ps = Evidence {
            parent_name: "powershell.exe",
            parent_spawns: 0,
            ..BASE
        };
        assert_eq!(classify(&ps), Origin::Script);
        let unsigned = Evidence {
            parent_signed: false,
            ..ide
        };
        assert_eq!(classify(&unsigned), Origin::Script);
    }
}
