//! Safety gates for AI Auto mode (`docs/06 §4`). Pure: the service gathers the inputs, this
//! module only answers "may the AI decide, and what exactly".

/// Minimum rule score for an automatic allow.
pub const ALLOW_MIN_SCORE: i32 = 40;
/// Below the score floor the advisor may still allow (no hard rule fired: a weak score alone, such
/// as an unsigned developer tool, is exactly what it is there to judge) at this confidence.
pub const ALLOW_LOW_SCORE_CONFIDENCE: f64 = 0.95;
/// Auto kill needs at least this confidence.
pub const KILL_MIN_CONFIDENCE: f64 = 0.95;
/// Auto kill needs a rule score at or below this.
pub const KILL_MAX_SCORE: i32 = 49;
/// Hours of learning during which the AI never decides.
pub const LEARNING_GRACE_HOURS: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    HardRule,
    NotConfident,
    NoAction,
    VerdictMismatch,
    ScoreTooLow,
    ScoreTooHigh,
    KillNotEnabled,
    NeverKill,
    LearningGrace,
    Unstable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Leave it Pending for the user.
    Skip(Skip),
    /// Apply `action` with `scope`, `by = "ai"`.
    Decide { action: Action, scope: &'static str },
}

/// Everything the gates need.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    pub hard_rule_fired: bool,
    pub score: i32,
    pub verdict: &'a str,
    pub confidence: f64,
    pub recommended_action: &'a str,
    pub auto_threshold: f64,
    pub auto_kill: bool,
    pub never_kill: bool,
    /// Hours since learning mode started; `None` when not in learning.
    pub learning_hours: Option<u64>,
    /// The AI already flipped allow↔block for this identity within the last 7 days.
    pub flipped_recently: bool,
}

/// Evaluate the gates in order; the first failing gate wins.
#[must_use]
pub fn decide(i: &Inputs<'_>) -> Outcome {
    use Outcome::Skip as S;
    if i.hard_rule_fired {
        return S(Skip::HardRule);
    }
    if i.learning_hours.is_some_and(|h| h < LEARNING_GRACE_HOURS) {
        return S(Skip::LearningGrace);
    }
    if i.confidence < i.auto_threshold {
        return S(Skip::NotConfident);
    }
    if i.flipped_recently {
        return S(Skip::Unstable);
    }
    match i.recommended_action {
        "allow" => {
            if i.verdict != "safe" {
                return S(Skip::VerdictMismatch);
            }
            if i.score < ALLOW_MIN_SCORE && i.confidence < ALLOW_LOW_SCORE_CONFIDENCE {
                return S(Skip::ScoreTooLow);
            }
            Outcome::Decide {
                action: Action::Allow,
                scope: "24h",
            }
        }
        "block" => {
            if i.verdict != "malicious" {
                return S(Skip::VerdictMismatch);
            }
            Outcome::Decide {
                action: Action::Block,
                scope: "forever",
            }
        }
        // Kill is never automatic unless explicitly enabled; otherwise the reversible block applies.
        "kill" => {
            if i.verdict != "malicious" {
                return S(Skip::VerdictMismatch);
            }
            if !i.auto_kill {
                return Outcome::Decide {
                    action: Action::Block,
                    scope: "forever",
                };
            }
            if i.never_kill {
                return S(Skip::NeverKill);
            }
            if i.confidence < KILL_MIN_CONFIDENCE {
                return S(Skip::NotConfident);
            }
            if i.score > KILL_MAX_SCORE {
                return S(Skip::ScoreTooHigh);
            }
            Outcome::Decide {
                action: Action::Kill,
                scope: "forever",
            }
        }
        _ => S(Skip::NoAction),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs<'static> {
        Inputs {
            hard_rule_fired: false,
            score: 60,
            verdict: "safe",
            confidence: 0.93,
            recommended_action: "allow",
            auto_threshold: 0.90,
            auto_kill: false,
            never_kill: false,
            learning_hours: None,
            flipped_recently: false,
        }
    }

    fn mal(action: &'static str) -> Inputs<'static> {
        Inputs {
            verdict: "malicious",
            recommended_action: action,
            score: 20,
            ..base()
        }
    }

    #[test]
    fn happy_paths_use_the_documented_scopes() {
        assert_eq!(
            decide(&base()),
            Outcome::Decide {
                action: Action::Allow,
                scope: "24h"
            }
        );
        assert_eq!(
            decide(&mal("block")),
            Outcome::Decide {
                action: Action::Block,
                scope: "forever"
            }
        );
    }

    #[test]
    fn a_fired_hard_rule_always_wins() {
        for i in [base(), mal("block"), mal("kill")] {
            assert_eq!(
                decide(&Inputs {
                    hard_rule_fired: true,
                    ..i
                }),
                Outcome::Skip(Skip::HardRule)
            );
        }
    }

    #[test]
    fn kill_is_never_automatic_by_default() {
        let o = decide(&Inputs {
            confidence: 0.99,
            ..mal("kill")
        });
        assert_eq!(
            o,
            Outcome::Decide {
                action: Action::Block,
                scope: "forever"
            }
        );
    }

    #[test]
    fn auto_kill_needs_every_condition() {
        let k = Inputs {
            auto_kill: true,
            confidence: 0.97,
            ..mal("kill")
        };
        assert_eq!(
            decide(&k),
            Outcome::Decide {
                action: Action::Kill,
                scope: "forever"
            }
        );
        assert_eq!(
            decide(&Inputs {
                never_kill: true,
                ..k.clone()
            }),
            Outcome::Skip(Skip::NeverKill)
        );
        assert_eq!(
            decide(&Inputs {
                score: 50,
                ..k.clone()
            }),
            Outcome::Skip(Skip::ScoreTooHigh)
        );
        assert_eq!(
            decide(&Inputs {
                confidence: 0.92,
                ..k
            }),
            Outcome::Skip(Skip::NotConfident)
        );
    }

    #[test]
    fn thresholds_and_score_floor() {
        assert_eq!(
            decide(&Inputs {
                confidence: 0.89,
                ..base()
            }),
            Outcome::Skip(Skip::NotConfident)
        );
        assert_eq!(
            decide(&Inputs {
                score: 39,
                ..base()
            }),
            Outcome::Skip(Skip::ScoreTooLow)
        );
        // a weak score alone is overruled only by a very confident advisor
        assert!(matches!(
            decide(&Inputs {
                score: 5,
                confidence: 0.96,
                ..base()
            }),
            Outcome::Decide { .. }
        ));
        assert_eq!(
            decide(&Inputs {
                verdict: "unknown",
                ..base()
            }),
            Outcome::Skip(Skip::VerdictMismatch)
        );
        assert_eq!(
            decide(&Inputs {
                recommended_action: "ask_user",
                ..base()
            }),
            Outcome::Skip(Skip::NoAction)
        );
    }

    #[test]
    fn learning_grace_and_stability() {
        assert_eq!(
            decide(&Inputs {
                learning_hours: Some(23),
                ..base()
            }),
            Outcome::Skip(Skip::LearningGrace)
        );
        assert!(matches!(
            decide(&Inputs {
                learning_hours: Some(24),
                ..base()
            }),
            Outcome::Decide { .. }
        ));
        assert_eq!(
            decide(&Inputs {
                flipped_recently: true,
                ..base()
            }),
            Outcome::Skip(Skip::Unstable)
        );
    }
}
