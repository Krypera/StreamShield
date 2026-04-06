use core_types::{
    AppConfig, ConfidenceLevel, DetectionFinding, PolicyDecision, PolicyEngine, RedactionTarget,
    ResponseAction,
};

#[derive(Debug, Default)]
pub struct DefaultPolicyEngine;

impl PolicyEngine for DefaultPolicyEngine {
    fn decide(&self, findings: &[DetectionFinding], config: &AppConfig) -> PolicyDecision {
        if findings.is_empty() || !config.protection_enabled {
            return PolicyDecision {
                max_confidence: ConfidenceLevel::Low,
                actions: vec![ResponseAction::NoOp],
                rationale: "No actionable findings".to_string(),
            };
        }

        let max_score = findings.iter().map(|f| f.score).max().unwrap_or(0);
        let max_conf = findings
            .iter()
            .map(|f| f.confidence)
            .max()
            .unwrap_or(ConfidenceLevel::Low);

        let (warning, redact, panic) = adjusted_thresholds(config);

        let mut actions = Vec::new();
        if max_score >= warning {
            actions.push(ResponseAction::ShowWarning {
                message: "Potential wallet secret exposure detected".to_string(),
            });
        }

        if max_score >= redact {
            let targets = findings
                .iter()
                .filter(|f| f.score >= redact)
                .map(|f| RedactionTarget {
                    bbox: f.bbox,
                    style: config.redaction_style,
                    finding_type: f.finding_type,
                })
                .collect::<Vec<_>>();

            if !targets.is_empty() {
                actions.push(ResponseAction::RedactRegion { targets });
            }

            if config.obs.enabled {
                actions.push(ResponseAction::SwitchObsSafeScene);
            }
        }

        if max_score >= panic {
            actions.push(ResponseAction::TriggerPanicShield);
            if config.obs.enabled {
                actions.push(ResponseAction::SwitchObsSafeScene);
            }
        }

        if actions.is_empty() {
            actions.push(ResponseAction::NoOp);
        }

        PolicyDecision {
            max_confidence: max_conf,
            actions,
            rationale: format!(
                "max_score={max_score}, thresholds(warn={warning}, redact={redact}, panic={panic})"
            ),
        }
    }
}

fn adjusted_thresholds(config: &AppConfig) -> (u8, u8, u8) {
    let t = &config.thresholds;
    match config.mode {
        core_types::ProtectionMode::Balanced => (t.warning_score, t.redact_score, t.panic_score),
        core_types::ProtectionMode::Strict => (
            t.warning_score.saturating_sub(5),
            t.redact_score.saturating_sub(6),
            t.panic_score.saturating_sub(8),
        ),
        core_types::ProtectionMode::Paranoid => (
            t.warning_score.saturating_sub(10),
            t.redact_score.saturating_sub(12),
            t.panic_score.saturating_sub(14),
        ),
    }
}

#[cfg(test)]
mod tests {
    use core_types::{
        AppConfig, BoundingBox, ConfidenceLevel, DetectionFinding, FindingType, PolicyEngine,
        ProtectionMode, ResponseAction,
    };

    use super::DefaultPolicyEngine;

    fn finding(score: u8, confidence: ConfidenceLevel) -> DetectionFinding {
        DetectionFinding {
            finding_type: FindingType::MnemonicPhrase,
            confidence,
            score,
            bbox: BoundingBox {
                x: 10.0,
                y: 10.0,
                width: 120.0,
                height: 50.0,
            },
            evidence: vec!["synthetic".to_string()],
        }
    }

    #[test]
    fn no_findings_returns_noop() {
        let config = AppConfig::default();
        let decision = DefaultPolicyEngine.decide(&[], &config);
        assert_eq!(decision.actions, vec![ResponseAction::NoOp]);
    }

    #[test]
    fn high_score_triggers_redaction_and_obs_when_enabled() {
        let mut config = AppConfig::default();
        config.obs.enabled = true;
        let decision =
            DefaultPolicyEngine.decide(&[finding(80, ConfidenceLevel::High)], &config);
        assert!(decision
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::RedactRegion { .. })));
        assert!(decision
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::SwitchObsSafeScene)));
    }

    #[test]
    fn critical_score_triggers_panic() {
        let config = AppConfig::default();
        let decision =
            DefaultPolicyEngine.decide(&[finding(95, ConfidenceLevel::Critical)], &config);
        assert!(decision
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::TriggerPanicShield)));
    }

    #[test]
    fn paranoid_mode_reduces_thresholds() {
        let mut config = AppConfig::default();
        config.mode = ProtectionMode::Paranoid;
        let decision =
            DefaultPolicyEngine.decide(&[finding(66, ConfidenceLevel::Medium)], &config);
        assert!(decision
            .actions
            .iter()
            .any(|a| matches!(a, ResponseAction::RedactRegion { .. })));
    }
}
