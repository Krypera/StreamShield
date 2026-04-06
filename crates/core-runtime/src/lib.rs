use anyhow::Result;
use core_types::{
    AppConfig, ConfidenceLevel, DetectionContext, Detector, FrameSource, ObsController, OcrEngine,
    PolicyEngine, RedactionRenderer, ResponseAction,
};

#[derive(Debug, Clone)]
pub struct RuntimeScanOutcome {
    pub findings_count: usize,
    pub max_confidence: ConfidenceLevel,
    pub action_count: usize,
    pub redaction_target_count: usize,
    pub panic_latched: bool,
    pub obs_switch_requested: bool,
    pub rationale: String,
}

pub struct PipelineRuntime<F, O, D, P, R, Obs>
where
    F: FrameSource,
    O: OcrEngine,
    D: Detector,
    P: PolicyEngine,
    R: RedactionRenderer,
    Obs: ObsController,
{
    frame_source: F,
    ocr_engine: O,
    detector: D,
    policy_engine: P,
    renderer: R,
    obs: Obs,
    panic_latched: bool,
}

impl<F, O, D, P, R, Obs> PipelineRuntime<F, O, D, P, R, Obs>
where
    F: FrameSource,
    O: OcrEngine,
    D: Detector,
    P: PolicyEngine,
    R: RedactionRenderer,
    Obs: ObsController,
{
    pub fn new(
        frame_source: F,
        ocr_engine: O,
        detector: D,
        policy_engine: P,
        renderer: R,
        obs: Obs,
    ) -> Self {
        Self {
            frame_source,
            ocr_engine,
            detector,
            policy_engine,
            renderer,
            obs,
            panic_latched: false,
        }
    }

    pub fn panic_latched(&self) -> bool {
        self.panic_latched
    }

    pub fn clear_alert_latch(&mut self) -> Result<()> {
        self.panic_latched = false;
        self.renderer.set_fullscreen_shield(false)?;
        Ok(())
    }

    pub fn scan_once(&mut self, config: &AppConfig) -> Result<RuntimeScanOutcome> {
        if !config.protection_enabled {
            self.renderer.set_targets(Vec::new())?;
            if !self.panic_latched {
                self.renderer.set_fullscreen_shield(false)?;
            }
            return Ok(RuntimeScanOutcome {
                findings_count: 0,
                max_confidence: ConfidenceLevel::Low,
                action_count: 1,
                redaction_target_count: 0,
                panic_latched: self.panic_latched,
                obs_switch_requested: false,
                rationale: "Protection disabled".to_string(),
            });
        }

        let frame = self.frame_source.capture_primary_display()?;
        let blocks = self.ocr_engine.extract_text(&frame)?;
        let ctx = DetectionContext {
            mode: config.mode,
            frame_width: frame.width,
            frame_height: frame.height,
        };
        let findings = self.detector.detect(&blocks, &ctx);
        let decision = self.policy_engine.decide(&findings, config);

        let mut redaction_target_count = 0usize;
        let mut obs_switch_requested = false;
        let mut redaction_applied = false;

        for action in &decision.actions {
            match action {
                ResponseAction::NoOp => {}
                ResponseAction::ShowWarning { .. } => {}
                ResponseAction::RedactRegion { targets } => {
                    redaction_target_count = targets.len();
                    redaction_applied = true;
                    self.renderer.set_targets(targets.clone())?;
                }
                ResponseAction::TriggerPanicShield => {
                    self.panic_latched = true;
                    self.renderer.set_fullscreen_shield(true)?;
                }
                ResponseAction::SwitchObsSafeScene => {
                    obs_switch_requested = true;
                    self.obs.switch_to_safe_scene(&config.obs)?;
                }
            }
        }

        if !redaction_applied {
            self.renderer.set_targets(Vec::new())?;
        }

        if !self.panic_latched {
            self.renderer.set_fullscreen_shield(false)?;
        }

        Ok(RuntimeScanOutcome {
            findings_count: findings.len(),
            max_confidence: decision.max_confidence,
            action_count: decision.actions.len(),
            redaction_target_count,
            panic_latched: self.panic_latched,
            obs_switch_requested,
            rationale: decision.rationale,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use core_types::{
        AppConfig, BoundingBox, CapturedFrame, ConfidenceLevel, DetectionFinding, Detector,
        FindingType, FrameSource, ObsConfig, ObsController, OcrEngine, OcrTextBlock, PolicyDecision,
        PolicyEngine, RedactionRenderer, RedactionStyle, RedactionTarget, ResponseAction,
    };

    use super::PipelineRuntime;

    struct FakeFrameSource;

    impl FrameSource for FakeFrameSource {
        fn capture_primary_display(&mut self) -> Result<CapturedFrame> {
            Ok(CapturedFrame {
                width: 100,
                height: 100,
                timestamp_ms: 1,
                rgba: vec![0; 100 * 100 * 4],
            })
        }
    }

    struct FakeOcr;

    impl OcrEngine for FakeOcr {
        fn backend_name(&self) -> &'static str {
            "fake"
        }

        fn extract_text(&self, _frame: &CapturedFrame) -> Result<Vec<OcrTextBlock>> {
            Ok(vec![OcrTextBlock {
                text: "synthetic test phrase".to_string(),
                bbox: BoundingBox {
                    x: 1.0,
                    y: 1.0,
                    width: 10.0,
                    height: 10.0,
                },
                confidence: 0.9,
            }])
        }
    }

    struct FakeDetector;

    impl Detector for FakeDetector {
        fn detect(
            &self,
            _blocks: &[OcrTextBlock],
            _ctx: &core_types::DetectionContext,
        ) -> Vec<DetectionFinding> {
            vec![DetectionFinding {
                finding_type: FindingType::MnemonicPhrase,
                confidence: ConfidenceLevel::Critical,
                score: 95,
                bbox: BoundingBox {
                    x: 2.0,
                    y: 2.0,
                    width: 20.0,
                    height: 20.0,
                },
                evidence: vec!["synthetic".to_string()],
            }]
        }
    }

    struct FakePolicy;

    impl PolicyEngine for FakePolicy {
        fn decide(&self, _findings: &[DetectionFinding], _config: &AppConfig) -> PolicyDecision {
            PolicyDecision {
                max_confidence: ConfidenceLevel::Critical,
                actions: vec![
                    ResponseAction::RedactRegion {
                        targets: vec![RedactionTarget {
                            bbox: BoundingBox {
                                x: 2.0,
                                y: 2.0,
                                width: 20.0,
                                height: 20.0,
                            },
                            style: RedactionStyle::BlackBox,
                            finding_type: FindingType::MnemonicPhrase,
                        }],
                    },
                    ResponseAction::TriggerPanicShield,
                    ResponseAction::SwitchObsSafeScene,
                ],
                rationale: "synthetic escalation".to_string(),
            }
        }
    }

    #[derive(Default)]
    struct FakeRenderer {
        target_count: usize,
        shield: bool,
    }

    impl RedactionRenderer for FakeRenderer {
        fn set_targets(&mut self, targets: Vec<RedactionTarget>) -> Result<()> {
            self.target_count = targets.len();
            Ok(())
        }

        fn set_fullscreen_shield(&mut self, enabled: bool) -> Result<()> {
            self.shield = enabled;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeObs {
        switches: usize,
    }

    impl ObsController for FakeObs {
        fn test_connection(&mut self, _config: &ObsConfig) -> Result<()> {
            Ok(())
        }

        fn switch_to_safe_scene(&mut self, _config: &ObsConfig) -> Result<()> {
            self.switches += 1;
            Ok(())
        }
    }

    #[test]
    fn runtime_applies_redaction_panic_and_obs_actions() {
        let mut runtime = PipelineRuntime::new(
            FakeFrameSource,
            FakeOcr,
            FakeDetector,
            FakePolicy,
            FakeRenderer::default(),
            FakeObs::default(),
        );

        let outcome = runtime.scan_once(&AppConfig::default()).expect("scan should succeed");
        assert_eq!(outcome.findings_count, 1);
        assert_eq!(outcome.redaction_target_count, 1);
        assert!(outcome.panic_latched);
        assert!(outcome.obs_switch_requested);
    }

    #[test]
    fn clear_alert_latch_turns_off_panic_state() {
        let mut runtime = PipelineRuntime::new(
            FakeFrameSource,
            FakeOcr,
            FakeDetector,
            FakePolicy,
            FakeRenderer::default(),
            FakeObs::default(),
        );

        let _ = runtime.scan_once(&AppConfig::default()).expect("scan should succeed");
        assert!(runtime.panic_latched());

        runtime.clear_alert_latch().expect("clear latch should succeed");
        assert!(!runtime.panic_latched());
    }
}
