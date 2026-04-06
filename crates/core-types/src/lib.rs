use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BoundingBox {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl BoundingBox {
    pub fn right(&self) -> f32 {
        self.x + self.width
    }

    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }

    pub fn union(&self, other: &Self) -> Self {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());
        Self {
            x,
            y,
            width: right - x,
            height: bottom - y,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub timestamp_ms: u64,
    pub rgba: Vec<u8>,
}

pub trait FrameSource: Send {
    fn capture_primary_display(&mut self) -> Result<CapturedFrame>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OcrTextBlock {
    pub text: String,
    pub bbox: BoundingBox,
    pub confidence: f32,
}

pub trait OcrEngine: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn extract_text(&self, frame: &CapturedFrame) -> Result<Vec<OcrTextBlock>>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    MnemonicPhrase,
    PrivateKey,
    ExtendedPrivateKey,
    SensitiveWalletLabel,
    GroupedRecoveryWords,
    UnknownHighRiskText,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ConfidenceLevel {
    pub fn score(self) -> u8 {
        match self {
            Self::Low => 20,
            Self::Medium => 50,
            Self::High => 75,
            Self::Critical => 95,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionFinding {
    pub finding_type: FindingType,
    pub confidence: ConfidenceLevel,
    pub score: u8,
    pub bbox: BoundingBox,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionContext {
    pub mode: ProtectionMode,
    pub frame_width: u32,
    pub frame_height: u32,
}

pub trait Detector: Send + Sync {
    fn detect(&self, blocks: &[OcrTextBlock], ctx: &DetectionContext) -> Vec<DetectionFinding>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionStyle {
    Blur,
    BlackBox,
    Pixelate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactionTarget {
    pub bbox: BoundingBox,
    pub style: RedactionStyle,
    pub finding_type: FindingType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseAction {
    NoOp,
    ShowWarning { message: String },
    RedactRegion { targets: Vec<RedactionTarget> },
    TriggerPanicShield,
    SwitchObsSafeScene,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub max_confidence: ConfidenceLevel,
    pub actions: Vec<ResponseAction>,
    pub rationale: String,
}

pub trait PolicyEngine: Send + Sync {
    fn decide(&self, findings: &[DetectionFinding], config: &AppConfig) -> PolicyDecision;
}

pub trait RedactionRenderer: Send {
    fn set_targets(&mut self, targets: Vec<RedactionTarget>) -> Result<()>;
    fn set_fullscreen_shield(&mut self, enabled: bool) -> Result<()>;
}

pub trait PanicController: Send {
    fn trigger_panic(&mut self) -> Result<()>;
    fn clear_panic(&mut self) -> Result<()>;
}

pub trait ObsController: Send {
    fn test_connection(&mut self, config: &ObsConfig) -> Result<()>;
    fn switch_to_safe_scene(&mut self, config: &ObsConfig) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectionMode {
    Balanced,
    Strict,
    Paranoid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PanicBehavior {
    ShieldOnly,
    ObsOnly,
    ShieldAndObs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionThresholds {
    pub warning_score: u8,
    pub redact_score: u8,
    pub panic_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObsConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub safe_scene: String,
    pub lock_safe_scene_until_clear: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    pub protection_enabled: bool,
    pub scan_interval_ms: u64,
    pub mode: ProtectionMode,
    pub thresholds: DetectionThresholds,
    pub redaction_style: RedactionStyle,
    pub panic_hotkey: String,
    pub panic_behavior: PanicBehavior,
    pub obs: ObsConfig,
    pub unsafe_debug_store_raw_frames: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            protection_enabled: true,
            scan_interval_ms: 400,
            mode: ProtectionMode::Balanced,
            thresholds: DetectionThresholds {
                warning_score: 45,
                redact_score: 72,
                panic_score: 92,
            },
            redaction_style: RedactionStyle::BlackBox,
            panic_hotkey: "Ctrl+Shift+Pause".to_string(),
            panic_behavior: PanicBehavior::ShieldAndObs,
            obs: ObsConfig {
                enabled: false,
                host: "127.0.0.1".to_string(),
                port: 4455,
                password: None,
                safe_scene: "SAFE".to_string(),
                lock_safe_scene_until_clear: true,
            },
            unsafe_debug_store_raw_frames: false,
        }
    }
}
