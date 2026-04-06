use core_detect::WalletSecretDetector;
use core_types::{
    BoundingBox, DetectionContext, Detector, OcrTextBlock, ProtectionMode,
};

fn block(text: &str, x: f32, y: f32) -> OcrTextBlock {
    OcrTextBlock {
        text: text.to_string(),
        bbox: BoundingBox {
            x,
            y,
            width: 60.0,
            height: 16.0,
        },
        confidence: 0.96,
    }
}

fn context() -> DetectionContext {
    DetectionContext {
        mode: ProtectionMode::Balanced,
        frame_width: 1920,
        frame_height: 1080,
    }
}

#[test]
fn fixture_grouped_24_word_synthetic_secret_escalates_high() {
    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "access",
        "accident", "account", "accuse", "achieve", "acoustic", "acquire", "across", "act", "action",
        "actor", "adapt", "add", "address", "adjust", "admit",
    ];
    let mut blocks = vec![block("Recovery phrase. Do not share.", 10.0, 10.0)];
    for (idx, w) in words.iter().enumerate() {
        blocks.push(block(w, (idx % 8) as f32 * 62.0, 60.0 + (idx / 8) as f32 * 20.0));
    }

    let findings = WalletSecretDetector.detect(&blocks, &context());
    assert!(findings.iter().any(|f| f.score >= 80));
}

#[test]
fn regression_unrelated_settings_screen_stays_low() {
    let blocks = vec![
        block("General settings", 10.0, 10.0),
        block("Display refresh rate", 10.0, 30.0),
        block("Audio bitrate", 10.0, 50.0),
    ];
    let findings = WalletSecretDetector.detect(&blocks, &context());
    assert!(findings.is_empty());
}
