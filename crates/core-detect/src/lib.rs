use std::collections::HashSet;

use bip39::Language;
use core_types::{
    BoundingBox, ConfidenceLevel, DetectionContext, DetectionFinding, Detector, FindingType,
    OcrTextBlock,
};
use once_cell::sync::Lazy;

static BIP39_ENGLISH_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    Language::English
        .word_list()
        .iter()
        .copied()
        .collect::<HashSet<_>>()
});

const CONTEXT_KEYWORDS: &[&str] = &[
    "seed phrase",
    "recovery phrase",
    "backup words",
    "write this down",
    "restore wallet",
    "secret key",
    "private key",
    "do not share",
    "your 12 words",
    "wallet backup",
    "recovery words",
    "show this phrase",
];

#[derive(Debug, Default)]
pub struct WalletSecretDetector;

impl Detector for WalletSecretDetector {
    fn detect(&self, blocks: &[OcrTextBlock], _ctx: &DetectionContext) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();

        if let Some(mnemonic) = detect_mnemonic_phrase(blocks) {
            findings.push(mnemonic);
        }

        findings.extend(detect_private_keys(blocks));
        findings.extend(detect_unknown_high_risk_text(blocks));
        findings.extend(detect_wallet_context_labels(blocks));

        findings
    }
}

fn normalize_text(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || c == '-' || c == '.' {
                c
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn is_alpha_token(token: &str) -> bool {
    token.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_bip39_style_word(token: &str) -> bool {
    token.len() >= 3 && is_alpha_token(token) && BIP39_ENGLISH_WORDS.contains(token)
}

fn context_hits(blocks: &[OcrTextBlock]) -> usize {
    blocks
        .iter()
        .map(|b| normalize_text(&b.text))
        .filter(|text| CONTEXT_KEYWORDS.iter().any(|k| text.contains(k)))
        .count()
}

fn detect_mnemonic_phrase(blocks: &[OcrTextBlock]) -> Option<DetectionFinding> {
    if blocks.is_empty() {
        return None;
    }

    let tokens = extract_tokens_with_block_index(blocks);
    if tokens.len() < 12 {
        return None;
    }

    let mut best: Option<(usize, usize, u8, bool, f32)> = None;
    let context = context_hits(blocks);

    for candidate_len in [12_usize, 18, 24] {
        if tokens.len() < candidate_len {
            continue;
        }

        for start in 0..=(tokens.len() - candidate_len) {
            let window = &tokens[start..start + candidate_len];
            let bip39_hits = window.iter().filter(|(t, _)| is_bip39_style_word(t)).count();
            let ratio = bip39_hits as f32 / candidate_len as f32;

            if ratio < 0.66 {
                continue;
            }

            let has_ordinal_signal = window.iter().any(|(t, _)| t == "1" || t == "1.");
            let grouped_layout = grouped_layout_signal(window, blocks);

            let mut score = 0_u8;
            score = score.saturating_add((ratio * 60.0) as u8);
            if grouped_layout {
                score = score.saturating_add(12);
            }
            if has_ordinal_signal {
                score = score.saturating_add(8);
            }
            if context > 0 {
                score = score.saturating_add((context.min(2) as u8) * 10);
            }

            if score < 65 {
                continue;
            }

            match best {
                Some((_, _, best_score, _, _)) if best_score >= score => {}
                _ => best = Some((start, candidate_len, score, has_ordinal_signal, ratio)),
            }
        }
    }

    let Some((start, len, score, has_ordinal_signal, ratio)) = best else {
        return None;
    };

    let token_slice = &tokens[start..start + len];
    let mut bbox: Option<BoundingBox> = None;
    for (_, idx) in token_slice {
        let b = blocks[*idx].bbox;
        bbox = Some(match bbox {
            Some(current) => current.union(&b),
            None => b,
        });
    }

    Some(DetectionFinding {
        finding_type: if has_ordinal_signal {
            FindingType::GroupedRecoveryWords
        } else {
            FindingType::MnemonicPhrase
        },
        confidence: level_from_score(score),
        score,
        bbox: bbox.unwrap_or(BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        }),
        evidence: vec![
            format!("window_len={len}"),
            format!("bip39_ratio={ratio:.2}"),
            format!("context_hits={context}"),
        ],
    })
}

fn grouped_layout_signal(window: &[(String, usize)], blocks: &[OcrTextBlock]) -> bool {
    if window.is_empty() {
        return false;
    }

    let mut rows: Vec<f32> = Vec::new();
    for (_, idx) in window {
        let y = blocks[*idx].bbox.y;
        if rows.iter().all(|v| (v - y).abs() > 12.0) {
            rows.push(y);
        }
    }

    rows.len() >= 2 && rows.len() <= 8
}

fn extract_tokens_with_block_index(blocks: &[OcrTextBlock]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        let normalized = normalize_text(&block.text);
        for token in normalized.split_whitespace() {
            let trimmed = token.trim_matches('.');
            if !trimmed.is_empty() {
                out.push((trimmed.to_string(), idx));
            }
        }
    }
    out
}

fn detect_private_keys(blocks: &[OcrTextBlock]) -> Vec<DetectionFinding> {
    let mut findings = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        let text = block.text.trim();
        let compact = text.replace(' ', "");
        let lower = compact.to_lowercase();

        let xprv_like = lower.starts_with("xprv") && compact.len() >= 64;
        let long_base58_like = compact.len() >= 64
            && compact
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c));
        let hex_secret_like = compact.len() >= 64
            && compact.len() % 2 == 0
            && compact.chars().all(|c| c.is_ascii_hexdigit());

        let near_secret_label = has_nearby_context_label(idx, blocks, 260.0);
        let diversity = charset_diversity_ratio(&compact);

        let mut score = 0_u8;
        if xprv_like {
            score = score.saturating_add(75);
        }
        if long_base58_like || hex_secret_like {
            score = score.saturating_add(42);
        }
        if diversity >= 0.45 {
            score = score.saturating_add(10);
        }
        if near_secret_label {
            score = score.saturating_add(12);
        }

        if score >= 68 {
            findings.push(DetectionFinding {
                finding_type: if xprv_like {
                    FindingType::ExtendedPrivateKey
                } else {
                    FindingType::PrivateKey
                },
                confidence: level_from_score(score),
                score,
                bbox: block.bbox,
                evidence: vec![
                    format!("xprv_like={xprv_like}"),
                    format!("base58_or_hex_secret_like={}", long_base58_like || hex_secret_like),
                    format!("near_secret_label={near_secret_label}"),
                ],
            });
        }
    }

    findings
}

fn detect_unknown_high_risk_text(blocks: &[OcrTextBlock]) -> Vec<DetectionFinding> {
    let mut findings = Vec::new();

    for (idx, block) in blocks.iter().enumerate() {
        let compact = block.text.replace(' ', "");
        if compact.len() < 80 {
            continue;
        }

        let mostly_safe_chars = compact
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+' || c == '=' || c == '-');
        if !mostly_safe_chars {
            continue;
        }

        let diversity = charset_diversity_ratio(&compact);
        let near_secret_label = has_nearby_context_label(idx, blocks, 280.0);

        let mut score = 0_u8;
        if diversity > 0.50 {
            score = score.saturating_add(45);
        }
        if near_secret_label {
            score = score.saturating_add(28);
        }

        if score >= 70 {
            findings.push(DetectionFinding {
                finding_type: FindingType::UnknownHighRiskText,
                confidence: level_from_score(score),
                score,
                bbox: block.bbox,
                evidence: vec![
                    format!("length={}", compact.len()),
                    format!("diversity={diversity:.2}"),
                    format!("near_secret_label={near_secret_label}"),
                ],
            });
        }
    }

    findings
}

fn has_nearby_context_label(idx: usize, blocks: &[OcrTextBlock], max_distance: f32) -> bool {
    let origin = blocks[idx].bbox;
    blocks.iter().enumerate().any(|(i, b)| {
        if i == idx {
            return false;
        }
        let text = normalize_text(&b.text);
        let has_label = CONTEXT_KEYWORDS.iter().any(|k| text.contains(k)) || text.contains("private");
        has_label && bbox_center_distance(origin, b.bbox) <= max_distance
    })
}

fn bbox_center_distance(a: BoundingBox, b: BoundingBox) -> f32 {
    let ax = a.x + a.width / 2.0;
    let ay = a.y + a.height / 2.0;
    let bx = b.x + b.width / 2.0;
    let by = b.y + b.height / 2.0;
    let dx = ax - bx;
    let dy = ay - by;
    (dx * dx + dy * dy).sqrt()
}

fn charset_diversity_ratio(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let unique = s.chars().collect::<HashSet<_>>().len() as f32;
    unique / s.len() as f32
}

fn detect_wallet_context_labels(blocks: &[OcrTextBlock]) -> Vec<DetectionFinding> {
    let mut findings = Vec::new();

    for block in blocks {
        let text = normalize_text(&block.text);
        if CONTEXT_KEYWORDS.iter().any(|k| text.contains(k)) {
            findings.push(DetectionFinding {
                finding_type: FindingType::SensitiveWalletLabel,
                confidence: ConfidenceLevel::Medium,
                score: 52,
                bbox: block.bbox,
                evidence: vec!["contextual_wallet_label".to_string()],
            });
        }
    }

    findings
}

fn level_from_score(score: u8) -> ConfidenceLevel {
    match score {
        0..=44 => ConfidenceLevel::Low,
        45..=69 => ConfidenceLevel::Medium,
        70..=89 => ConfidenceLevel::High,
        _ => ConfidenceLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use core_types::{
        BoundingBox, ConfidenceLevel, DetectionContext, Detector, OcrTextBlock, ProtectionMode,
    };

    use super::WalletSecretDetector;

    fn block(text: &str, x: f32, y: f32) -> OcrTextBlock {
        OcrTextBlock {
            text: text.to_string(),
            bbox: BoundingBox {
                x,
                y,
                width: 50.0,
                height: 14.0,
            },
            confidence: 0.95,
        }
    }

    fn ctx() -> DetectionContext {
        DetectionContext {
            mode: ProtectionMode::Balanced,
            frame_width: 1920,
            frame_height: 1080,
        }
    }

    #[test]
    fn detects_grouped_12_word_candidate_even_with_context_header() {
        let words = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "access",
            "accident", "account", "accuse",
        ];
        let mut blocks = vec![block("Recovery phrase - write this down", 0.0, 0.0)];
        for (idx, w) in words.iter().enumerate() {
            blocks.push(block(w, (idx as f32) * 55.0, 40.0));
        }

        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().any(|f| f.score >= 70));
    }

    #[test]
    fn detects_real_bip39_english_words() {
        let words = vec![
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "access",
            "accident", "account", "accuse",
        ];
        let blocks = words
            .iter()
            .enumerate()
            .map(|(i, w)| block(w, (i as f32) * 40.0, 12.0))
            .collect::<Vec<_>>();

        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().any(|f| f.score >= 65));
    }

    #[test]
    fn flags_xprv_like_private_key() {
        let blocks = vec![block(
            "xprv9s21ZrQH143K3FAKEDEMOEXAMPLEONLYNOTREALWALLETSECRETFAKE123456789",
            100.0,
            100.0,
        )];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().any(|f| f.score >= 75));
    }

    #[test]
    fn marks_unknown_high_risk_text_with_context() {
        let blocks = vec![
            block("Private key", 10.0, 10.0),
            block(
                "A8D9f7K2mQ1wZ3xC5vB7nM9pL2kJ4hG6tR8yU0iO2pQ4wE6rT8yU0iO2pQ4wE6rT8y",
                20.0,
                40.0,
            ),
        ];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings
            .iter()
            .any(|f| matches!(f.finding_type, core_types::FindingType::UnknownHighRiskText)));
    }

    #[test]
    fn avoids_false_positive_on_normal_12_word_sentence() {
        let words = [
            "today", "we", "walk", "to", "the", "studio", "for", "a", "camera", "check", "before",
            "stream",
        ];
        let blocks = vec![block(&words.join(" "), 20.0, 20.0)];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn avoids_false_positive_on_harmless_numbered_list() {
        let blocks = vec![
            block("1. install rust", 10.0, 10.0),
            block("2. run tests", 10.0, 30.0),
            block("3. open obs", 10.0, 50.0),
        ];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().all(|f| f.confidence <= ConfidenceLevel::Medium));
    }

    #[test]
    fn detects_contextual_wallet_warning_text() {
        let blocks = vec![block("Write this down: your recovery phrase", 10.0, 10.0)];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().any(|f| f.score >= 50));
    }

    #[test]
    fn avoids_false_positive_on_technical_docs_text() {
        let blocks = vec![block(
            "Configure websocket retries and tls handshake timeout for production clients",
            10.0,
            10.0,
        )];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.is_empty());
    }
}
