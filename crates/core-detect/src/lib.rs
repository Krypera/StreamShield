use core_types::{
    ConfidenceLevel, DetectionContext, DetectionFinding, Detector, FindingType, OcrTextBlock,
};

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
];

const SYNTHETIC_BIP39_STYLE_WORDS: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "access",
    "accident", "account", "accuse", "achieve", "acoustic", "acquire", "across", "act", "action",
    "actor", "adapt", "add", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport",
    "aisle", "alarm", "album", "alert", "alien", "all", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor",
    "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange",
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
        findings.extend(detect_wallet_context_labels(blocks));

        findings
    }
}

fn normalize(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || *c == '-')
        .collect::<String>()
}

fn tokens_with_bbox(blocks: &[OcrTextBlock]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (idx, b) in blocks.iter().enumerate() {
        for token in normalize(&b.text).split_whitespace() {
            out.push((token.to_string(), idx));
        }
    }
    out
}

fn detect_mnemonic_phrase(blocks: &[OcrTextBlock]) -> Option<DetectionFinding> {
    let tokens = tokens_with_bbox(blocks);
    let token_count = tokens.len();
    if ![12_usize, 18, 24].contains(&token_count) {
        return None;
    }

    let bip39_hits = tokens
        .iter()
        .filter(|(t, _)| SYNTHETIC_BIP39_STYLE_WORDS.contains(&t.as_str()))
        .count();

    let ratio = bip39_hits as f32 / token_count as f32;
    let has_ordered_list = blocks.iter().any(|b| {
        let t = normalize(&b.text);
        t.starts_with("1 ") || t.starts_with("1.") || t.starts_with("01")
    });

    let context_hits = blocks
        .iter()
        .map(|b| normalize(&b.text))
        .filter(|text| CONTEXT_KEYWORDS.iter().any(|k| text.contains(k)))
        .count();

    let mut score = 0_u8;
    if ratio >= 0.7 {
        score = score.saturating_add(50);
    }
    if ratio >= 0.9 {
        score = score.saturating_add(20);
    }
    if has_ordered_list {
        score = score.saturating_add(10);
    }
    if context_hits > 0 {
        score = score.saturating_add((context_hits.min(2) as u8) * 10);
    }

    if score < 60 {
        return None;
    }

    let confidence = level_from_score(score);
    let bbox = blocks
        .iter()
        .map(|b| b.bbox)
        .reduce(|acc, cur| acc.union(&cur))
        .unwrap_or(core_types::BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        });

    Some(DetectionFinding {
        finding_type: if has_ordered_list {
            FindingType::GroupedRecoveryWords
        } else {
            FindingType::MnemonicPhrase
        },
        confidence,
        score,
        bbox,
        evidence: vec![
            format!("token_count={token_count}"),
            format!("bip39_ratio={ratio:.2}"),
            format!("context_hits={context_hits}"),
        ],
    })
}

fn detect_private_keys(blocks: &[OcrTextBlock]) -> Vec<DetectionFinding> {
    let mut findings = Vec::new();

    for block in blocks {
        let text = normalize(&block.text);
        let compact = text.replace(' ', "");
        let is_xprv = compact.starts_with("xprv") && compact.len() >= 40;
        let long_secret_like = compact.len() >= 50
            && compact
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+' || c == '=');
        let nearby_label = CONTEXT_KEYWORDS
            .iter()
            .any(|k| text.contains(k) || text.contains("private"));

        let mut score = 0_u8;
        if is_xprv {
            score = score.saturating_add(75);
        }
        if long_secret_like {
            score = score.saturating_add(40);
        }
        if nearby_label {
            score = score.saturating_add(15);
        }

        if score >= 65 {
            findings.push(DetectionFinding {
                finding_type: if is_xprv {
                    FindingType::ExtendedPrivateKey
                } else {
                    FindingType::PrivateKey
                },
                confidence: level_from_score(score),
                score,
                bbox: block.bbox,
                evidence: vec![
                    format!("xprv_like={is_xprv}"),
                    format!("long_secret_like={long_secret_like}"),
                    format!("context_nearby={nearby_label}"),
                ],
            });
        }
    }

    findings
}

fn detect_wallet_context_labels(blocks: &[OcrTextBlock]) -> Vec<DetectionFinding> {
    let mut findings = Vec::new();

    for block in blocks {
        let text = normalize(&block.text);
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
    fn detects_grouped_12_word_candidate() {
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
    fn flags_xprv_like_private_key() {
        let blocks = vec![block(
            "xprv9s21ZrQH143K3FAKEDEMOEXAMPLEONLYNOTREALWALLETSECRET",
            100.0,
            100.0,
        )];
        let findings = WalletSecretDetector.detect(&blocks, &ctx());
        assert!(findings.iter().any(|f| f.score >= 75));
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
