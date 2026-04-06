use anyhow::Result;
use core_types::{CapturedFrame, OcrEngine, OcrTextBlock};

#[derive(Debug, Clone)]
pub struct LocalOcrEngine {
    backend_name: &'static str,
}

impl LocalOcrEngine {
    pub fn new(backend_name: &'static str) -> Self {
        Self { backend_name }
    }
}

impl Default for LocalOcrEngine {
    fn default() -> Self {
        Self::new("local-ocr-placeholder")
    }
}

impl OcrEngine for LocalOcrEngine {
    fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    fn extract_text(&self, _frame: &CapturedFrame) -> Result<Vec<OcrTextBlock>> {
        Ok(Vec::new())
    }
}

pub fn group_nearby_blocks(blocks: &[OcrTextBlock], y_tolerance: f32) -> Vec<Vec<OcrTextBlock>> {
    let mut sorted = blocks.to_vec();
    sorted.sort_by(|a, b| a.bbox.y.partial_cmp(&b.bbox.y).unwrap_or(std::cmp::Ordering::Equal));

    let mut groups: Vec<Vec<OcrTextBlock>> = Vec::new();
    for block in sorted {
        if let Some(last_group) = groups.last_mut() {
            let avg_y: f32 = last_group.iter().map(|b| b.bbox.y).sum::<f32>() / last_group.len() as f32;
            if (block.bbox.y - avg_y).abs() <= y_tolerance {
                last_group.push(block);
                continue;
            }
        }
        groups.push(vec![block]);
    }

    for group in &mut groups {
        group.sort_by(|a, b| a.bbox.x.partial_cmp(&b.bbox.x).unwrap_or(std::cmp::Ordering::Equal));
    }

    groups
}

#[cfg(test)]
mod tests {
    use core_types::{BoundingBox, OcrTextBlock};

    use super::group_nearby_blocks;

    fn b(text: &str, x: f32, y: f32) -> OcrTextBlock {
        OcrTextBlock {
            text: text.to_string(),
            bbox: BoundingBox {
                x,
                y,
                width: 30.0,
                height: 12.0,
            },
            confidence: 0.95,
        }
    }

    #[test]
    fn fixture_groups_two_rows_of_recovery_words() {
        let blocks = vec![
            b("abandon", 10.0, 20.0),
            b("ability", 50.0, 20.0),
            b("able", 95.0, 20.0),
            b("about", 10.0, 42.0),
            b("above", 50.0, 42.0),
            b("absent", 95.0, 42.0),
        ];

        let groups = group_nearby_blocks(&blocks, 6.0);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 3);
        assert_eq!(groups[1].len(), 3);
    }

    #[test]
    fn fixture_keeps_distant_blocks_separate() {
        let blocks = vec![b("seed", 10.0, 10.0), b("phrase", 20.0, 45.0)];
        let groups = group_nearby_blocks(&blocks, 5.0);
        assert_eq!(groups.len(), 2);
    }
}
