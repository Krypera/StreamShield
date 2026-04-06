use std::{io::Cursor, sync::Mutex};

use anyhow::{Context, Result};
use core_types::{BoundingBox, CapturedFrame, OcrEngine, OcrTextBlock};
use image::{ColorType, ImageFormat};
use leptess::LepTess;

pub struct LocalOcrEngine {
    backend_name: &'static str,
    inner: Mutex<LepTess>,
}

impl LocalOcrEngine {
    pub fn new_tesseract(data_path: Option<&str>, language: &str) -> Result<Self> {
        let mut lt = LepTess::new(data_path, language)
            .with_context(|| format!("failed to initialize tesseract for lang={language}"))?;
        lt.set_fallback_source_resolution(300);
        Ok(Self {
            backend_name: "tesseract-offline",
            inner: Mutex::new(lt),
        })
    }

    fn frame_to_tiff_bytes(frame: &CapturedFrame) -> Result<Vec<u8>> {
        let mut bytes = Cursor::new(Vec::new());
        image::write_buffer_with_format(
            &mut bytes,
            &frame.rgba,
            frame.width,
            frame.height,
            ColorType::Rgba8,
            ImageFormat::Tiff,
        )
        .context("failed to encode frame as in-memory TIFF")?;

        Ok(bytes.into_inner())
    }
}

impl Default for LocalOcrEngine {
    fn default() -> Self {
        Self::new_tesseract(None, "eng").expect("local tesseract engine initialization failed")
    }
}

impl OcrEngine for LocalOcrEngine {
    fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    fn extract_text(&self, frame: &CapturedFrame) -> Result<Vec<OcrTextBlock>> {
        let bytes = Self::frame_to_tiff_bytes(frame)?;
        let mut lt = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("ocr mutex poisoned"))?;

        lt.set_image_from_mem(&bytes)
            .context("tesseract set_image_from_mem failed")?;

        let tsv = lt
            .get_tsv_text(0)
            .context("failed to read tesseract TSV output")?;
        Ok(parse_tesseract_tsv(&tsv))
    }
}

fn parse_tesseract_tsv(tsv: &str) -> Vec<OcrTextBlock> {
    let mut out = Vec::new();

    for (idx, line) in tsv.lines().enumerate() {
        if idx == 0 || line.trim().is_empty() {
            continue;
        }

        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 12 {
            continue;
        }

        let left = cols[6].parse::<f32>().ok();
        let top = cols[7].parse::<f32>().ok();
        let width = cols[8].parse::<f32>().ok();
        let height = cols[9].parse::<f32>().ok();
        let conf = cols[10].parse::<f32>().ok();
        let text = cols[11].trim();

        if text.is_empty() {
            continue;
        }

        let (Some(x), Some(y), Some(w), Some(h)) = (left, top, width, height) else {
            continue;
        };

        let confidence = conf.unwrap_or(0.0).clamp(0.0, 100.0) / 100.0;
        out.push(OcrTextBlock {
            text: text.to_string(),
            bbox: BoundingBox {
                x,
                y,
                width: w,
                height: h,
            },
            confidence,
        });
    }

    out
}

pub fn group_nearby_blocks(blocks: &[OcrTextBlock], y_tolerance: f32) -> Vec<Vec<OcrTextBlock>> {
    let mut sorted = blocks.to_vec();
    sorted.sort_by(|a, b| {
        a.bbox
            .y
            .partial_cmp(&b.bbox.y)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

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
        group.sort_by(|a, b| {
            a.bbox
                .x
                .partial_cmp(&b.bbox.x)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    groups
}

#[cfg(test)]
mod tests {
    use core_types::{BoundingBox, OcrTextBlock};

    use super::{group_nearby_blocks, parse_tesseract_tsv};

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

    #[test]
    fn parses_tesseract_tsv_into_blocks() {
        let tsv = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n5\t1\t1\t1\t1\t1\t120\t240\t60\t20\t89.3\tseed\n";
        let blocks = parse_tesseract_tsv(tsv);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].text, "seed");
        assert_eq!(blocks[0].bbox.x, 120.0);
        assert!((blocks[0].confidence - 0.893).abs() < 0.001);
    }
}
