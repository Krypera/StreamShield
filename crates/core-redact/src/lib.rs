use anyhow::Result;
use core_types::{BoundingBox, CapturedFrame, RedactionRenderer, RedactionStyle, RedactionTarget};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OverlaySpace {
    pub source_width: u32,
    pub source_height: u32,
    pub overlay_width: u32,
    pub overlay_height: u32,
}

pub fn map_bbox_to_overlay(src: BoundingBox, space: OverlaySpace) -> BoundingBox {
    let sx = space.overlay_width as f32 / space.source_width as f32;
    let sy = space.overlay_height as f32 / space.source_height as f32;
    BoundingBox {
        x: src.x * sx,
        y: src.y * sy,
        width: src.width * sx,
        height: src.height * sy,
    }
}

pub fn apply_redactions_to_frame(frame: &mut CapturedFrame, targets: &[RedactionTarget]) {
    for target in targets {
        apply_single_redaction(frame, target);
    }
}

fn apply_single_redaction(frame: &mut CapturedFrame, target: &RedactionTarget) {
    let (x0, y0, x1, y1) = clamp_bbox_to_frame(target.bbox, frame.width, frame.height);
    if x1 <= x0 || y1 <= y0 {
        return;
    }

    match target.style {
        RedactionStyle::BlackBox => apply_black_box(frame, x0, y0, x1, y1),
        RedactionStyle::Pixelate => apply_pixelate(frame, x0, y0, x1, y1, 10),
        RedactionStyle::Blur => apply_box_blur(frame, x0, y0, x1, y1, 2),
    }
}

fn clamp_bbox_to_frame(bbox: BoundingBox, width: u32, height: u32) -> (u32, u32, u32, u32) {
    let x0 = bbox.x.max(0.0).floor() as u32;
    let y0 = bbox.y.max(0.0).floor() as u32;
    let x1 = (bbox.x + bbox.width).min(width as f32).ceil() as u32;
    let y1 = (bbox.y + bbox.height).min(height as f32).ceil() as u32;
    (x0.min(width), y0.min(height), x1.min(width), y1.min(height))
}

fn apply_black_box(frame: &mut CapturedFrame, x0: u32, y0: u32, x1: u32, y1: u32) {
    for y in y0..y1 {
        for x in x0..x1 {
            let idx = ((y * frame.width + x) * 4) as usize;
            if idx + 3 < frame.rgba.len() {
                frame.rgba[idx] = 0;
                frame.rgba[idx + 1] = 0;
                frame.rgba[idx + 2] = 0;
                frame.rgba[idx + 3] = 255;
            }
        }
    }
}

fn apply_pixelate(frame: &mut CapturedFrame, x0: u32, y0: u32, x1: u32, y1: u32, block: u32) {
    let step = block.max(1);
    let mut by = y0;
    while by < y1 {
        let mut bx = x0;
        while bx < x1 {
            let ex = (bx + step).min(x1);
            let ey = (by + step).min(y1);

            let (r, g, b, a, count) = average_region(frame, bx, by, ex, ey);
            if count > 0 {
                for y in by..ey {
                    for x in bx..ex {
                        let idx = ((y * frame.width + x) * 4) as usize;
                        frame.rgba[idx] = r;
                        frame.rgba[idx + 1] = g;
                        frame.rgba[idx + 2] = b;
                        frame.rgba[idx + 3] = a;
                    }
                }
            }

            bx = ex;
        }
        by = (by + step).min(y1);
    }
}

fn average_region(frame: &CapturedFrame, x0: u32, y0: u32, x1: u32, y1: u32) -> (u8, u8, u8, u8, u32) {
    let mut r_sum = 0_u64;
    let mut g_sum = 0_u64;
    let mut b_sum = 0_u64;
    let mut a_sum = 0_u64;
    let mut count = 0_u32;

    for y in y0..y1 {
        for x in x0..x1 {
            let idx = ((y * frame.width + x) * 4) as usize;
            if idx + 3 < frame.rgba.len() {
                r_sum += frame.rgba[idx] as u64;
                g_sum += frame.rgba[idx + 1] as u64;
                b_sum += frame.rgba[idx + 2] as u64;
                a_sum += frame.rgba[idx + 3] as u64;
                count += 1;
            }
        }
    }

    if count == 0 {
        return (0, 0, 0, 255, 0);
    }

    (
        (r_sum / count as u64) as u8,
        (g_sum / count as u64) as u8,
        (b_sum / count as u64) as u8,
        (a_sum / count as u64) as u8,
        count,
    )
}

fn apply_box_blur(frame: &mut CapturedFrame, x0: u32, y0: u32, x1: u32, y1: u32, radius: u32) {
    let original = frame.rgba.clone();

    for y in y0..y1 {
        for x in x0..x1 {
            let sx0 = x.saturating_sub(radius).max(x0);
            let sy0 = y.saturating_sub(radius).max(y0);
            let sx1 = (x + radius + 1).min(x1);
            let sy1 = (y + radius + 1).min(y1);

            let mut r_sum = 0_u64;
            let mut g_sum = 0_u64;
            let mut b_sum = 0_u64;
            let mut a_sum = 0_u64;
            let mut count = 0_u64;

            for sy in sy0..sy1 {
                for sx in sx0..sx1 {
                    let idx = ((sy * frame.width + sx) * 4) as usize;
                    if idx + 3 < original.len() {
                        r_sum += original[idx] as u64;
                        g_sum += original[idx + 1] as u64;
                        b_sum += original[idx + 2] as u64;
                        a_sum += original[idx + 3] as u64;
                        count += 1;
                    }
                }
            }

            if count > 0 {
                let idx = ((y * frame.width + x) * 4) as usize;
                frame.rgba[idx] = (r_sum / count) as u8;
                frame.rgba[idx + 1] = (g_sum / count) as u8;
                frame.rgba[idx + 2] = (b_sum / count) as u8;
                frame.rgba[idx + 3] = (a_sum / count) as u8;
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct OverlayRedactionRenderer {
    targets: Vec<RedactionTarget>,
    shield_enabled: bool,
}

impl OverlayRedactionRenderer {
    pub fn current_targets(&self) -> &[RedactionTarget] {
        &self.targets
    }

    pub fn shield_enabled(&self) -> bool {
        self.shield_enabled
    }
}

impl RedactionRenderer for OverlayRedactionRenderer {
    fn set_targets(&mut self, targets: Vec<RedactionTarget>) -> Result<()> {
        self.targets = targets;
        Ok(())
    }

    fn set_fullscreen_shield(&mut self, enabled: bool) -> Result<()> {
        self.shield_enabled = enabled;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core_types::{
        BoundingBox, CapturedFrame, FindingType, RedactionRenderer, RedactionStyle, RedactionTarget,
    };

    use super::{
        apply_redactions_to_frame, map_bbox_to_overlay, OverlayRedactionRenderer, OverlaySpace,
    };

    #[test]
    fn maps_ocr_bbox_into_overlay_coordinates() {
        let space = OverlaySpace {
            source_width: 1920,
            source_height: 1080,
            overlay_width: 3840,
            overlay_height: 2160,
        };
        let mapped = map_bbox_to_overlay(
            BoundingBox {
                x: 100.0,
                y: 50.0,
                width: 300.0,
                height: 100.0,
            },
            space,
        );
        assert_eq!(mapped.x, 200.0);
        assert_eq!(mapped.y, 100.0);
        assert_eq!(mapped.width, 600.0);
        assert_eq!(mapped.height, 200.0);
    }

    #[test]
    fn keeps_primary_display_consistent_when_dimensions_match() {
        let space = OverlaySpace {
            source_width: 1920,
            source_height: 1080,
            overlay_width: 1920,
            overlay_height: 1080,
        };
        let src = BoundingBox {
            x: 12.0,
            y: 34.0,
            width: 56.0,
            height: 78.0,
        };
        let mapped = map_bbox_to_overlay(src, space);
        assert_eq!(mapped, src);
    }

    #[test]
    fn renderer_updates_targets_and_shield_state() {
        let mut renderer = OverlayRedactionRenderer::default();
        renderer
            .set_targets(vec![RedactionTarget {
                bbox: BoundingBox {
                    x: 1.0,
                    y: 1.0,
                    width: 10.0,
                    height: 10.0,
                },
                style: RedactionStyle::Blur,
                finding_type: FindingType::MnemonicPhrase,
            }])
            .expect("target update");
        renderer.set_fullscreen_shield(true).expect("shield enable");
        assert_eq!(renderer.current_targets().len(), 1);
        assert!(renderer.shield_enabled());
    }

    #[test]
    fn black_box_redaction_changes_pixels() {
        let mut frame = CapturedFrame {
            width: 4,
            height: 4,
            timestamp_ms: 1,
            rgba: vec![255; 4 * 4 * 4],
        };
        apply_redactions_to_frame(
            &mut frame,
            &[RedactionTarget {
                bbox: BoundingBox {
                    x: 1.0,
                    y: 1.0,
                    width: 2.0,
                    height: 2.0,
                },
                style: RedactionStyle::BlackBox,
                finding_type: FindingType::PrivateKey,
            }],
        );

        let idx = ((1 * frame.width + 1) * 4) as usize;
        assert_eq!(frame.rgba[idx], 0);
        assert_eq!(frame.rgba[idx + 1], 0);
        assert_eq!(frame.rgba[idx + 2], 0);
    }
}
