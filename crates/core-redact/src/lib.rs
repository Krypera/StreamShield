use anyhow::Result;
use core_types::{BoundingBox, RedactionRenderer, RedactionTarget};

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
    use core_types::{BoundingBox, FindingType, RedactionStyle, RedactionTarget, RedactionRenderer};

    use super::{map_bbox_to_overlay, OverlayRedactionRenderer, OverlaySpace};

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
}
