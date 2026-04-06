use core_redact::{map_bbox_to_overlay, OverlaySpace};
use core_types::BoundingBox;

#[test]
fn coordinate_mapping_maintains_primary_display_ratio() {
    let mapped = map_bbox_to_overlay(
        BoundingBox {
            x: 640.0,
            y: 360.0,
            width: 320.0,
            height: 180.0,
        },
        OverlaySpace {
            source_width: 1920,
            source_height: 1080,
            overlay_width: 2560,
            overlay_height: 1440,
        },
    );

    assert!((mapped.x - 853.3333).abs() < 0.01);
    assert!((mapped.y - 480.0).abs() < 0.01);
    assert!((mapped.width - 426.6666).abs() < 0.01);
    assert!((mapped.height - 240.0).abs() < 0.01);
}
