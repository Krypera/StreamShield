use core_ocr::group_nearby_blocks;
use core_types::{BoundingBox, OcrTextBlock};

fn b(text: &str, x: f32, y: f32) -> OcrTextBlock {
    OcrTextBlock {
        text: text.to_string(),
        bbox: BoundingBox {
            x,
            y,
            width: 40.0,
            height: 14.0,
        },
        confidence: 0.9,
    }
}

#[test]
fn fixture_ocr_grouping_keeps_three_columns_in_same_row() {
    let blocks = vec![
        b("1 abandon", 10.0, 20.0),
        b("2 ability", 100.0, 20.0),
        b("3 able", 200.0, 20.0),
    ];
    let groups = group_nearby_blocks(&blocks, 4.0);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].len(), 3);
}
