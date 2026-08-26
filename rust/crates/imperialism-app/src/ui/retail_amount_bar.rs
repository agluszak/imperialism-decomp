//! Recovered `TAmtBar` family: shared geometry, click-to-value, and bar drawing.
//!
//! Screen/domain code supplies the values. This module owns retail bar geometry,
//! the `TAmtBar::DoMouseCommand` click calculation, and the specialized fills.

use super::retail_raster::{IndexedRasterExt, indexed_picture};
use bevy::prelude::*;
use imperialism_formats::IndexedPicture;

pub const INDUSTRY_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 150,
    height: 6,
    segments: 0,
};

pub const TRADE_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 100,
    height: 7,
    segments: 0,
};

pub const INDUSTRY_BAR_FILL: u8 = 0x16;
// `TTraderAmtBar` calls `ApplyLegendSplitSlot34(0x37)`, which resolves through
// `TViewMgr::GetColor` to palette 0xbd rather than using 0x37 as a DIB index.
pub const TRADE_BAR_FILL: u8 = 0xbd;
const KEY_INDEX: u8 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountBarGeometry {
    pub width: i32,
    pub height: i32,
    pub segments: i16,
}

impl AmountBarGeometry {
    pub const fn with_segments(self, segments: i16) -> Self {
        Self { segments, ..self }
    }

    pub fn span(self, value: i16) -> i16 {
        if self.segments <= 0 {
            0
        } else {
            (i32::from(value) * self.width / i32::from(self.segments)).clamp(0, self.width) as i16
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountBarPixels {
    pub range: i16,
    pub current: i16,
    pub color: u8,
}

/// `TAmtBar::DoMouseCommand`: `x * segments / width + 1`, with a leading half-segment dead zone.
pub fn amount_bar_value_at_x(geometry: AmountBarGeometry, x: i32) -> i16 {
    if geometry.width <= 0 {
        return 0;
    }
    if geometry.segments <= 0 {
        // `auxValueA <= 0` takes the float branch: `x * 0 / width + 1`.
        return 1;
    }
    let dead_zone = geometry.width / (i32::from(geometry.segments) << 1);
    if x < dead_zone {
        0
    } else {
        (x * i32::from(geometry.segments) / geometry.width + 1) as i16
    }
}

pub fn amount_bar_x_from_normalized(geometry: AmountBarGeometry, normalized_x: f32) -> i32 {
    (((normalized_x + 0.5) * geometry.width as f32).floor() as i32).clamp(0, geometry.width - 1)
}

/// `TAmtBar` fallback: a click that would yield 0 is promoted to 1 when the counter is already 0.
pub fn amount_bar_click_value(geometry: AmountBarGeometry, x: i32, previous: i16) -> i16 {
    let mut value = amount_bar_value_at_x(geometry, x);
    if value == 0 && x != 0 && previous == 0 {
        value = 1;
    }
    value
}

/// `TTraderAmtBar::ApplyMoveClamp`: a click in the first merchant-capacity column becomes 1.
pub fn trade_amount_bar_click_value(geometry: AmountBarGeometry, x: i32) -> i16 {
    let value = amount_bar_value_at_x(geometry, x);
    if geometry.segments > 0 && x > 0 && x < geometry.width / i32::from(geometry.segments) {
        1
    } else {
        value
    }
}

/// `TRailCluster::SetMoveAmount` quantization: `((step / 2 + value) / step) * step`.
pub fn quantize_amount_bar_value(value: i16, step: i16) -> i16 {
    if step <= 0 {
        value
    } else {
        let step = i32::from(step);
        ((step / 2 + i32::from(value)) / step * step) as i16
    }
}

pub fn draw_industry_amount_bar(
    picture: &mut IndexedPicture,
    pixels: AmountBarPixels,
    geometry: AmountBarGeometry,
) {
    picture.fill_rect(
        IRect::new(0, 1, i32::from(pixels.current).min(geometry.width), 5),
        pixels.color,
    );
    let tick = i32::from(pixels.range).clamp(0, geometry.width);
    picture.fill_rect(IRect::new(tick, 0, tick + 1, 5), 0);
}

pub fn draw_trade_amount_bar(
    picture: &mut IndexedPicture,
    pixels: AmountBarPixels,
    geometry: AmountBarGeometry,
) {
    picture.fill_rect(
        IRect::new(
            0,
            0,
            i32::from(pixels.current).clamp(0, geometry.width),
            geometry.height,
        ),
        pixels.color,
    );
}

#[allow(dead_code)] // recovered TAmtBar::Draw overlay; no unspecialized bar is bound yet
pub fn draw_base_amount_bar(
    picture: &mut IndexedPicture,
    pixels: AmountBarPixels,
    geometry: AmountBarGeometry,
) {
    let fill = i32::from(pixels.current.min(pixels.range)).clamp(0, geometry.width);
    if fill > 0 {
        picture.fill_rect(IRect::new(0, 1, fill, geometry.height.min(5)), pixels.color);
    }
    if fill < geometry.width {
        picture.fill_rect(IRect::new(fill, 4, geometry.width, 5), 0);
    }
}

pub fn industry_amount_bar_picture(pixels: AmountBarPixels) -> IndexedPicture {
    let mut picture = indexed_picture(
        INDUSTRY_AMOUNT_BAR.width,
        INDUSTRY_AMOUNT_BAR.height,
        KEY_INDEX,
    );
    draw_industry_amount_bar(&mut picture, pixels, INDUSTRY_AMOUNT_BAR);
    picture
}

pub fn trade_amount_bar_picture(pixels: AmountBarPixels) -> IndexedPicture {
    let mut picture = indexed_picture(TRADE_AMOUNT_BAR.width, TRADE_AMOUNT_BAR.height, KEY_INDEX);
    draw_trade_amount_bar(&mut picture, pixels, TRADE_AMOUNT_BAR);
    picture
}

#[cfg(test)]
#[allow(clippy::identity_op)]
mod tests {
    use super::*;

    #[test]
    fn click_uses_a_leading_half_segment_dead_zone() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        assert_eq!(amount_bar_value_at_x(geometry, 0), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 6), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 7), 1);
        assert_eq!(amount_bar_value_at_x(geometry, 15), 2);
        assert_eq!(amount_bar_value_at_x(geometry, 149), 10);
    }

    #[test]
    fn zero_capacity_click_is_one() {
        assert_eq!(
            amount_bar_value_at_x(INDUSTRY_AMOUNT_BAR.with_segments(0), 40),
            1
        );
    }

    #[test]
    fn click_promotes_a_dead_zone_press_when_the_counter_is_already_zero() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        assert_eq!(amount_bar_click_value(geometry, 3, 0), 1);
        assert_eq!(amount_bar_click_value(geometry, 3, 4), 0);
        assert_eq!(amount_bar_click_value(geometry, 0, 0), 0);
    }

    #[test]
    fn trade_click_clamps_the_first_capacity_column_to_one() {
        let geometry = TRADE_AMOUNT_BAR.with_segments(20);
        assert_eq!(trade_amount_bar_click_value(geometry, 0), 0);
        assert_eq!(trade_amount_bar_click_value(geometry, 3), 1);
        assert_eq!(trade_amount_bar_click_value(geometry, 50), 11);
    }

    #[test]
    fn rail_click_quantizes_to_the_cluster_step() {
        assert_eq!(quantize_amount_bar_value(1, 2), 2);
        assert_eq!(quantize_amount_bar_value(2, 2), 2);
        assert_eq!(quantize_amount_bar_value(3, 6), 6);
        assert_eq!(quantize_amount_bar_value(2, 6), 0);
        assert_eq!(quantize_amount_bar_value(5, 1), 5);
    }

    #[test]
    fn industry_bar_fills_current_and_ticks_the_range() {
        let picture = industry_amount_bar_picture(AmountBarPixels {
            range: 100,
            current: 40,
            color: INDUSTRY_BAR_FILL,
        });
        assert_eq!(picture.pixels[1 * 150 + 0], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[1 * 150 + 39], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[1 * 150 + 40], KEY_INDEX);
        assert_eq!(picture.pixels[100], 0);
        assert_eq!(picture.pixels[0], KEY_INDEX);
    }

    #[test]
    fn trade_bar_fills_the_full_height() {
        let picture = trade_amount_bar_picture(AmountBarPixels {
            range: 100,
            current: 25,
            color: TRADE_BAR_FILL,
        });
        assert_eq!(picture.pixels[0], TRADE_BAR_FILL);
        assert_eq!(picture.pixels[6 * 100 + 24], TRADE_BAR_FILL);
        assert_eq!(picture.pixels[25], KEY_INDEX);
    }

    #[test]
    fn trader_bar_uses_the_view_manager_resolved_palette_index() {
        assert_eq!(TRADE_BAR_FILL, 0xbd);
    }

    #[test]
    fn base_bar_fills_to_current_and_underlines_the_remainder() {
        let mut picture = indexed_picture(20, 6, KEY_INDEX);
        draw_base_amount_bar(
            &mut picture,
            AmountBarPixels {
                range: 16,
                current: 8,
                color: INDUSTRY_BAR_FILL,
            },
            AmountBarGeometry {
                width: 20,
                height: 6,
                segments: 20,
            },
        );
        assert_eq!(picture.pixels[1 * 20 + 0], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[1 * 20 + 7], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[4 * 20 + 8], 0);
        assert_eq!(picture.pixels[4 * 20 + 19], 0);
    }

    #[test]
    fn span_scales_against_segments() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(50);
        assert_eq!(geometry.span(0), 0);
        assert_eq!(geometry.span(25), 75);
        assert_eq!(geometry.span(50), 150);
        assert_eq!(INDUSTRY_AMOUNT_BAR.span(10), 0);
    }
}
