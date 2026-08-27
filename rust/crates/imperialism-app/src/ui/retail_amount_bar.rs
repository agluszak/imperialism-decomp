//! Recovered `TAmtBar` family: structure-only BSN helpers plus click/geometry math.
//!
//! Screens own interaction and presentation via retained child entity handles.

use super::retail::retail_background_color;
use bevy::prelude::*;

pub const INDUSTRY_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 150,
    segments: 0,
};

pub const TRADE_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 100,
    segments: 0,
};

pub const INDUSTRY_BAR_FILL: u8 = 0x16;
// `TTraderAmtBar` calls `ApplyLegendSplitSlot34(0x37)` → palette 0xbd via GetColor.
pub const TRADE_BAR_FILL: u8 = 0xbd;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AmountBarStyle {
    #[default]
    Production,
    Trade,
}

/// Private child refs for an amount-bar hierarchy.
///
/// Trade bars leave [`Self::limit`] as [`Entity::PLACEHOLDER`] (no limit child).
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct AmountBarParts {
    pub fill: Entity,
    pub limit: Entity,
}

/// Generated helper: production bars include a limit marker; trade bars are fill-only.
pub fn retail_amount_bar(style: AmountBarStyle) -> impl Scene {
    let production = (style == AmountBarStyle::Production).then(production_amount_bar);
    let trade = (style == AmountBarStyle::Trade).then(trade_amount_bar);
    bsn! { {production} {trade} }
}

#[rustfmt::skip]
fn production_amount_bar() -> impl Scene {
    bsn! {
        AmountBarParts { fill: #Fill, limit: #Limit }
        Children [
            (
                #Fill
                Node { position_type: PositionType::Absolute, left: px(0), top: px(1), width: px(0), height: px(4) }
                retail_background_color(INDUSTRY_BAR_FILL)
                Pickable::IGNORE
            ),
            (
                #Limit
                Node { position_type: PositionType::Absolute, left: px(0), top: px(0), width: px(1), height: px(5) }
                retail_background_color(0)
                Pickable::IGNORE
            ),
        ]
    }
}

#[rustfmt::skip]
fn trade_amount_bar() -> impl Scene {
    bsn! {
        AmountBarParts { fill: #Fill, limit: {Entity::PLACEHOLDER} }
        Children [(
            #Fill
            Node { position_type: PositionType::Absolute, left: px(0), top: px(0), width: px(0), height: percent(100) }
            retail_background_color(TRADE_BAR_FILL)
            Pickable::IGNORE
        )]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountBarGeometry {
    pub width: i32,
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

pub fn amount_bar_geometry(style: AmountBarStyle, segments: i16) -> AmountBarGeometry {
    match style {
        AmountBarStyle::Production => INDUSTRY_AMOUNT_BAR.with_segments(segments),
        AmountBarStyle::Trade => TRADE_AMOUNT_BAR.with_segments(segments),
    }
}

/// Counter offset relative to the bar's top-left for industry/rail quantity markers.
pub fn amount_bar_counter_offset(geometry: AmountBarGeometry, value: i16) -> Vec2 {
    Vec2::new(f32::from(geometry.span(value)) - 2.0, 6.0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_bar_click_dead_zone_promotion_and_trade_clamp() {
        let industry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        for (x, expected) in [(0, 0), (6, 0), (7, 1), (15, 2), (149, 10)] {
            assert_eq!(amount_bar_value_at_x(industry, x), expected, "x={x}");
        }
        assert_eq!(amount_bar_click_value(industry, 3, 0), 1);
        assert_eq!(amount_bar_click_value(industry, 3, 4), 0);

        let trade = TRADE_AMOUNT_BAR.with_segments(20);
        assert_eq!(trade_amount_bar_click_value(trade, 0), 0);
        assert_eq!(trade_amount_bar_click_value(trade, 3), 1);
        assert_eq!(trade_amount_bar_click_value(trade, 50), 11);

        for (value, step, expected) in [(1, 2, 2), (2, 2, 2), (3, 6, 6), (2, 6, 0), (5, 1, 5)] {
            assert_eq!(quantize_amount_bar_value(value, step), expected);
        }
    }
}
