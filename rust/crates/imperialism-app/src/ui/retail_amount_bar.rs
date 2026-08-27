//! Recovered `TAmtBar` geometry and click math. Scene structure is generated.

use bevy::prelude::*;

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AmountBarStyle {
    #[default]
    Production,
    Trade,
}

/// Private child refs for a generated amount-bar hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct AmountBarParts {
    pub fill: Entity,
    pub limit: Entity,
}

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
#[allow(clippy::identity_op)]
mod tests {
    use super::*;

    #[test]
    fn click_and_span_match_retail() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        assert_eq!(amount_bar_value_at_x(geometry, 0), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 6), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 7), 1);
        assert_eq!(amount_bar_click_value(geometry, 3, 0), 1);
        assert_eq!(
            trade_amount_bar_click_value(TRADE_AMOUNT_BAR.with_segments(20), 3),
            1
        );
        assert_eq!(quantize_amount_bar_value(3, 6), 6);
        assert_eq!(INDUSTRY_AMOUNT_BAR.with_segments(50).span(25), 75);
        assert_eq!(
            amount_bar_counter_offset(INDUSTRY_AMOUNT_BAR.with_segments(50), 25),
            Vec2::new(73.0, 6.0)
        );
    }
}
