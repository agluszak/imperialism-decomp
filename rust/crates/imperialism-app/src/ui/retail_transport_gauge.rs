//! Transport-gauge fill math. Scene structure is generated.

use bevy::prelude::*;

const TRACK_WIDTH: f32 = 113.0;

/// Palette indices for capacity/limit colouring in the transport screen renderer.
pub const TRANSPORT_GAUGE_PARTIAL_PALETTE: u8 = 0x33;
pub const TRANSPORT_GAUGE_FULL_PALETTE: u8 = 0x34;

/// Row vs capacity specialization recovered from `TTransportPicture::Refresh`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetailTransportGaugeKind {
    #[default]
    Allocation,
    Capacity,
}

/// Child refs for a generated transport-gauge hierarchy.
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct TransportGaugeParts {
    pub kind: RetailTransportGaugeKind,
    pub fill: Entity,
    pub limit: Entity,
}

/// `TTransportPicture::Refresh` 113px remainder-distribution fill width.
pub fn transport_gauge_width(value: i16, total: i16) -> f32 {
    if total <= 0 {
        return 0.0;
    }
    let pixels_per_unit = TRACK_WIDTH / f32::from(total);
    let remainder = TRACK_WIDTH - pixels_per_unit * f32::from(total);
    let value = f32::from(value);
    let width = if remainder < value {
        remainder * (pixels_per_unit + 1.0) + (value - remainder) * pixels_per_unit
    } else {
        value * (pixels_per_unit + 1.0)
    };
    width.clamp(0.0, TRACK_WIDTH).trunc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_gauge_width_matches_retail_padding() {
        assert_eq!(transport_gauge_width(0, 10), 0.0);
        assert_eq!(transport_gauge_width(10, 10), 113.0);
        assert_eq!(transport_gauge_width(5, 0), 0.0);
    }
}
