//! Transport gauge fill/limit presentation helpers.
//!
//! Hierarchy construction lives in codegen (`TransportGaugeParts` on generated nodes).
//! Screens update fill/limit widths via bind-time handles.

use bevy::prelude::*;

const TRACK_WIDTH: f32 = 113.0;

pub const TRANSPORT_GAUGE_PARTIAL_PALETTE: u8 = 0x33;
pub const TRANSPORT_GAUGE_FULL_PALETTE: u8 = 0x34;

/// Child refs for a transport-gauge hierarchy.
///
/// Capacity gauges leave [`Self::limit`] as [`Entity::PLACEHOLDER`].
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct TransportGaugeParts {
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
