//! Recovered `TTransportPicture` gauge overlays as structure-only scene helpers.
//!
//! Screens write fill/limit via bind-time handles. Allocation vs capacity is a binder concern.
//! Codegen merges synthetic remainder/fill/limit children from these helpers with recovered row
//! children into one `Children` list.

use super::retail::retail_background_color;
use bevy::prelude::*;

pub const TRACK_WIDTH: f32 = 113.0;
pub const TRACK_TOP: f32 = 0x0d as f32;
pub const TRACK_HEIGHT: f32 = 0x04 as f32;
pub const LIMIT_TOP: f32 = 0x12 as f32;
pub const LIMIT_HEIGHT: f32 = 0x02 as f32;
pub const REMAINDER_PALETTE: u8 = 0x3b;
pub const ALLOCATION_FILL_PALETTE: u8 = 0x3a;

pub const TRANSPORT_GAUGE_PARTIAL_PALETTE: u8 = 0x33;
pub const TRANSPORT_GAUGE_FULL_PALETTE: u8 = 0x34;

/// `TTransportPicture::Refresh` track-left rule from recovered owner geometry.
pub const fn transport_gauge_track_left(owner_local_x: i32) -> i16 {
    if owner_local_x > 0xC8 { 0x5D } else { 0x61 }
}

/// Child refs for a transport-gauge hierarchy.
///
/// Capacity gauges leave [`Self::limit`] as [`Entity::PLACEHOLDER`].
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct TransportGaugeParts {
    pub fill: Entity,
    pub limit: Entity,
}

/// Remainder strip for a merged transport-gauge `Children` list.
#[rustfmt::skip]
pub fn transport_gauge_remainder(track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(TRACK_TOP),
            width: px(TRACK_WIDTH),
            height: px(TRACK_HEIGHT),
        }
        retail_background_color(REMAINDER_PALETTE)
        Pickable::IGNORE
    }
}

/// Allocation fill child for a merged transport-gauge `Children` list.
#[rustfmt::skip]
pub fn transport_gauge_allocation_fill(track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(TRACK_TOP),
            width: px(0),
            height: px(TRACK_HEIGHT),
        }
        retail_background_color(ALLOCATION_FILL_PALETTE)
        Pickable::IGNORE
    }
}

/// Capacity fill child for a merged transport-gauge `Children` list.
#[rustfmt::skip]
pub fn transport_gauge_capacity_fill(track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(TRACK_TOP),
            width: px(0),
            height: px(TRACK_HEIGHT),
        }
        retail_background_color(TRANSPORT_GAUGE_PARTIAL_PALETTE)
        Pickable::IGNORE
    }
}

/// Limit strip child for a merged transport-gauge `Children` list.
#[rustfmt::skip]
pub fn transport_gauge_limit(track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left - 1.),
            top: px(LIMIT_TOP),
            width: px(TRACK_WIDTH + 2.),
            height: px(LIMIT_HEIGHT),
        }
        retail_background_color(TRANSPORT_GAUGE_PARTIAL_PALETTE)
        Visibility::Hidden
        Pickable::IGNORE
    }
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

    #[test]
    fn track_left_follows_retail_geometry_threshold() {
        assert_eq!(transport_gauge_track_left(0xC8), 0x61);
        assert_eq!(transport_gauge_track_left(0xC9), 0x5D);
    }
}
