//! Recovered `TTransportPicture` gauge overlays as structure-only scene helpers.
//!
//! Screens write fill/limit via bind-time handles. Allocation vs capacity is a binder concern.
//! When a recovered transport node also has resource children, codegen merges those with the
//! synthetic remainder/fill/limit children into one `Children` list — do not nest
//! [`retail_transport_gauge`] (which owns `Children`) beside another `Children` block.

use super::retail::{retail_background_color, retail_picture};
use bevy::prelude::*;

const TRACK_WIDTH: f32 = 113.0;
const TRACK_TOP: f32 = 0x0d as f32;
const TRACK_HEIGHT: f32 = 0x04 as f32;
const REMAINDER_PALETTE: u8 = 0x3b;
const ALLOCATION_FILL_PALETTE: u8 = 0x3a;

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

/// Leaf construction when the recovered node has no resource children.
///
/// Production transport rows always merge via codegen; this helper remains for the
/// no-children codegen path and as the structure reference for that merge.
#[allow(dead_code)]
#[rustfmt::skip]
pub fn retail_transport_gauge(picture_id: i16, track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        retail_picture(picture_id)
        TransportGaugeParts { fill: #Fill, limit: #Limit }
        Children [
            (
                Node { position_type: PositionType::Absolute, left: px(left), top: px(TRACK_TOP), width: px(TRACK_WIDTH), height: px(TRACK_HEIGHT) }
                retail_background_color(REMAINDER_PALETTE)
                Pickable::IGNORE
            ),
            (
                #Fill
                Node { position_type: PositionType::Absolute, left: px(left), top: px(TRACK_TOP), width: px(0), height: px(TRACK_HEIGHT) }
                retail_background_color(ALLOCATION_FILL_PALETTE)
                Pickable::IGNORE
            ),
            (
                #Limit
                Node { position_type: PositionType::Absolute, left: px(left - 1.), top: px(0x12), width: px(TRACK_WIDTH + 2.), height: px(0x02) }
                retail_background_color(TRANSPORT_GAUGE_PARTIAL_PALETTE)
                Visibility::Hidden
                Pickable::IGNORE
            ),
        ]
    }
}

/// Capacity (`tota`) leaf helper when the recovered node has no resource children.
#[allow(dead_code)]
#[rustfmt::skip]
pub fn retail_transport_capacity_gauge(picture_id: i16, track_left: i16) -> impl Scene {
    let left = f32::from(track_left);
    bsn! {
        retail_picture(picture_id)
        TransportGaugeParts { fill: #Fill, limit: {Entity::PLACEHOLDER} }
        Children [
            (
                Node { position_type: PositionType::Absolute, left: px(left), top: px(TRACK_TOP), width: px(TRACK_WIDTH), height: px(TRACK_HEIGHT) }
                retail_background_color(REMAINDER_PALETTE)
                Pickable::IGNORE
            ),
            (
                #Fill
                Node { position_type: PositionType::Absolute, left: px(left), top: px(TRACK_TOP), width: px(0), height: px(TRACK_HEIGHT) }
                retail_background_color(TRANSPORT_GAUGE_PARTIAL_PALETTE)
                Pickable::IGNORE
            ),
        ]
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
}
