//! Transport gauge fill/limit presentation helpers.
//!
//! Private track/fill/limit entities are declared in BSN via [`transport_gauge_capacity_children`]
//! and [`transport_gauge_allocation_children`]. Screens bind [`TransportGaugeParts`] and update
//! fill/limit via retained handles. Recovered caption and arrow controls remain ordinary
//! generated children.

use super::retail::retail_background_color;
use bevy::prelude::*;
use bevy::scene::SceneList;

const TRACK_WIDTH: f32 = 113.0;
const TRACK_TOP: f32 = 13.0;
const TRACK_HEIGHT: f32 = 4.0;
const LIMIT_TOP: f32 = 18.0;
const LIMIT_WIDTH: f32 = 115.0;
const LIMIT_HEIGHT: f32 = 2.0;
const TRACK_BG_PALETTE: u8 = 0x3b;
const LIMIT_PALETTE: u8 = 0x33;

pub const TRANSPORT_GAUGE_PARTIAL_PALETTE: u8 = 0x33;
pub const TRANSPORT_GAUGE_FULL_PALETTE: u8 = 0x34;

const CAPACITY_FILL_PALETTE: u8 = TRANSPORT_GAUGE_PARTIAL_PALETTE;
const ALLOCATION_FILL_PALETTE: u8 = 0x3a;

/// Child refs for a transport-gauge hierarchy.
///
/// Capacity gauges leave [`Self::limit`] as [`Entity::PLACEHOLDER`].
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct TransportGaugeParts {
    pub fill: Entity,
    pub limit: Entity,
}

/// Retained child refs for a capacity (`tota`) gauge row.
pub fn transport_gauge_capacity_parts() -> impl Scene {
    bsn! {
        TransportGaugeParts { fill: #Fill, limit: {Entity::PLACEHOLDER} }
    }
}

/// Retained child refs for an allocation gauge row.
pub fn transport_gauge_allocation_parts() -> impl Scene {
    bsn! {
        TransportGaugeParts { fill: #Fill, limit: #Limit }
    }
}

/// Private gauge entities for a capacity row's `Children [ ... ]`.
pub fn transport_gauge_capacity_children(owner_left: i32) -> impl SceneList {
    let track_left = transport_gauge_track_left(owner_left);
    bsn_list! [
        (
            Node {
                position_type: PositionType::Absolute,
                left: px(track_left),
                top: px(TRACK_TOP),
                width: px(TRACK_WIDTH),
                height: px(TRACK_HEIGHT),
            }
            retail_background_color(TRACK_BG_PALETTE)
            Pickable::IGNORE
        ),
        (
            #Fill
            Node {
                position_type: PositionType::Absolute,
                left: px(track_left),
                top: px(TRACK_TOP),
                width: px(0.0),
                height: px(TRACK_HEIGHT),
            }
            retail_background_color(CAPACITY_FILL_PALETTE)
            Pickable::IGNORE
        ),
    ]
}

/// Private gauge entities for an allocation row's `Children [ ... ]`.
pub fn transport_gauge_allocation_children(owner_left: i32) -> impl SceneList {
    let track_left = transport_gauge_track_left(owner_left);
    bsn_list! [
        (
            Node {
                position_type: PositionType::Absolute,
                left: px(track_left),
                top: px(TRACK_TOP),
                width: px(TRACK_WIDTH),
                height: px(TRACK_HEIGHT),
            }
            retail_background_color(TRACK_BG_PALETTE)
            Pickable::IGNORE
        ),
        (
            #Fill
            Node {
                position_type: PositionType::Absolute,
                left: px(track_left),
                top: px(TRACK_TOP),
                width: px(0.0),
                height: px(TRACK_HEIGHT),
            }
            retail_background_color(ALLOCATION_FILL_PALETTE)
            Pickable::IGNORE
        ),
        (
            #Limit
            Node {
                position_type: PositionType::Absolute,
                left: px(track_left - 1.0),
                top: px(LIMIT_TOP),
                width: px(LIMIT_WIDTH),
                height: px(LIMIT_HEIGHT),
            }
            retail_background_color(LIMIT_PALETTE)
            Visibility::Hidden
            Pickable::IGNORE
        ),
    ]
}

fn transport_gauge_track_left(owner_left: i32) -> f32 {
    if owner_left > 0xC8 {
        0x5D as f32
    } else {
        0x61 as f32
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
    fn transport_gauge_track_left_follows_refresh_rule() {
        assert_eq!(transport_gauge_track_left(0xC9), 0x5D as f32);
        assert_eq!(transport_gauge_track_left(0xC8), 0x61 as f32);
    }

    #[test]
    fn transport_gauge_width_distributes_remainder_pixels() {
        assert_eq!(transport_gauge_width(0, 10), 0.0);
        assert_eq!(transport_gauge_width(0, 0), 0.0);
        assert!(transport_gauge_width(5, 10) > 0.0);
        assert!(transport_gauge_width(10, 10) <= TRACK_WIDTH);
    }
}
