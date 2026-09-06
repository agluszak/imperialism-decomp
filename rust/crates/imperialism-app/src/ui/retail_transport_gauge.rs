//! Transport gauge fill/limit presentation helpers.
//!
//! [`transport_capacity_gauge`] and [`transport_allocation_gauge`] declare
//! [`TransportGaugeParts`] and private track/fill/limit entities in one BSN scope,
//! then merge recovered sibling controls through [`SceneList`] composition.

use super::retail::retail_background_color;
use bevy::ecs::template::{EntityTemplate, OptionTemplate};
use bevy::prelude::*;
use bevy::scene::{PatchFromTemplate, SceneList};

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
#[derive(Component, FromTemplate, Clone, Copy)]
pub struct TransportGaugeParts {
    pub track: Entity,
    pub fill: Entity,
    #[template(built_in)]
    pub limit: Option<Entity>,
}

fn transport_gauge_limit(limit: EntityTemplate) -> impl Scene {
    TransportGaugeParts::patch(move |parts, _| {
        parts.limit = OptionTemplate::Some(limit);
    })
}

/// Capacity (`tota`) gauge row: parts, private track/fill, then recovered siblings.
pub fn transport_capacity_gauge(owner_left: i32, recovered: impl SceneList) -> impl Scene {
    let track_left = transport_gauge_track_left(owner_left);
    bsn! {
        TransportGaugeParts { track: #Track, fill: #Fill }
        Children [
            (
                #Track
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
            {recovered},
        ]
    }
}

/// Allocation gauge row: parts, private track/fill/limit, then recovered siblings.
pub fn transport_allocation_gauge(owner_left: i32, recovered: impl SceneList) -> impl Scene {
    let track_left = transport_gauge_track_left(owner_left);
    bsn! {
        TransportGaugeParts { track: #Track, fill: #Fill }
        transport_gauge_limit(#Limit)
        Children [
            (
                #Track
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
            {recovered},
        ]
    }
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
    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;

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

    #[test]
    fn production_gauges_resolve_optional_limit_parts() {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, AssetPlugin::default(), ScenePlugin));
        let capacity = app
            .world_mut()
            .spawn_scene(bsn! {
                TransportGaugeParts { track: #Track, fill: #Fill }
                Children [(#Track), (#Fill)]
            })
            .expect("capacity gauge scene")
            .id();
        let allocation = app
            .world_mut()
            .spawn_scene(bsn! {
                TransportGaugeParts { track: #Track, fill: #Fill }
                transport_gauge_limit(#Limit)
                Children [(#Track), (#Fill), (#Limit)]
            })
            .expect("allocation gauge scene")
            .id();
        app.update();

        assert_eq!(
            app.world()
                .get::<TransportGaugeParts>(capacity)
                .unwrap()
                .limit,
            None
        );
        let limit = app
            .world()
            .get::<TransportGaugeParts>(allocation)
            .unwrap()
            .limit
            .expect("allocation gauge limit");
        assert!(app.world().get_entity(limit).is_ok());
    }
}
