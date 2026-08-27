//! Transport gauge fill/limit presentation helpers.
//!
//! `retail_transport_gauge` owns the track, fill, and limit child hierarchy.
//! Screens bind [`TransportGaugeParts`] and update fill/limit via retained handles.
//! Recovered caption and arrow controls remain ordinary generated children.

use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;

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

#[derive(Clone, Copy)]
struct TransportGaugeColors {
    track_bg: Color,
    fill: Color,
    limit: Color,
}

/// `TTransportPicture` track/fill/limit chrome for one gauge row.
///
/// `owner_left` is the recovered control origin; track placement follows
/// `TTransportPicture::Refresh` (`owner_left > 0xc8` => 0x5d else 0x61).
pub fn retail_transport_gauge(owner_left: i32, capacity: bool) -> impl Scene {
    bsn! {
        template(move |context| Ok(spawn_transport_gauge(context, owner_left, capacity)))
    }
}

fn transport_gauge_track_left(owner_left: i32) -> f32 {
    if owner_left > 0xC8 {
        0x5D as f32
    } else {
        0x61 as f32
    }
}

fn spawn_transport_gauge(
    context: &mut TemplateContext,
    owner_left: i32,
    capacity: bool,
) -> TransportGaugeParts {
    let colors = TransportGaugeColors {
        track_bg: palette_color(context, TRACK_BG_PALETTE),
        fill: palette_color(
            context,
            if capacity {
                CAPACITY_FILL_PALETTE
            } else {
                ALLOCATION_FILL_PALETTE
            },
        ),
        limit: palette_color(context, LIMIT_PALETTE),
    };
    let mut parts = TransportGaugeParts {
        fill: Entity::PLACEHOLDER,
        limit: Entity::PLACEHOLDER,
    };
    context.entity.with_children(|parent| {
        parts = spawn_transport_gauge_nodes(
            parent,
            transport_gauge_track_left(owner_left),
            capacity,
            colors,
        );
    });
    parts
}

fn spawn_transport_gauge_nodes(
    parent: &mut ChildSpawner,
    track_left: f32,
    capacity: bool,
    colors: TransportGaugeColors,
) -> TransportGaugeParts {
    parent.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(track_left),
            top: Val::Px(TRACK_TOP),
            width: Val::Px(TRACK_WIDTH),
            height: Val::Px(TRACK_HEIGHT),
            ..default()
        },
        BackgroundColor(colors.track_bg),
        Pickable::IGNORE,
    ));
    let fill = parent
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(track_left),
                top: Val::Px(TRACK_TOP),
                width: Val::Px(0.0),
                height: Val::Px(TRACK_HEIGHT),
                ..default()
            },
            BackgroundColor(colors.fill),
            Pickable::IGNORE,
        ))
        .id();
    let limit = if capacity {
        Entity::PLACEHOLDER
    } else {
        parent
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(track_left - 1.0),
                    top: Val::Px(LIMIT_TOP),
                    width: Val::Px(LIMIT_WIDTH),
                    height: Val::Px(LIMIT_HEIGHT),
                    ..default()
                },
                BackgroundColor(colors.limit),
                Visibility::Hidden,
                Pickable::IGNORE,
            ))
            .id()
    };

    TransportGaugeParts { fill, limit }
}

fn palette_color(context: &TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
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

    #[test]
    fn transport_gauge_spawn_builds_allocation_and_capacity_hierarchies() {
        let colors = TransportGaugeColors {
            track_bg: Color::WHITE,
            fill: Color::srgb(1.0, 0.0, 0.0),
            limit: Color::srgb(0.0, 0.0, 1.0),
        };
        let mut world = World::new();
        let allocation_root = world.spawn_empty().id();
        let allocation_parts = {
            let mut parts = TransportGaugeParts {
                fill: Entity::PLACEHOLDER,
                limit: Entity::PLACEHOLDER,
            };
            world.entity_mut(allocation_root).with_children(|parent| {
                parts = spawn_transport_gauge_nodes(parent, 0x61 as f32, false, colors);
            });
            parts
        };
        world.entity_mut(allocation_root).insert(allocation_parts);
        let allocation_parts = world
            .get::<TransportGaugeParts>(allocation_root)
            .copied()
            .expect("allocation gauge");
        assert_ne!(allocation_parts.limit, Entity::PLACEHOLDER);
        assert_eq!(
            world.get::<ChildOf>(allocation_parts.fill).unwrap().0,
            allocation_root
        );
        assert_eq!(
            world.get::<ChildOf>(allocation_parts.limit).unwrap().0,
            allocation_root
        );
        assert_eq!(world.get::<Children>(allocation_root).unwrap().len(), 3);

        let capacity_root = world.spawn_empty().id();
        let capacity_parts = {
            let mut parts = TransportGaugeParts {
                fill: Entity::PLACEHOLDER,
                limit: Entity::PLACEHOLDER,
            };
            world.entity_mut(capacity_root).with_children(|parent| {
                parts = spawn_transport_gauge_nodes(parent, 0x5D as f32, true, colors);
            });
            parts
        };
        world.entity_mut(capacity_root).insert(capacity_parts);
        let capacity_parts = world
            .get::<TransportGaugeParts>(capacity_root)
            .copied()
            .expect("capacity gauge");
        assert_eq!(capacity_parts.limit, Entity::PLACEHOLDER);
        assert_eq!(
            world.get::<ChildOf>(capacity_parts.fill).unwrap().0,
            capacity_root
        );
        assert_eq!(world.get::<Children>(capacity_root).unwrap().len(), 2);
    }
}
