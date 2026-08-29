//! Transport gauge fill/limit presentation helpers.
//!
//! `retail_transport_gauge` owns the track, fill, and limit child hierarchy.
//! Screens bind [`TransportGaugeParts`] and update fill/limit via retained handles.
//! Recovered caption and arrow controls remain ordinary generated children.
//!
//! Unlike `retail_amount_bar()` and `retail_numbered_arrow()`, this helper cannot
//! own its entire subtree in BSN `Children [...]`. A `TTransportPicture` resource
//! node has both private Windows implementation entities (track/fill/limit) and
//! recovered public controls (`text`, `left`, `rght`, `valu`) that application
//! code binds by tag. The template adds only the private entities; the outer
//! generated scene keeps the recovered siblings.

use super::retail::RetailTag;
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use imperialism_formats::{FourCc, fourcc};

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

const TRANSPORT_CAPACITY_TAG: FourCc = fourcc!("tota");

/// `TTransportPicture` track/fill/limit chrome for one gauge row.
///
/// `owner_left` is the recovered control origin; track placement follows
/// `TTransportPicture::Refresh` (`owner_left > 0xc8` => 0x5d else 0x61`).
/// Capacity vs allocation fill is derived from the node's recovered `RetailTag`
/// (`tota` rows use the capacity palette and omit the limit marker).
pub fn retail_transport_gauge(owner_left: i32) -> impl Scene {
    bsn! {
        template(move |context| {
            let capacity = context
                .entity
                .get::<RetailTag>()
                .is_some_and(|tag| tag.0 == TRANSPORT_CAPACITY_TAG);
            Ok(spawn_transport_gauge(context, owner_left, capacity))
        })
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
}
