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

/// `TTransportPicture` track/fill/limit chrome for one gauge row.
///
/// `track_left` mirrors `Refresh`: owner local x > 0xc8 => 0x5d else 0x61.
pub fn retail_transport_gauge(track_left: i32, capacity: bool) -> impl Scene {
    bsn! {
        template(move |context| Ok(spawn_transport_gauge(context, track_left, capacity)))
    }
}

fn spawn_transport_gauge(
    context: &mut TemplateContext,
    track_left: i32,
    capacity: bool,
) -> TransportGaugeParts {
    let track_left = track_left as f32;
    let fill_palette = if capacity {
        CAPACITY_FILL_PALETTE
    } else {
        ALLOCATION_FILL_PALETTE
    };
    let track_bg = palette_color(context, TRACK_BG_PALETTE);
    let fill_color = palette_color(context, fill_palette);
    let limit_color = palette_color(context, LIMIT_PALETTE);

    let mut fill = Entity::PLACEHOLDER;
    let mut limit = Entity::PLACEHOLDER;

    context.entity.with_children(|parent| {
        parent.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(track_left),
                top: Val::Px(TRACK_TOP),
                width: Val::Px(TRACK_WIDTH),
                height: Val::Px(TRACK_HEIGHT),
                ..default()
            },
            BackgroundColor(track_bg),
            Pickable::IGNORE,
        ));
        fill = parent
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(track_left),
                    top: Val::Px(TRACK_TOP),
                    width: Val::Px(0.0),
                    height: Val::Px(TRACK_HEIGHT),
                    ..default()
                },
                BackgroundColor(fill_color),
                Pickable::IGNORE,
            ))
            .id();
        if !capacity {
            limit = parent
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(track_left - 1.0),
                        top: Val::Px(LIMIT_TOP),
                        width: Val::Px(LIMIT_WIDTH),
                        height: Val::Px(LIMIT_HEIGHT),
                        ..default()
                    },
                    BackgroundColor(limit_color),
                    Visibility::Hidden,
                    Pickable::IGNORE,
                ))
                .id();
        }
    });

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
    fn transport_gauge_width_distributes_remainder_pixels() {
        assert_eq!(transport_gauge_width(0, 10), 0.0);
        assert_eq!(transport_gauge_width(0, 0), 0.0);
        assert!(transport_gauge_width(5, 10) > 0.0);
        assert!(transport_gauge_width(10, 10) <= TRACK_WIDTH);
    }
}
