//! Recovered `TTransportPicture` gauge overlays as a structure-only BSN SceneComponent.
//!
//! Screens call [`apply_transport_gauge`] (or write fill/caption/limit directly).
//! The Add observer wires the generated `text` child into [`TransportGaugeParts`].

use super::retail::{RetailTag, retail_picture};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use imperialism_formats::fourcc;

const TRACK_WIDTH: f32 = 113.0;
const TRACK_TOP: f32 = 0x0d as f32;
const TRACK_HEIGHT: f32 = 0x04 as f32;
const LIMIT_TOP: f32 = 0x12 as f32;
const LIMIT_HEIGHT: f32 = 0x02 as f32;
const REMAINDER_PALETTE: u8 = 0x3b;
const ALLOCATION_FILL_PALETTE: u8 = 0x3a;
const PARTIAL_PALETTE: u8 = 0x33;
const FULL_PALETTE: u8 = 0x34;

/// Row vs capacity specialization recovered from `TTransportPicture::Refresh`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetailTransportGaugeKind {
    #[default]
    Allocation,
    Capacity,
}

/// Private structure for the transport-gauge hierarchy.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(TransportGaugeProps)]
pub struct TransportGaugeParts {
    pub kind: RetailTransportGaugeKind,
    pub fill: Entity,
    pub limit: Entity,
    /// Generated `text` child; wired on `Add` once the scene children exist.
    pub caption: Entity,
}

/// Static construction props for [`TransportGaugeParts`].
#[derive(Default, Clone, Copy)]
pub struct TransportGaugeProps {
    pub picture_id: i16,
    pub kind: RetailTransportGaugeKind,
    pub track_left: i16,
}

impl TransportGaugeParts {
    fn scene(props: TransportGaugeProps) -> impl Scene {
        let track_left = f32::from(props.track_left);
        let fill_palette = match props.kind {
            RetailTransportGaugeKind::Allocation => ALLOCATION_FILL_PALETTE,
            RetailTransportGaugeKind::Capacity => PARTIAL_PALETTE,
        };
        bsn! {
            retail_picture(props.picture_id)
            TransportGaugeParts {
                kind: {props.kind},
                fill: #Fill,
                limit: #Limit,
                caption: {Entity::PLACEHOLDER},
            }
            Children [
                (
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(track_left),
                        top: px(TRACK_TOP),
                        width: px(TRACK_WIDTH),
                        height: px(TRACK_HEIGHT),
                    }
                    template(move |context| {
                        Ok(BackgroundColor(template_palette_color(context, REMAINDER_PALETTE)))
                    })
                    Pickable::IGNORE
                ),
                (
                    #Fill
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(track_left),
                        top: px(TRACK_TOP),
                        width: px(0),
                        height: px(TRACK_HEIGHT),
                    }
                    template(move |context| {
                        Ok(BackgroundColor(template_palette_color(context, fill_palette)))
                    })
                    Pickable::IGNORE
                ),
                (
                    #Limit
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(track_left - 1.0),
                        top: px(LIMIT_TOP),
                        width: px(TRACK_WIDTH + 2.0),
                        height: px(LIMIT_HEIGHT),
                    }
                    template(move |context| {
                        Ok(BackgroundColor(template_palette_color(context, PARTIAL_PALETTE)))
                    })
                    template(|_context| Ok(Visibility::Hidden))
                    Pickable::IGNORE
                ),
            ]
        }
    }
}

/// BSN helper used by generated screens.
pub fn retail_transport_gauge(
    picture_id: i16,
    kind: RetailTransportGaugeKind,
    track_left: i16,
) -> impl Scene {
    bsn! {
        @TransportGaugeParts {
            @picture_id: picture_id,
            @kind: kind,
            @track_left: track_left,
        }
    }
}

pub(super) fn register_transport_gauge(app: &mut App) {
    app.add_observer(on_transport_gauge_added);
}

fn on_transport_gauge_added(
    event: On<Add, TransportGaugeParts>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut gauges: Query<&mut TransportGaugeParts>,
) {
    let Ok(mut gauge) = gauges.get_mut(event.entity) else {
        return;
    };
    let Ok(kids) = children.get(event.entity) else {
        return;
    };
    for child in kids.iter() {
        if tags.get(child).is_ok_and(|tag| tag.0 == fourcc!("text")) {
            gauge.caption = child;
            return;
        }
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

/// Project authoritative gauge values onto fill, caption, and limit presentation.
pub fn apply_transport_gauge(
    parts: &TransportGaugeParts,
    current: i16,
    total: i16,
    limit: Option<i16>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    backgrounds: &mut Query<&mut BackgroundColor>,
    commands: &mut Commands,
    partial: Color,
    full: Color,
) {
    nodes
        .get_mut(parts.fill)
        .expect("TransportGaugeParts fill child")
        .width = Val::Px(transport_gauge_width(current, total));
    if parts.caption != Entity::PLACEHOLDER {
        texts
            .get_mut(parts.caption)
            .expect("TransportGaugeParts caption child")
            .0 = format!("{current}  /  {total}");
    }
    match parts.kind {
        RetailTransportGaugeKind::Allocation => match limit {
            Some(limit) => {
                commands.entity(parts.limit).insert(Visibility::Visible);
                backgrounds
                    .get_mut(parts.limit)
                    .expect("TransportGaugeParts limit child")
                    .0 = if current < limit { partial } else { full };
            }
            None => {
                commands.entity(parts.limit).insert(Visibility::Hidden);
            }
        },
        RetailTransportGaugeKind::Capacity => {
            backgrounds
                .get_mut(parts.fill)
                .expect("TransportGaugeParts fill child")
                .0 = if total > 0 && current == total {
                full
            } else {
                partial
            };
        }
    }
}

fn template_palette_color(context: &TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

/// Palette indices used by [`apply_transport_gauge`] for capacity/limit colouring.
pub const TRANSPORT_GAUGE_PARTIAL_PALETTE: u8 = PARTIAL_PALETTE;
pub const TRANSPORT_GAUGE_FULL_PALETTE: u8 = FULL_PALETTE;

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
