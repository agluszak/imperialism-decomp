//! Recovered `TTransportPicture` gauge overlays as a BSN SceneComponent.
//!
//! The retail picture is the static art; this widget owns the 113px fill track,
//! remainder band, optional limit strip, capacity fill colouring, and the
//! generated `text` child caption (`"{current}  /  {total}"`).

use super::retail::{RetailTag, retail_picture};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::prelude::*;
use bevy::ui::UiSystems;
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
#[scene(RetailTransportGaugeProps)]
pub struct RetailTransportGauge {
    pub kind: RetailTransportGaugeKind,
    pub fill: Entity,
    pub limit: Entity,
    /// Generated `text` child; wired on `Add` once the scene children exist.
    pub caption: Entity,
}

/// Static construction props for [`RetailTransportGauge`].
#[derive(Default, Clone, Copy)]
pub struct RetailTransportGaugeProps {
    pub picture_id: i16,
    pub kind: RetailTransportGaugeKind,
    pub track_left: i16,
}

/// Externally projected gauge state (`splitValue94` / `96` / `splitLimit98`).
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportGaugeValue {
    pub current: i16,
    pub total: i16,
    pub limit: Option<i16>,
}

impl RetailTransportGauge {
    fn scene(props: RetailTransportGaugeProps) -> impl Scene {
        let track_left = f32::from(props.track_left);
        let fill_palette = match props.kind {
            RetailTransportGaugeKind::Allocation => ALLOCATION_FILL_PALETTE,
            RetailTransportGaugeKind::Capacity => PARTIAL_PALETTE,
        };
        bsn! {
            retail_picture(props.picture_id)
            RetailTransportGauge {
                kind: {props.kind},
                fill: #Fill,
                limit: #Limit,
                caption: {Entity::PLACEHOLDER},
            }
            TransportGaugeValue
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
        @RetailTransportGauge {
            @picture_id: picture_id,
            @kind: kind,
            @track_left: track_left,
        }
    }
}

pub(super) fn register_transport_gauge(app: &mut App) {
    app.add_systems(PostUpdate, draw_transport_gauges.before(UiSystems::Prepare))
        .add_observer(on_transport_gauge_added);
}

fn on_transport_gauge_added(
    event: On<Add, RetailTransportGauge>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut gauges: Query<&mut RetailTransportGauge>,
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

fn template_palette_color(context: &TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

fn draw_transport_gauges(
    gauges: Query<(&RetailTransportGauge, &TransportGaugeValue), Changed<TransportGaugeValue>>,
    mut nodes: Query<&mut Node>,
    mut backgrounds: Query<&mut BackgroundColor>,
    mut texts: Query<&mut Text>,
    mut commands: Commands,
    assets: Option<Res<RetailAssetsResource>>,
) {
    let Some(assets) = assets else {
        return;
    };
    let partial = palette_color(&assets, PARTIAL_PALETTE);
    let full = palette_color(&assets, FULL_PALETTE);
    for (gauge, value) in &gauges {
        nodes
            .get_mut(gauge.fill)
            .expect("RetailTransportGauge fill child")
            .width = Val::Px(transport_gauge_width(value.current, value.total));
        if gauge.caption != Entity::PLACEHOLDER {
            texts
                .get_mut(gauge.caption)
                .expect("RetailTransportGauge caption child")
                .0 = format!("{}  /  {}", value.current, value.total);
        }
        match gauge.kind {
            RetailTransportGaugeKind::Allocation => match value.limit {
                Some(limit) => {
                    commands.entity(gauge.limit).insert(Visibility::Visible);
                    backgrounds
                        .get_mut(gauge.limit)
                        .expect("RetailTransportGauge limit child")
                        .0 = if value.current < limit { partial } else { full };
                }
                None => {
                    commands.entity(gauge.limit).insert(Visibility::Hidden);
                }
            },
            RetailTransportGaugeKind::Capacity => {
                backgrounds
                    .get_mut(gauge.fill)
                    .expect("RetailTransportGauge fill child")
                    .0 = if value.total > 0 && value.current == value.total {
                    full
                } else {
                    partial
                };
            }
        }
    }
}

fn palette_color(assets: &RetailAssetsResource, index: u8) -> Color {
    let [red, green, blue] = assets.assets().default_dib_palette()[index].to_array();
    Color::srgb_u8(red, green, blue)
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
