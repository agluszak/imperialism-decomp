//! Recovered `TAmtBar` family as a BSN SceneComponent.
//!
//! Structure (`RetailAmountBar` + fill/limit children) is spawned atomically.
//! Screens project [`RetailAmountBarState`] and observe `ValueChange<i16>`.

use super::retail_raster::IndexedRasterExt;
use crate::RetailAssetsResource;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::UiSystems;
use bevy::ui_widgets::ValueChange;
use imperialism_formats::IndexedPicture;

pub const INDUSTRY_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 150,
    height: 6,
    segments: 0,
};

pub const TRADE_AMOUNT_BAR: AmountBarGeometry = AmountBarGeometry {
    width: 100,
    height: 7,
    segments: 0,
};

pub const INDUSTRY_BAR_FILL: u8 = 0x16;
// `TTraderAmtBar` calls `ApplyLegendSplitSlot34(0x37)`, which resolves through
// `TViewMgr::GetColor` to palette 0xbd rather than using 0x37 as a DIB index.
pub const TRADE_BAR_FILL: u8 = 0xbd;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetailAmountBarKind {
    #[default]
    Industry,
    Rail,
    Trader,
}

/// Immutable recovered amount-bar specialization plus private child refs.
#[derive(SceneComponent, FromTemplate, Clone)]
#[scene(RetailAmountBarProps)]
pub struct RetailAmountBar {
    pub kind: RetailAmountBarKind,
    pub fill: Entity,
    pub limit: Entity,
}

/// Static construction props for [`RetailAmountBar`].
#[derive(Default, Clone, Copy)]
pub struct RetailAmountBarProps {
    pub kind: RetailAmountBarKind,
}

/// Live presentation state projected from authoritative gameplay.
#[derive(Component, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetailAmountBarState {
    pub value: i16,
    pub range: i16,
    pub maximum: i16,
}

impl RetailAmountBar {
    pub fn geometry(&self, state: RetailAmountBarState) -> AmountBarGeometry {
        match self.kind {
            RetailAmountBarKind::Industry | RetailAmountBarKind::Rail => {
                INDUSTRY_AMOUNT_BAR.with_segments(state.range)
            }
            RetailAmountBarKind::Trader => TRADE_AMOUNT_BAR.with_segments(state.range),
        }
    }

    fn scene(props: RetailAmountBarProps) -> impl Scene {
        let fill_index = match props.kind {
            RetailAmountBarKind::Trader => TRADE_BAR_FILL,
            RetailAmountBarKind::Industry | RetailAmountBarKind::Rail => INDUSTRY_BAR_FILL,
        };
        let (fill_top, fill_height) = match props.kind {
            RetailAmountBarKind::Trader => (Val::Px(0.0), Val::Percent(100.0)),
            RetailAmountBarKind::Industry | RetailAmountBarKind::Rail => {
                (Val::Px(1.0), Val::Px(4.0))
            }
        };
        let limit_visibility = match props.kind {
            RetailAmountBarKind::Trader => Visibility::Hidden,
            RetailAmountBarKind::Industry | RetailAmountBarKind::Rail => Visibility::Inherited,
        };
        bsn! {
            RetailAmountBar {
                kind: {props.kind},
                fill: #Fill,
                limit: #Limit,
            }
            RetailAmountBarState
            on(on_amount_bar_click)
            Children [
                (
                    #Fill
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: {fill_top},
                        width: px(0),
                        height: {fill_height},
                    }
                    template(move |context| {
                        Ok(BackgroundColor(template_palette_color(context, fill_index)))
                    })
                    Pickable::IGNORE
                ),
                (
                    #Limit
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(0),
                        width: px(1),
                        height: px(5),
                    }
                    template(move |context| {
                        Ok(BackgroundColor(template_palette_color(context, 0)))
                    })
                    template_value(limit_visibility)
                    Pickable::IGNORE
                ),
            ]
        }
    }
}

/// BSN helper used by generated screens.
pub fn retail_amount_bar(kind: RetailAmountBarKind) -> impl Scene {
    bsn! {
        @RetailAmountBar {
            @kind: kind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountBarGeometry {
    pub width: i32,
    pub height: i32,
    pub segments: i16,
}

impl AmountBarGeometry {
    pub const fn with_segments(self, segments: i16) -> Self {
        Self { segments, ..self }
    }

    pub fn span(self, value: i16) -> i16 {
        if self.segments <= 0 {
            0
        } else {
            (i32::from(value) * self.width / i32::from(self.segments)).clamp(0, self.width) as i16
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmountBarPixels {
    pub range: i16,
    pub current: i16,
    pub color: u8,
}

/// Counter offset relative to the bar's top-left for industry/rail quantity markers.
pub fn amount_bar_counter_offset(geometry: AmountBarGeometry, value: i16) -> Vec2 {
    let span = geometry.span(value);
    Vec2::new(f32::from(span) - 2.0, 6.0)
}

pub(super) fn register_amount_bar(app: &mut App) {
    app.add_systems(PostUpdate, draw_amount_bars.before(UiSystems::Prepare));
}

fn template_palette_color(context: &bevy::ecs::template::TemplateContext, index: u8) -> Color {
    let [red, green, blue] = context
        .resource::<RetailAssetsResource>()
        .assets()
        .default_dib_palette()[index]
        .to_array();
    Color::srgb_u8(red, green, blue)
}

fn draw_amount_bars(
    bars: Query<(&RetailAmountBar, &RetailAmountBarState), Changed<RetailAmountBarState>>,
    mut nodes: Query<&mut Node>,
) {
    for (bar, state) in &bars {
        let geometry = bar.geometry(*state);
        let span = geometry.span(state.value);
        nodes
            .get_mut(bar.fill)
            .expect("RetailAmountBar fill child")
            .width = Val::Px(f32::from(span));
        if !matches!(bar.kind, RetailAmountBarKind::Trader) {
            nodes
                .get_mut(bar.limit)
                .expect("RetailAmountBar limit child")
                .left = Val::Px(f32::from(geometry.span(state.maximum)));
        }
    }
}

fn on_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RetailAmountBar, &RetailAmountBarState)>,
    mut commands: Commands,
) {
    let Ok((bar, state)) = bars.get(click.entity) else {
        return;
    };
    let Some(position) = click.hit.position else {
        return;
    };
    click.propagate(false);
    let geometry = bar.geometry(*state);
    let x = amount_bar_x_from_normalized(geometry, position.x);
    let value = match bar.kind {
        RetailAmountBarKind::Trader => trade_amount_bar_click_value(geometry, x),
        RetailAmountBarKind::Industry | RetailAmountBarKind::Rail => {
            amount_bar_click_value(geometry, x, state.value)
        }
    };
    commands.trigger(ValueChange {
        source: click.entity,
        value,
        is_final: true,
    });
}

/// `TAmtBar::DoMouseCommand`: `x * segments / width + 1`, with a leading half-segment dead zone.
pub fn amount_bar_value_at_x(geometry: AmountBarGeometry, x: i32) -> i16 {
    if geometry.width <= 0 {
        return 0;
    }
    if geometry.segments <= 0 {
        // `auxValueA <= 0` takes the float branch: `x * 0 / width + 1`.
        return 1;
    }
    let dead_zone = geometry.width / (i32::from(geometry.segments) << 1);
    if x < dead_zone {
        0
    } else {
        (x * i32::from(geometry.segments) / geometry.width + 1) as i16
    }
}

pub fn amount_bar_x_from_normalized(geometry: AmountBarGeometry, normalized_x: f32) -> i32 {
    (((normalized_x + 0.5) * geometry.width as f32).floor() as i32).clamp(0, geometry.width - 1)
}

/// `TAmtBar` fallback: a click that would yield 0 is promoted to 1 when the counter is already 0.
pub fn amount_bar_click_value(geometry: AmountBarGeometry, x: i32, previous: i16) -> i16 {
    let mut value = amount_bar_value_at_x(geometry, x);
    if value == 0 && x != 0 && previous == 0 {
        value = 1;
    }
    value
}

/// `TTraderAmtBar::ApplyMoveClamp`: a click in the first merchant-capacity column becomes 1.
pub fn trade_amount_bar_click_value(geometry: AmountBarGeometry, x: i32) -> i16 {
    let value = amount_bar_value_at_x(geometry, x);
    if geometry.segments > 0 && x > 0 && x < geometry.width / i32::from(geometry.segments) {
        1
    } else {
        value
    }
}

/// `TRailCluster::SetMoveAmount` quantization: `((step / 2 + value) / step) * step`.
pub fn quantize_amount_bar_value(value: i16, step: i16) -> i16 {
    if step <= 0 {
        value
    } else {
        let step = i32::from(step);
        ((step / 2 + i32::from(value)) / step * step) as i16
    }
}

#[allow(dead_code)] // recovered TAmtBar::Draw overlay; no unspecialized bar is bound yet
pub fn draw_base_amount_bar(
    picture: &mut IndexedPicture,
    pixels: AmountBarPixels,
    geometry: AmountBarGeometry,
) {
    let fill = i32::from(pixels.current.min(pixels.range)).clamp(0, geometry.width);
    if fill > 0 {
        picture.fill_rect(IRect::new(0, 1, fill, geometry.height.min(5)), pixels.color);
    }
    if fill < geometry.width {
        picture.fill_rect(IRect::new(fill, 4, geometry.width, 5), 0);
    }
}

#[cfg(test)]
#[allow(clippy::identity_op)]
mod tests {
    use super::super::retail_raster::indexed_picture;
    use super::*;

    const KEY_INDEX: u8 = 0x10;

    #[test]
    fn click_uses_a_leading_half_segment_dead_zone() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        assert_eq!(amount_bar_value_at_x(geometry, 0), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 6), 0);
        assert_eq!(amount_bar_value_at_x(geometry, 7), 1);
        assert_eq!(amount_bar_value_at_x(geometry, 15), 2);
        assert_eq!(amount_bar_value_at_x(geometry, 149), 10);
    }

    #[test]
    fn zero_capacity_click_is_one() {
        assert_eq!(
            amount_bar_value_at_x(INDUSTRY_AMOUNT_BAR.with_segments(0), 40),
            1
        );
    }

    #[test]
    fn click_promotes_a_dead_zone_press_when_the_counter_is_already_zero() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(10);
        assert_eq!(amount_bar_click_value(geometry, 3, 0), 1);
        assert_eq!(amount_bar_click_value(geometry, 3, 4), 0);
        assert_eq!(amount_bar_click_value(geometry, 0, 0), 0);
    }

    #[test]
    fn trade_click_clamps_the_first_capacity_column_to_one() {
        let geometry = TRADE_AMOUNT_BAR.with_segments(20);
        assert_eq!(trade_amount_bar_click_value(geometry, 0), 0);
        assert_eq!(trade_amount_bar_click_value(geometry, 3), 1);
        assert_eq!(trade_amount_bar_click_value(geometry, 50), 11);
    }

    #[test]
    fn rail_click_quantizes_to_the_cluster_step() {
        assert_eq!(quantize_amount_bar_value(1, 2), 2);
        assert_eq!(quantize_amount_bar_value(2, 2), 2);
        assert_eq!(quantize_amount_bar_value(3, 6), 6);
        assert_eq!(quantize_amount_bar_value(2, 6), 0);
        assert_eq!(quantize_amount_bar_value(5, 1), 5);
    }

    #[test]
    fn trader_bar_uses_the_view_manager_resolved_palette_index() {
        assert_eq!(TRADE_BAR_FILL, 0xbd);
    }

    #[test]
    fn base_bar_fills_to_current_and_underlines_the_remainder() {
        let mut picture = indexed_picture(20, 6, KEY_INDEX);
        draw_base_amount_bar(
            &mut picture,
            AmountBarPixels {
                range: 16,
                current: 8,
                color: INDUSTRY_BAR_FILL,
            },
            AmountBarGeometry {
                width: 20,
                height: 6,
                segments: 20,
            },
        );
        assert_eq!(picture.pixels[1 * 20 + 0], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[1 * 20 + 7], INDUSTRY_BAR_FILL);
        assert_eq!(picture.pixels[4 * 20 + 8], 0);
        assert_eq!(picture.pixels[4 * 20 + 19], 0);
    }

    #[test]
    fn span_scales_against_segments() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(50);
        assert_eq!(geometry.span(0), 0);
        assert_eq!(geometry.span(25), 75);
        assert_eq!(geometry.span(50), 150);
        assert_eq!(INDUSTRY_AMOUNT_BAR.span(10), 0);
    }

    #[test]
    fn counter_offset_tracks_fill_span() {
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(50);
        assert_eq!(
            amount_bar_counter_offset(geometry, 25),
            Vec2::new(73.0, 6.0)
        );
    }
}
