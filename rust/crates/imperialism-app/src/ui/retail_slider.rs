//! Recovered `TTwoPicSlider` over stock `Slider` (`height - 12` track + zero strip).

use super::retail::{
    load_template_picture, retail_text_color, retail_text_shadow, retail_text_style,
};
use crate::RetailAssetsResource;
use bevy::ecs::template::TemplateContext;
use bevy::picking::events::{Pointer, Press};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui::UiSystems;
use bevy::ui_widgets::{
    Slider, SliderOrientation, SliderPrecision, SliderRange, SliderValue, TrackClick, ValueChange,
};
use imperialism_formats::PictureId;

pub const TWO_PIC_SLIDER_SPLIT_PAD: i16 = 0x0c;

#[derive(Component, FromTemplate, Clone, Copy)]
#[component(immutable)]
pub struct RetailTwoPicSliderParts {
    pub input: Entity,
    pub lower: Entity,
    pub off: Entity,
}

#[derive(Component, FromTemplate, Clone, Copy)]
#[component(immutable)]
struct TwoPicSliderZeroStrip {
    input: Entity,
}

#[rustfmt::skip]
pub fn retail_two_pic_slider(
    picture_base: i16,
    scale: i16,
    off_group: i16,
    off_index: i16,
    disabled: bool,
) -> impl Scene {
    let input_disabled = disabled.then(|| bsn! { InteractionDisabled });
    bsn! {
        Pickable::IGNORE
        RetailTwoPicSliderParts { input: #Input, lower: #Lower, off: #Off }
        template(move |context| {
            Ok(ImageNode::new(load_template_picture(context, PictureId::new(picture_base))?))
        })
        Children [
            (
                #Input
                Node { position_type: PositionType::Absolute, left: px(0), top: px(0), right: px(0), bottom: px(TWO_PIC_SLIDER_SPLIT_PAD as f32) }
                Slider { track_click: TrackClick::Snap, orientation: SliderOrientation::Vertical }
                SliderValue(0.0)
                SliderRange::new(0.0, scale as f32)
                SliderPrecision(0)
                Pickable::default()
                {input_disabled}
            ),
            (
                #Zero
                Node { position_type: PositionType::Absolute, left: px(0), right: px(0), bottom: px(0), height: px(TWO_PIC_SLIDER_SPLIT_PAD as f32) }
                TwoPicSliderZeroStrip { input: #Input }
                Pickable::default()
            ),
            (
                #Lower
                Node { position_type: PositionType::Absolute, left: px(0), bottom: px(0), width: percent(100), height: px(0), overflow: Overflow::clip() }
                template(move |context| {
                    Ok(ImageNode::new(load_template_picture(context, PictureId::new(picture_base + 1))?))
                })
                Pickable::IGNORE
            ),
            (
                #Off
                Node { position_type: PositionType::Absolute, left: px(0), top: px(0), width: percent(100), height: percent(100), justify_content: JustifyContent::Center, align_items: AlignItems::Center }
                template(move |context| Ok(Text(load_off_string(context, off_group, off_index))))
                retail_text_style(1, 0, 14, 1)
                retail_text_color(0x28)
                retail_text_shadow(0, 1, 1)
                Visibility::Visible
                Pickable::IGNORE
            ),
        ]
    }
}

fn load_off_string(context: &TemplateContext, off_group: i16, off_index: i16) -> String {
    context
        .resource::<RetailAssetsResource>()
        .ui_string(off_group as u16, off_index as u16)
}

pub(super) fn register_slider(app: &mut App) {
    app.add_observer(on_two_pic_zero_strip_press).add_systems(
        PostUpdate,
        sync_two_pic_slider_visuals.before(UiSystems::Prepare),
    );
}

fn on_two_pic_zero_strip_press(
    mut press: On<Pointer<Press>>,
    strips: Query<&TwoPicSliderZeroStrip>,
    disabled: Query<Has<InteractionDisabled>>,
    mut commands: Commands,
) {
    let Ok(strip) = strips.get(press.event_target()) else {
        return;
    };
    press.propagate(false);
    if disabled.get(strip.input).unwrap_or(false) {
        return;
    }
    commands.trigger(ValueChange::<f32> {
        source: strip.input,
        value: 0.0,
        is_final: true,
    });
}

fn two_pic_slider_split(value: i16, height: i16, scale: i16) -> i16 {
    let span = height - TWO_PIC_SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    match value * span / scale {
        0 => 0,
        split => split + TWO_PIC_SLIDER_SPLIT_PAD,
    }
}

fn sync_two_pic_slider_visuals(
    roots: Query<(&RetailTwoPicSliderParts, &Node)>,
    values: Query<(&SliderValue, &SliderRange), Changed<SliderValue>>,
    mut nodes: Query<&mut Node, Without<RetailTwoPicSliderParts>>,
    mut images: Query<&mut ImageNode, Without<RetailTwoPicSliderParts>>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (parts, root) in &roots {
        let Ok((value, range)) = values.get(parts.input) else {
            continue;
        };
        let (Val::Px(height), Val::Px(width)) = (root.height, root.width) else {
            continue;
        };
        let height = height as i16;
        let split = two_pic_slider_split(value.0 as i16, height, range.end() as i16);
        let fill = if split < TWO_PIC_SLIDER_SPLIT_PAD {
            0
        } else {
            split
        };
        if let Ok(mut n) = nodes.get_mut(parts.lower) {
            n.height = Val::Px(f32::from(fill));
        }
        if let Ok(mut image) = images.get_mut(parts.lower) {
            let top = f32::from(height - fill);
            image.rect = Some(Rect {
                min: Vec2::new(0.0, top),
                max: Vec2::new(width.max(1.0), f32::from(height).max(top)),
            });
        }
        if let Ok(mut off) = visibilities.get_mut(parts.off) {
            *off = if split < TWO_PIC_SLIDER_SPLIT_PAD {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::picking::backend::HitData;
    use bevy::picking::pointer::{Location, PointerButton, PointerId};

    #[derive(Resource, Default)]
    struct Values(Vec<(Entity, f32)>);

    fn press(entity: Entity, app: &mut App) {
        app.world_mut().trigger(Pointer::new(
            PointerId::Mouse,
            Location {
                target: bevy::camera::NormalizedRenderTarget::None {
                    width: 1,
                    height: 1,
                },
                position: Vec2::ZERO,
            },
            Press {
                button: PointerButton::Primary,
                hit: HitData::new(Entity::from_bits(1), 0.0, None, None),
                count: 1,
            },
            entity,
        ));
        app.update();
    }

    #[test]
    fn slider_split_matches_retail_padding() {
        assert_eq!(two_pic_slider_split(0, 91, 100), 0);
        assert_eq!(two_pic_slider_split(100, 91, 100), 91);
        assert_eq!(two_pic_slider_split(0xff, 91, 0xff), 91);
    }

    #[test]
    fn zero_strip_emits_only_for_enabled_input() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins).init_resource::<Values>();
        register_slider(&mut app);
        app.world_mut()
            .add_observer(|change: On<ValueChange<f32>>, mut values: ResMut<Values>| {
                values.0.push((change.source, change.value));
            });
        app.update();

        let enabled_input = app.world_mut().spawn_empty().id();
        let enabled_strip = app
            .world_mut()
            .spawn(TwoPicSliderZeroStrip {
                input: enabled_input,
            })
            .id();
        app.update();
        press(enabled_strip, &mut app);
        assert_eq!(app.world().resource::<Values>().0, [(enabled_input, 0.0)]);

        let disabled_input = app.world_mut().spawn(InteractionDisabled).id();
        let disabled_strip = app
            .world_mut()
            .spawn(TwoPicSliderZeroStrip {
                input: disabled_input,
            })
            .id();
        app.update();
        press(disabled_strip, &mut app);
        assert_eq!(app.world().resource::<Values>().0, [(enabled_input, 0.0)]);
    }
}
