use super::generated;
use super::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts, get_string,
    ui_string,
};
use super::query_floater::bind_query_floater_control;
use super::retail::{
    RetailPictureSwap, RetailTag, RetailUiAssets, find_descendant, try_find_descendant,
};
use crate::AppState;
use bevy::picking::hover::DirectlyHovered;
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{
    Activate, Button, Checkbox, Slider, SliderOrientation, SliderPrecision, SliderRange,
    SliderValue, TrackClick, ValueChange, slider_self_update,
};
use imperialism_formats::{PictureId, RetailTextStylePreset, fourcc};

/// `g_anGamePreferenceIndexByRow`: which `preferenceValues` slot each opta..opte row displays.
const PREFERENCE_INDEX_BY_ROW: [i16; 5] = [3, 2, 8, 10, 0];
const CHECKBOX_TAGS: [imperialism_formats::FourCc; 5] = [
    fourcc!("opta"),
    fourcc!("optb"),
    fourcc!("optc"),
    fourcc!("optd"),
    fourcc!("opte"),
];
const LABEL_TAGS: [imperialism_formats::FourCc; 5] = [
    fourcc!("txta"),
    fourcc!("txtb"),
    fourcc!("txtc"),
    fourcc!("txtd"),
    fourcc!("txte"),
];
const SLIDER_SPLIT_PAD: i16 = 0x0c;
const MUSIC_SLIDER_SCALE: i16 = 0xff;
const SOUND_SLIDER_SCALE: i16 = 100;
const MUSIC_PICTURE_BASE: i16 = 0x1036;
const SOUND_PICTURE_BASE: i16 = 0x1038;
const TACTICAL_BATTLE_ON_PICTURE: i16 = 4158;
const TACTICAL_BATTLE_OFF_PICTURE: i16 = 4160;

/// Screen restored when preferences close.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreferencesReturn(pub(crate) AppState);

/// Retail `TSimMgr::preferenceValues[14]`.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GamePreferences {
    values: [i16; 14],
}

impl Default for GamePreferences {
    fn default() -> Self {
        // `TSimMgr::InitializeOrLoadEntryArray14AndClampLimits(false)` before the INI overlay.
        let mut values = [0x101; 14];
        values[0] = 0;
        values[1] = 0;
        values[2] = 100;
        values[3] = 0xff;
        values[10] = 0;
        values[11] = 0;
        values[12] = 0;
        Self { values }
    }
}

#[derive(Component)]
struct PreferencesRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum PreferencesAction {
    Okay,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceRow(usize);

/// Preference slot Okay writes after the checkboxes.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceSlider {
    slot: usize,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceSliderLayer {
    lower: bool,
}

#[derive(Component)]
struct PreferenceSliderOffLabel;

pub(crate) struct PreferencesPlugin;

impl Plugin for PreferencesPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<GamePreferences>()
            .add_systems(
                OnEnter(AppState::Preferences),
                (spawn_preferences, bind_preferences).chain(),
            )
            .add_systems(
                Update,
                sync_preference_slider_visuals.run_if(in_state(AppState::Preferences)),
            )
            .add_observer(
                on_preference_checked::<Add, Checked>.run_if(in_state(AppState::Preferences)),
            )
            .add_observer(
                on_preference_checked::<Remove, Checked>.run_if(in_state(AppState::Preferences)),
            )
            .add_observer(on_preference_slider_change.run_if(in_state(AppState::Preferences)))
            .add_observer(on_preferences_activate.run_if(in_state(AppState::Preferences)));
    }
}

fn spawn_preferences(mut commands: Commands) {
    let root = commands.spawn_scene(generated::linger_4150()).id();
    commands
        .entity(root)
        .insert((PreferencesRoot, DespawnOnExit(AppState::Preferences)));
}

fn bind_preferences(
    mut commands: Commands,
    root: Single<Entity, Added<PreferencesRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut nodes: Query<&mut Node>,
    prefs: Res<GamePreferences>,
    mut assets: RetailUiAssets,
) {
    let root = *root;
    bind_query_floater_control(&mut commands, root, &children, &tags);
    let curs = find_descendant(root, fourcc!("curs"), &children, &tags);
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        curs,
        &mut nodes.get_mut(curs).expect("preferences curs has Node"),
        HoverHelpBarStyle::PREFERENCES,
    );
    bind_hover_help_texts(
        &mut commands,
        root,
        &children,
        &tags,
        [
            (fourcc!("okay"), ui_string(&assets, 0x2743, 0x25)),
            (fourcc!("quer"), ui_string(&assets, 0x2730, 3)),
        ],
    );

    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail preferences caption style");
    let color = TextColor(assets.palette_color(0x38));

    for row in 0..5 {
        let checkbox = try_find_descendant(root, CHECKBOX_TAGS[row], &children, &tags);
        // Missing opta/optb: label-only row always uses the "on" caption.
        let caption_on = checkbox.is_none() || preference_row_is_on(&prefs, row);
        commands
            .entity(find_descendant(root, LABEL_TAGS[row], &children, &tags))
            .insert((
                Text::new(preference_caption(&assets, row, caption_on)),
                font.clone(),
                layout,
                line_height,
                color,
            ));
        let Some(checkbox) = checkbox else {
            continue;
        };
        let mut entity = commands.entity(checkbox);
        entity
            .insert((
                PreferenceRow(row),
                HoverHelpText(ui_string(&assets, 0x2743, row as i16 + 0x26)),
                DirectlyHovered::default(),
            ))
            .remove::<InteractionDisabled>();
        if row == 4 {
            let idle = assets
                .picture(PictureId::new(TACTICAL_BATTLE_OFF_PICTURE))
                .expect("tactical-battle preference off picture");
            let on = assets
                .picture(PictureId::new(TACTICAL_BATTLE_ON_PICTURE))
                .expect("tactical-battle preference on picture");
            entity.remove::<Button>().insert((
                Checkbox,
                RetailPictureSwap {
                    idle: idle.clone(),
                    active: on,
                },
                ImageNode::new(idle),
            ));
        }
        if preference_row_is_on(&prefs, row) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
    }

    let music_hover = ui_string(&assets, 0x2743, 0x27);
    let sound_hover = ui_string(&assets, 0x2743, 0x26);
    bind_volume_slider(
        &mut commands,
        &mut assets,
        find_descendant(root, fourcc!("musi"), &children, &tags),
        &nodes,
        MUSIC_PICTURE_BASE,
        3,
        MUSIC_SLIDER_SCALE,
        prefs.values[3],
        music_hover,
    );
    bind_volume_slider(
        &mut commands,
        &mut assets,
        find_descendant(root, fourcc!("soun"), &children, &tags),
        &nodes,
        SOUND_PICTURE_BASE,
        2,
        SOUND_SLIDER_SCALE,
        prefs.values[2],
        sound_hover,
    );

    commands
        .entity(find_descendant(root, fourcc!("okay"), &children, &tags))
        .insert(PreferencesAction::Okay)
        .remove::<InteractionDisabled>();

    let (radio_font, radio_layout, radio_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail auto-resolution option style");
    let radio_color = TextColor(assets.palette_color(0x28));
    let radio_shadow = TextShadow {
        offset: Vec2::ONE,
        color: assets.palette_color(0x5c),
    };
    commands
        .entity(find_descendant(root, fourcc!("tpca"), &children, &tags))
        .insert((
            Text::new(ui_string(&assets, 0x2763, 0x18)),
            font,
            layout,
            line_height,
            color,
        ))
        .remove::<InteractionDisabled>();
    let yes = find_descendant(root, fourcc!("yess"), &children, &tags);
    let no = find_descendant(root, fourcc!("nooo"), &children, &tags);
    commands.entity(yes).insert((
        Text::new(ui_string(&assets, 0x2763, 0x16)),
        radio_font.clone(),
        radio_layout,
        radio_line_height,
        radio_color,
        radio_shadow,
        Checked,
    ));
    commands
        .entity(no)
        .insert((
            Text::new(ui_string(&assets, 0x2763, 0x17)),
            radio_font,
            radio_layout,
            radio_line_height,
            radio_color,
            radio_shadow,
        ))
        .remove::<Checked>();
    commands
        .entity(find_descendant(root, fourcc!("opca"), &children, &tags))
        .remove::<InteractionDisabled>();
}

#[allow(clippy::too_many_arguments)]
fn bind_volume_slider(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    slider: Entity,
    nodes: &Query<&mut Node>,
    picture_base: i16,
    slot: usize,
    scale: i16,
    value: i16,
    hover: String,
) {
    let height = node_px_height(nodes, slider).unwrap_or(91);
    let width = node_px_width(nodes, slider).unwrap_or(102.0);
    let split = slider_split_from_value(value, height, scale);
    let upper = assets
        .picture(PictureId::new(picture_base))
        .expect("preference slider upper picture");
    let lower = assets
        .picture(PictureId::new(picture_base + 1))
        .expect("preference slider lower picture");
    commands
        .entity(slider)
        .insert((
            Slider {
                track_click: TrackClick::Snap,
                orientation: SliderOrientation::Vertical,
            },
            SliderValue(f32::from(value)),
            SliderRange::new(0.0, f32::from(scale)),
            SliderPrecision(0),
            PreferenceSlider { slot },
            HoverHelpText(hover),
            DirectlyHovered::default(),
        ))
        .observe(slider_self_update)
        .remove::<InteractionDisabled>();
    spawn_slider_layers(commands, slider, upper, lower, split, height, width);
    let (off_font, off_layout, off_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 1,
        })
        .expect("retail slider off-label style");
    commands.spawn((
        PreferenceSliderOffLabel,
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(0.0),
            top: Val::Px(0.0),
            width: Val::Px(width),
            height: Val::Px(f32::from(height)),
            justify_content: JustifyContent::Center,
            align_items: AlignItems::Center,
            ..default()
        },
        Text::new(get_string(assets, 0x2743, 0x3b)),
        off_font,
        off_layout,
        off_line_height,
        TextColor(assets.palette_color(0)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0x28),
        },
        if split < SLIDER_SPLIT_PAD {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        },
        Pickable::IGNORE,
        ChildOf(slider),
    ));
}

fn spawn_slider_layers(
    commands: &mut Commands,
    slider: Entity,
    upper: Handle<Image>,
    lower: Handle<Image>,
    split: i16,
    height: i16,
    width: f32,
) {
    let fill = slider_fill_height(split);
    let upper_clip = commands
        .spawn((
            PreferenceSliderLayer { lower: false },
            slider_clip_node(0.0, f32::from(height - fill), width),
            Pickable::IGNORE,
            ChildOf(slider),
        ))
        .id();
    commands.spawn((
        slider_image_node(width, f32::from(height)),
        ImageNode::new(upper),
        Pickable::IGNORE,
        ChildOf(upper_clip),
    ));
    let lower_top = f32::from(height - fill);
    let lower_clip = commands
        .spawn((
            PreferenceSliderLayer { lower: true },
            slider_clip_node(lower_top, f32::from(fill), width),
            Pickable::IGNORE,
            ChildOf(slider),
        ))
        .id();
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(0.0),
            top: Val::Px(f32::from(fill - height)),
            width: Val::Px(width),
            height: Val::Px(f32::from(height)),
            ..default()
        },
        ImageNode::new(lower),
        Pickable::IGNORE,
        ChildOf(lower_clip),
    ));
}

fn slider_clip_node(top: f32, height: f32, width: f32) -> Node {
    Node {
        position_type: PositionType::Absolute,
        left: Val::Px(0.0),
        top: Val::Px(top),
        width: Val::Px(width),
        height: Val::Px(height),
        overflow: Overflow::clip(),
        ..default()
    }
}

fn slider_image_node(width: f32, height: f32) -> Node {
    Node {
        position_type: PositionType::Absolute,
        left: Val::Px(0.0),
        top: Val::Px(0.0),
        width: Val::Px(width),
        height: Val::Px(height),
        ..default()
    }
}

fn node_px_height(nodes: &Query<&mut Node>, entity: Entity) -> Option<i16> {
    match nodes.get(entity).ok()?.height {
        Val::Px(height) => Some(height as i16),
        _ => None,
    }
}

fn node_px_width(nodes: &Query<&mut Node>, entity: Entity) -> Option<f32> {
    match nodes.get(entity).ok()?.width {
        Val::Px(width) => Some(width),
        _ => None,
    }
}

fn preference_row_is_on(prefs: &GamePreferences, row: usize) -> bool {
    let index = PREFERENCE_INDEX_BY_ROW[row];
    if index < 0 {
        return false;
    }
    prefs.values[index as usize] as u8 != 0
}

fn preference_caption(assets: &RetailUiAssets, row: usize, is_on: bool) -> String {
    get_string(assets, 0x2743, row as i16 * 2 + 0x10 + i16::from(!is_on))
}

fn slider_split_from_value(value: i16, height: i16, scale: i16) -> i16 {
    let span = height - SLIDER_SPLIT_PAD;
    if span <= 0 || scale == 0 {
        return 0;
    }
    let split = value * span / scale;
    if split == 0 {
        0
    } else {
        split + SLIDER_SPLIT_PAD
    }
}

fn slider_fill_height(split: i16) -> i16 {
    if split < SLIDER_SPLIT_PAD { 0 } else { split }
}

fn on_preference_slider_change(
    change: On<ValueChange<f32>>,
    sliders: Query<&PreferenceSlider>,
    mut prefs: ResMut<GamePreferences>,
) {
    let Ok(slider) = sliders.get(change.source) else {
        return;
    };
    if slider.slot == 3 {
        prefs.values[3] = change.value as i16;
    }
}

fn sync_preference_slider_visuals(
    sliders: Query<
        (Entity, &SliderValue, &SliderRange, &Node),
        (With<PreferenceSlider>, Changed<SliderValue>),
    >,
    children: Query<&Children>,
    mut layers: Query<(&PreferenceSliderLayer, &mut Node)>,
    mut images: Query<&mut Node, Without<PreferenceSliderLayer>>,
    mut off_labels: Query<&mut Visibility, With<PreferenceSliderOffLabel>>,
) {
    for (slider, value, range, node) in &sliders {
        let Ok(kids) = children.get(slider) else {
            continue;
        };
        let height = match node.height {
            Val::Px(height) => height as i16,
            _ => 91,
        };
        let split = slider_split_from_value(value.0 as i16, height, range.end() as i16);
        let fill = slider_fill_height(split);
        let width = match node.width {
            Val::Px(width) => width,
            _ => 102.0,
        };
        for child in kids.iter() {
            if let Ok(mut visibility) = off_labels.get_mut(child) {
                *visibility = if split < SLIDER_SPLIT_PAD {
                    Visibility::Inherited
                } else {
                    Visibility::Hidden
                };
            }
            let Ok((layer, mut node)) = layers.get_mut(child) else {
                continue;
            };
            if layer.lower {
                *node = slider_clip_node(f32::from(height - fill), f32::from(fill), width);
                if let Ok(image_kids) = children.get(child)
                    && let Some(image) = image_kids.iter().next()
                    && let Ok(mut image_node) = images.get_mut(image)
                {
                    image_node.top = Val::Px(f32::from(fill - height));
                }
            } else {
                *node = slider_clip_node(0.0, f32::from(height - fill), width);
            }
        }
    }
}

fn on_preference_checked<E: EntityEvent, C: Component>(
    event: On<E, C>,
    rows: Query<&PreferenceRow>,
    mut texts: Query<&mut Text>,
    labels: Query<(Entity, &RetailTag)>,
    assets: RetailUiAssets,
) {
    let Ok(row) = rows.get(event.event_target()) else {
        return;
    };
    let Some((label, _)) = labels.iter().find(|(_, tag)| tag.0 == LABEL_TAGS[row.0]) else {
        return;
    };
    if let Ok(mut text) = texts.get_mut(label) {
        text.0 = preference_caption(&assets, row.0, E::is::<Add>());
    }
}

fn on_preferences_activate(
    activate: On<Activate>,
    actions: Query<&PreferencesAction>,
    rows: Query<(&PreferenceRow, Has<Checked>)>,
    sliders: Query<(&PreferenceSlider, &SliderValue)>,
    mut prefs: ResMut<GamePreferences>,
    returning: Res<PreferencesReturn>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        PreferencesAction::Okay => {
            // `TGamePreferencesPicture::DoEvent` writes `preferenceValues[row] = IsOn`
            // for each present opta+row checkbox, then overwrites [3]/[2] from the sliders.
            for (row, checked) in &rows {
                prefs.values[row.0] = i16::from(checked);
            }
            for (slider, value) in &sliders {
                prefs.values[slider.slot] = value.0 as i16;
            }
            next_state.set(returning.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slider_split_matches_retail_padding() {
        assert_eq!(slider_split_from_value(0, 91, 100), 0);
        assert_eq!(slider_split_from_value(100, 91, 100), 91);
        assert_eq!(slider_split_from_value(0xff, 91, 0xff), 91);
    }

    #[test]
    fn okay_writes_checkbox_rows_then_slider_slots() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::Preferences)
            .insert_resource(PreferencesReturn(AppState::StrategicMap))
            .init_resource::<GamePreferences>()
            .add_observer(on_preferences_activate);
        let root = app.world_mut().spawn(PreferencesRoot).id();
        app.world_mut()
            .spawn((PreferenceRow(2), Checked, ChildOf(root)));
        app.world_mut().spawn((PreferenceRow(3), ChildOf(root)));
        app.world_mut().spawn((
            PreferenceSlider { slot: 2 },
            SliderValue(50.0),
            ChildOf(root),
        ));
        app.world_mut().spawn((
            PreferenceSlider { slot: 3 },
            SliderValue(0.0),
            ChildOf(root),
        ));
        let okay = app
            .world_mut()
            .spawn((PreferencesAction::Okay, ChildOf(root)))
            .id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: okay });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        let prefs = app.world().resource::<GamePreferences>();
        assert_eq!(prefs.values[2], 50);
        assert_eq!(prefs.values[3], 0);
    }
}
