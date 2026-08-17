use super::generated;
use super::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts, get_string,
    ui_string,
};
use super::query_floater::bind_query_floater_control;
use super::retail::{RetailPictureSwap, RetailTag, RetailTree, RetailUiAssets};
use crate::media::RetailAudioAssets;
use crate::{AppState, ReturnTo};
use bevy::picking::hover::DirectlyHovered;
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{
    Activate, Button, Checkbox, Slider, SliderOrientation, SliderPrecision, SliderRange,
    SliderValue, TrackClick, ValueChange, slider_self_update,
};
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

/// `g_anGamePreferenceIndexByRow` and the controls for each displayed row.
const PREFERENCE_ROWS: [(
    i16,
    imperialism_formats::FourCc,
    imperialism_formats::FourCc,
); 5] = [
    (3, fourcc!("opta"), fourcc!("txta")),
    (2, fourcc!("optb"), fourcc!("txtb")),
    (8, fourcc!("optc"), fourcc!("txtc")),
    (10, fourcc!("optd"), fourcc!("txtd")),
    (0, fourcc!("opte"), fourcc!("txte")),
];
const SLIDER_SPLIT_PAD: i16 = 0x0c;
const MUSIC_SLIDER_SCALE: i16 = 0xff;
const SOUND_SLIDER_SCALE: i16 = 100;
const MUSIC_PICTURE_BASE: i16 = 0x1036;
const SOUND_PICTURE_BASE: i16 = 0x1038;
const TACTICAL_BATTLE_ON_PICTURE: i16 = 4158;
const TACTICAL_BATTLE_OFF_PICTURE: i16 = 4160;

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

impl GamePreferences {
    /// Preference slot 2: DirectSound master percent, 0..=100.
    pub(crate) fn sound_volume_percent(&self) -> i16 {
        self.values[2]
    }

    /// Preference slot 3: CD/aux music scalar, 0..=255.
    pub(crate) fn music_volume(&self) -> i16 {
        self.values[3]
    }

    /// Preference slot 8 gates `ShowTurnAlertsForActiveNation`.
    pub(crate) fn turn_alerts_enabled(&self) -> bool {
        self.values[8] != 0
    }
}

#[derive(Component)]
struct PreferencesRoot;

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
            .add_systems(
                OnExit(AppState::Preferences),
                super::session::clear_return_to,
            );
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
    tree: RetailTree,
    mut nodes: Query<&mut Node>,
    prefs: Res<GamePreferences>,
    mut assets: RetailUiAssets,
) {
    let root = *root;
    bind_query_floater_control(&mut commands, root, &tree);
    let curs = tree.find(root, fourcc!("curs"));
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
        &tree,
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

    for (row, &(_, checkbox_tag, label_tag)) in PREFERENCE_ROWS.iter().enumerate() {
        let checkbox = tree.try_find(root, checkbox_tag);
        // Missing opta/optb: label-only row always uses the "on" caption.
        let caption_on = checkbox.is_none() || preference_row_is_on(&prefs, row);
        commands.entity(tree.find(root, label_tag)).insert((
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
            .observe(on_preference_checked::<Add, Checked>)
            .observe(on_preference_checked::<Remove, Checked>)
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
        tree.find(root, fourcc!("musi")),
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
        tree.find(root, fourcc!("soun")),
        &nodes,
        SOUND_PICTURE_BASE,
        2,
        SOUND_SLIDER_SCALE,
        prefs.values[2],
        sound_hover,
    );

    commands
        .entity(tree.find(root, fourcc!("okay")))
        .observe(on_preferences_activate)
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
        .entity(tree.find(root, fourcc!("tpca")))
        .insert((
            Text::new(ui_string(&assets, 0x2763, 0x18)),
            font,
            layout,
            line_height,
            color,
        ))
        .remove::<InteractionDisabled>();
    let yes = tree.find(root, fourcc!("yess"));
    let no = tree.find(root, fourcc!("nooo"));
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
        .entity(tree.find(root, fourcc!("opca")))
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
        .observe(on_preference_slider_change)
        .observe(on_sound_slider_released)
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
    let index = PREFERENCE_ROWS[row].0;
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
    match slider.slot {
        3 => prefs.values[3] = change.value as i16,
        2 if change.is_final => prefs.values[2] = change.value as i16,
        _ => {}
    }
}

fn on_sound_slider_released(
    change: On<ValueChange<f32>>,
    sliders: Query<&PreferenceSlider>,
    mut commands: Commands,
    mut audio: RetailAudioAssets,
) {
    let Ok(slider) = sliders.get(change.source) else {
        return;
    };
    if slider.slot != 2 || !change.is_final {
        return;
    }
    audio.play(&mut commands, SoundId::UI_CLICK);
}

#[allow(clippy::type_complexity)]
fn sync_preference_slider_visuals(
    sliders: Query<
        (Entity, &SliderValue, &SliderRange),
        (With<PreferenceSlider>, Changed<SliderValue>),
    >,
    children: Query<&Children>,
    mut layers: Query<(&PreferenceSliderLayer, &mut Node)>,
    mut images: Query<&mut Node, Without<PreferenceSliderLayer>>,
    mut off_labels: Query<&mut Visibility, With<PreferenceSliderOffLabel>>,
) {
    for (slider, value, range) in &sliders {
        let Ok(kids) = children.get(slider) else {
            continue;
        };
        let (height, width) = match images.get(slider) {
            Ok(node) => (
                match node.height {
                    Val::Px(height) => height as i16,
                    _ => 91,
                },
                match node.width {
                    Val::Px(width) => width,
                    _ => 102.0,
                },
            ),
            Err(_) => (91, 102.0),
        };
        let split = slider_split_from_value(value.0 as i16, height, range.end() as i16);
        let fill = slider_fill_height(split);
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
    let Some((label, _)) = labels
        .iter()
        .find(|(_, tag)| tag.0 == PREFERENCE_ROWS[row.0].2)
    else {
        return;
    };
    if let Ok(mut text) = texts.get_mut(label) {
        text.0 = preference_caption(&assets, row.0, E::is::<Add>());
    }
}

fn on_preferences_activate(
    _activate: On<Activate>,
    rows: Query<(&PreferenceRow, Has<Checked>)>,
    sliders: Query<(&PreferenceSlider, &SliderValue)>,
    mut prefs: ResMut<GamePreferences>,
    returning: Res<ReturnTo>,
    mut next_state: ResMut<NextState<AppState>>,
) {
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
    fn sound_slider_release_writes_preference_slot_2() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .init_resource::<GamePreferences>()
            .add_observer(on_preference_slider_change);
        let slider = app.world_mut().spawn(PreferenceSlider { slot: 2 }).id();
        app.world_mut().commands().trigger(ValueChange {
            source: slider,
            value: 40.0_f32,
            is_final: false,
        });
        app.world_mut().flush();
        assert_eq!(
            app.world()
                .resource::<GamePreferences>()
                .sound_volume_percent(),
            100
        );

        app.world_mut().commands().trigger(ValueChange {
            source: slider,
            value: 40.0_f32,
            is_final: true,
        });
        app.world_mut().flush();
        assert_eq!(
            app.world()
                .resource::<GamePreferences>()
                .sound_volume_percent(),
            40
        );
    }
}
