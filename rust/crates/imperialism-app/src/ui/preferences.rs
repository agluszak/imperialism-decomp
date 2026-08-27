use super::generated;
use super::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts,
};
use super::query_floater::bind_query_floater_control;
use super::retail::{RetailPictureSwap, RetailTag, RetailTree, RetailUiAssets};
use super::retail_raster::IndexedRasterExt;
use crate::media::RetailAudioAssets;
use crate::{AppState, RetailAssetsResource, ReturnTo};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{
    Activate, Button, Checkbox, Slider, SliderOrientation, SliderPrecision, SliderRange,
    SliderValue, TrackClick, ValueChange, slider_self_update,
};
use enum_map::{Enum, EnumMap};
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId, fourcc};

/// `g_anGamePreferenceIndexByRow` and the controls for each displayed row.
const PREFERENCE_ROWS: [(
    PreferenceSlot,
    imperialism_formats::FourCc,
    imperialism_formats::FourCc,
); 5] = [
    (
        PreferenceSlot::MusicVolume,
        fourcc!("opta"),
        fourcc!("txta"),
    ),
    (
        PreferenceSlot::SoundVolume,
        fourcc!("optb"),
        fourcc!("txtb"),
    ),
    (PreferenceSlot::TurnAlerts, fourcc!("optc"), fourcc!("txtc")),
    (PreferenceSlot::Unknown10, fourcc!("optd"), fourcc!("txtd")),
    (
        PreferenceSlot::TacticalBattle,
        fourcc!("opte"),
        fourcc!("txte"),
    ),
];
const SLIDER_SPLIT_PAD: i16 = 0x0c;
const MUSIC_SLIDER_SCALE: i16 = 0xff;
const SOUND_SLIDER_SCALE: i16 = 100;
const MUSIC_PICTURE_BASE: PictureId = PictureId::new(0x1036);
const SOUND_PICTURE_BASE: PictureId = PictureId::new(0x1038);
const TACTICAL_BATTLE_ON_PICTURE: PictureId = PictureId::new(4158);
const TACTICAL_BATTLE_OFF_PICTURE: PictureId = PictureId::new(4160);

/// Retail `TSimMgr::preferenceValues[14]`.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
enum PreferenceSlot {
    TacticalBattle,
    Unknown1,
    SoundVolume,
    MusicVolume,
    Unknown4,
    Unknown5,
    Unknown6,
    Unknown7,
    TurnAlerts,
    Unknown9,
    Unknown10,
    Unknown11,
    Unknown12,
    Unknown13,
}

#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GamePreferences {
    values: EnumMap<PreferenceSlot, i16>,
}

impl Default for GamePreferences {
    fn default() -> Self {
        // `TSimMgr::InitializeOrLoadEntryArray14AndClampLimits(false)` before the INI overlay.
        Self {
            values: EnumMap::from_array([
                0, 0, 100, 0xff, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0, 0, 0, 0x101,
            ]),
        }
    }
}

impl GamePreferences {
    /// Preference slot 2: DirectSound master percent, 0..=100.
    pub(crate) fn sound_volume_percent(&self) -> i16 {
        self.values[PreferenceSlot::SoundVolume]
    }

    /// Preference slot 3: CD/aux music scalar, 0..=255.
    pub(crate) fn music_volume(&self) -> i16 {
        self.values[PreferenceSlot::MusicVolume]
    }

    /// Preference slot 8 gates `ShowTurnAlertsForActiveNation`.
    pub(crate) fn turn_alerts_enabled(&self) -> bool {
        self.values[PreferenceSlot::TurnAlerts] != 0
    }

    /// Preference slot 5 gates `TTacticalBattleView::GlideUnit`.
    pub(crate) fn tactical_movement_animations_enabled(&self) -> bool {
        self.values[PreferenceSlot::Unknown5] != 0
    }

    /// Preference slot 0 controls whether human-participant land battles open tactically.
    pub(crate) fn tactical_battles_enabled(&self) -> bool {
        self.values[PreferenceSlot::TacticalBattle] != 0
    }

    #[cfg(test)]
    pub(crate) fn set_tactical_battles_enabled(&mut self, enabled: bool) {
        self.values[PreferenceSlot::TacticalBattle] = i16::from(enabled);
    }
}

#[derive(Component)]
struct PreferencesRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceRow {
    ui_row: usize,
    slot: PreferenceSlot,
}

/// Preference slot Okay writes after the checkboxes.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceSlider {
    slot: PreferenceSlot,
}

#[derive(Component)]
struct PreferenceSliderVisual {
    upper: imperialism_formats::IndexedPicture,
    lower: imperialism_formats::IndexedPicture,
}

/// Centered "Off" caption shown while a volume slider sits at its minimum.
#[derive(Component)]
struct PreferenceSliderOff;

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
            (fourcc!("okay"), assets.ui_string(0x2743, 0x25)),
            (fourcc!("quer"), assets.ui_string(0x2730, 3)),
        ],
    );

    for (row, &(slot, checkbox_tag, label_tag)) in PREFERENCE_ROWS.iter().enumerate() {
        let checkbox = tree.try_find(root, checkbox_tag);
        // Missing opta/optb: label-only row always uses the "on" caption.
        let caption_on = checkbox.is_none() || preference_row_is_on(&prefs, row);
        let caption = preference_caption(&assets, row, caption_on);
        commands
            .entity(tree.find(root, label_tag))
            .insert((Text::new(caption.clone()), AccessibleLabel::new(caption)));
        let Some(checkbox) = checkbox else {
            continue;
        };
        let hover = assets.ui_string(0x2743, row as u16 + 0x26);
        let mut entity = commands.entity(checkbox);
        entity
            .insert((PreferenceRow { ui_row: row, slot }, HoverHelpText(hover)))
            .observe(on_preference_checked::<Add, Checked>)
            .observe(on_preference_checked::<Remove, Checked>)
            .remove::<InteractionDisabled>();
        if row == 4 {
            let idle = assets.picture(TACTICAL_BATTLE_OFF_PICTURE);
            let on = assets.picture(TACTICAL_BATTLE_ON_PICTURE);
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

    let music_hover = assets.ui_string(0x2743, 0x27);
    let sound_hover = assets.ui_string(0x2743, 0x26);
    bind_volume_slider(
        &mut commands,
        &mut assets,
        tree.find(root, fourcc!("musi")),
        MUSIC_PICTURE_BASE,
        PreferenceSlot::MusicVolume,
        MUSIC_SLIDER_SCALE,
        prefs.values[PreferenceSlot::MusicVolume],
        music_hover,
    );
    bind_volume_slider(
        &mut commands,
        &mut assets,
        tree.find(root, fourcc!("soun")),
        SOUND_PICTURE_BASE,
        PreferenceSlot::SoundVolume,
        SOUND_SLIDER_SCALE,
        prefs.values[PreferenceSlot::SoundVolume],
        sound_hover,
    );

    commands
        .entity(tree.find(root, fourcc!("okay")))
        .observe(on_preferences_activate)
        .remove::<InteractionDisabled>();

    commands
        .entity(tree.find(root, fourcc!("tpca")))
        .remove::<InteractionDisabled>();
    let yes = tree.find(root, fourcc!("yess"));
    let no = tree.find(root, fourcc!("nooo"));
    commands.entity(yes).insert(Checked);
    commands.entity(no).remove::<Checked>();
    commands
        .entity(tree.find(root, fourcc!("opca")))
        .remove::<InteractionDisabled>();
}

#[allow(clippy::too_many_arguments)]
fn bind_volume_slider(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    slider: Entity,
    picture_base: PictureId,
    slot: PreferenceSlot,
    scale: i16,
    value: i16,
    hover: String,
) {
    let upper = assets.indexed_picture(picture_base);
    let lower = assets.indexed_picture(picture_base.offset(1));
    let image = assets.add_image(upper.to_image(assets.default_dib_palette()));
    let off = assets.get_string(0x2743, 0x3b);
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
            ImageNode::new(image),
            PreferenceSliderVisual { upper, lower },
        ))
        .observe(slider_self_update)
        .observe(on_preference_slider_change)
        .observe(on_sound_slider_released)
        .remove::<InteractionDisabled>();
    let (off_font, off_layout, off_line_height, _) = assets
        .text_style(RetailTextStylePreset::built(14, 1))
        .expect("retail preference slider off text style");
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            width: Val::Percent(100.0),
            height: Val::Percent(100.0),
            ..default()
        },
        Text::new(off),
        off_font,
        off_layout,
        off_line_height,
        TextColor(Color::BLACK),
        Pickable::IGNORE,
        PreferenceSliderOff,
        ChildOf(slider),
    ));
}

fn preference_row_is_on(prefs: &GamePreferences, row: usize) -> bool {
    prefs.values[PREFERENCE_ROWS[row].0] != 0
}

fn preference_caption(assets: &RetailUiAssets, row: usize, is_on: bool) -> String {
    assets.get_string(0x2743, row as u16 * 2 + 0x10 + u16::from(!is_on))
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
        PreferenceSlot::MusicVolume => {
            prefs.values[PreferenceSlot::MusicVolume] = change.value as i16
        }
        PreferenceSlot::SoundVolume if change.is_final => {
            prefs.values[PreferenceSlot::SoundVolume] = change.value as i16
        }
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
    if slider.slot != PreferenceSlot::SoundVolume || !change.is_final {
        return;
    }
    audio.play(&mut commands, SoundId::UI_CLICK);
}

#[allow(clippy::type_complexity)]
fn sync_preference_slider_visuals(
    retail: Res<RetailAssetsResource>,
    mut image_assets: ResMut<Assets<Image>>,
    sliders: Query<
        (
            &SliderValue,
            &SliderRange,
            &PreferenceSliderVisual,
            &ImageNode,
            &Node,
            &Children,
        ),
        (With<PreferenceSlider>, Changed<SliderValue>),
    >,
    mut off_labels: Query<(&PreferenceSliderOff, &mut Visibility)>,
) {
    for (value, range, visual, image_node, node, children) in &sliders {
        let height = match node.height {
            Val::Px(height) => height as i16,
            _ => visual.upper.height as i16,
        };
        let split = slider_split_from_value(value.0 as i16, height, range.end() as i16);
        let fill = slider_fill_height(split);
        let mut picture = visual.upper.clone();
        let top = i32::from(height - fill);
        picture.copy_rect(
            &visual.lower,
            IRect::new(0, top, visual.lower.width as i32, i32::from(height)),
            IVec2::new(0, top),
        );
        let show_off = split < SLIDER_SPLIT_PAD;
        for child in children.iter() {
            if let Ok((_, mut visibility)) = off_labels.get_mut(child) {
                *visibility = if show_off {
                    Visibility::Inherited
                } else {
                    Visibility::Hidden
                };
            }
        }
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
}

fn on_preference_checked<E: EntityEvent, C: Component>(
    event: On<E, C>,
    mut commands: Commands,
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
        .find(|(_, tag)| tag.0 == PREFERENCE_ROWS[row.ui_row].2)
    else {
        return;
    };
    if let Ok(mut text) = texts.get_mut(label) {
        let caption = preference_caption(&assets, row.ui_row, E::is::<Add>());
        text.0.clone_from(&caption);
        commands.entity(label).insert(AccessibleLabel::new(caption));
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
        prefs.values[row.slot] = i16::from(checked);
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
        let slider = app
            .world_mut()
            .spawn(PreferenceSlider {
                slot: PreferenceSlot::SoundVolume,
            })
            .id();
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
