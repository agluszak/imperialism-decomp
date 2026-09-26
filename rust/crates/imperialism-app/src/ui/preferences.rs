use super::generated;
use super::hover_help::{HoverHelpText, bind_hover_help_texts};
use super::query_floater::bind_query_floater_control;
use super::retail::{RetailTree, RetailTwoPicSliderParts, RetailUiAssets};
use crate::media::RetailAudioAssets;
use crate::{AppState, ReturnTo};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{
    Activate, SliderValue, ValueChange, checkbox_self_update, slider_self_update,
};
use enum_map::{Enum, EnumMap};
use imperialism_formats::{SoundId, fourcc};

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

#[derive(Component)]
struct PreferencesView {
    music: Entity,
    sound: Entity,
    /// Dialog-local checkbox draft state; slot captured at bind time.
    checkboxes: Vec<(Entity, PreferenceSlot)>,
}

pub(crate) struct PreferencesPlugin;

impl Plugin for PreferencesPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<GamePreferences>()
            .add_systems(
                OnEnter(AppState::Preferences),
                (spawn_preferences, bind_preferences).chain(),
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
    prefs: Res<GamePreferences>,
    assets: RetailUiAssets,
    slider_parts: Query<&RetailTwoPicSliderParts>,
) {
    let root = *root;
    bind_query_floater_control(&mut commands, root, &tree);
    // HoverHelpBar + recovered curs style come from codegen / Windows deltas.
    bind_hover_help_texts(
        &mut commands,
        root,
        &tree,
        [
            (fourcc!("okay"), assets.ui_string(0x2743, 0x25)),
            (fourcc!("quer"), assets.ui_string(0x2730, 3)),
        ],
    );

    let mut checkboxes = Vec::new();
    for (row, &(slot, checkbox_tag, label_tag)) in PREFERENCE_ROWS.iter().enumerate() {
        let checkbox = tree.try_find(root, checkbox_tag);
        // Missing opta/optb: label-only row always uses the "on" caption.
        let caption_on = checkbox.is_none() || preference_row_is_on(&prefs, row);
        let caption = preference_caption(&assets, row, caption_on);
        let label = tree.find(root, label_tag);
        commands
            .entity(label)
            .insert((Text::new(caption.clone()), AccessibleLabel::new(caption)));
        let Some(checkbox) = checkbox else {
            continue;
        };
        let hover = assets.ui_string(0x2743, row as u16 + 0x26);
        let mut entity = commands.entity(checkbox);
        entity
            .insert(HoverHelpText(hover))
            .observe(checkbox_self_update)
            .observe(
                move |change: On<ValueChange<bool>>,
                      mut commands: Commands,
                      mut texts: Query<&mut Text>,
                      assets: RetailUiAssets| {
                    let caption = preference_caption(&assets, row, change.value);
                    if let Ok(mut text) = texts.get_mut(label) {
                        text.0.clone_from(&caption);
                    }
                    commands.entity(label).insert(AccessibleLabel::new(caption));
                },
            )
            .remove::<InteractionDisabled>();
        if preference_row_is_on(&prefs, row) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
        checkboxes.push((checkbox, slot));
    }

    let [music, sound] = [
        (fourcc!("musi"), 0x27u16, PreferenceSlot::MusicVolume),
        (fourcc!("soun"), 0x26, PreferenceSlot::SoundVolume),
    ]
    .map(|(tag, hover, slot)| {
        let slider_root = tree.find(root, tag);
        let input = slider_parts
            .get(slider_root)
            .expect("bound two-pic slider")
            .input;
        commands.entity(slider_root).remove::<InteractionDisabled>();
        let write_on_drag = matches!(slot, PreferenceSlot::MusicVolume);
        commands
            .entity(input)
            .insert((
                SliderValue(f32::from(prefs.values[slot])),
                HoverHelpText(assets.ui_string(0x2743, hover)),
            ))
            .observe(slider_self_update)
            .remove::<InteractionDisabled>()
            .observe(
                move |change: On<ValueChange<f32>>,
                      mut prefs: ResMut<GamePreferences>,
                      mut commands: Commands,
                      mut audio: RetailAudioAssets| {
                    if write_on_drag || change.is_final {
                        prefs.values[slot] = change.value as i16;
                    }
                    if matches!(slot, PreferenceSlot::SoundVolume) && change.is_final {
                        audio.play(&mut commands, SoundId::UI_CLICK);
                    }
                },
            );
        input
    });
    commands.entity(root).insert(PreferencesView {
        music,
        sound,
        checkboxes,
    });

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

fn preference_row_is_on(prefs: &GamePreferences, row: usize) -> bool {
    prefs.values[PREFERENCE_ROWS[row].0] != 0
}

fn preference_caption(assets: &RetailUiAssets, row: usize, is_on: bool) -> String {
    assets.get_string(0x2743, row as u16 * 2 + 0x10 + u16::from(!is_on))
}

fn on_preferences_activate(
    _activate: On<Activate>,
    views: Query<&PreferencesView>,
    checked: Query<(), With<Checked>>,
    values: Query<&SliderValue>,
    mut prefs: ResMut<GamePreferences>,
    returning: Res<ReturnTo>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let view = views
        .single()
        .expect("Preferences state must contain exactly one PreferencesView");
    // `TGamePreferencesPicture::DoEvent` writes `preferenceValues[row] = IsOn`
    // for each present opta+row checkbox, then overwrites [3]/[2] from the sliders.
    for &(entity, slot) in &view.checkboxes {
        prefs.values[slot] = i16::from(checked.contains(entity));
    }
    prefs.values[PreferenceSlot::MusicVolume] =
        values.get(view.music).expect("bound music slider").0 as i16;
    prefs.values[PreferenceSlot::SoundVolume] =
        values.get(view.sound).expect("bound sound slider").0 as i16;
    next_state.set(returning.0);
}
