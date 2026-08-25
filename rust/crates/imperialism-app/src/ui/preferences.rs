use super::generated;
use super::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts, get_string,
    ui_string,
};
use super::query_floater::bind_query_floater_control;
use super::retail::{RetailPictureSwap, RetailUiAssets};
use super::retail_raster::IndexedRasterExt;
use super::retail_raster_text::RetailRasterTextPainter;
use crate::media::RetailAudioAssets;
use crate::{AppState, RetailAssetsResource, RetailFonts, ReturnTo};
use bevy::prelude::*;
use bevy::reflect::Is;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{
    Activate, Button, Checkbox, Slider, SliderOrientation, SliderPrecision, SliderRange,
    SliderValue, TrackClick, ValueChange, slider_self_update,
};
use enum_map::{Enum, EnumMap};
use imperialism_formats::{PictureId, RetailTextStylePreset, SoundId};

/// `g_anGamePreferenceIndexByRow` and the controls for each displayed row.
const PREFERENCE_ROW_SLOTS: [PreferenceSlot; 5] = [
    PreferenceSlot::MusicVolume,
    PreferenceSlot::SoundVolume,
    PreferenceSlot::TurnAlerts,
    PreferenceSlot::Unknown10,
    PreferenceSlot::TacticalBattle,
];
const SLIDER_SPLIT_PAD: i16 = 0x0c;
const MUSIC_SLIDER_SCALE: i16 = 0xff;
const SOUND_SLIDER_SCALE: i16 = 100;
const MUSIC_PICTURE_BASE: i16 = 0x1036;
const SOUND_PICTURE_BASE: i16 = 0x1038;
const TACTICAL_BATTLE_ON_PICTURE: i16 = 4158;
const TACTICAL_BATTLE_OFF_PICTURE: i16 = 4160;

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

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct PreferenceLabel {
    ui_row: usize,
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
    off: String,
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
    let ui = generated::spawn_linger_4150(&mut commands);
    commands
        .entity(ui.root)
        .insert((PreferencesRoot, ui, DespawnOnExit(AppState::Preferences)));
}

fn bind_preferences(
    mut commands: Commands,
    ui: Single<&generated::Linger4150, Added<PreferencesRoot>>,
    mut nodes: Query<&mut Node>,
    prefs: Res<GamePreferences>,
    mut assets: RetailUiAssets,
) {
    let ui = **ui;
    bind_query_floater_control(&mut commands, ui.quer);
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        ui.curs,
        &mut nodes.get_mut(ui.curs).expect("preferences curs has Node"),
        HoverHelpBarStyle::PREFERENCES,
    );
    bind_hover_help_texts(
        &mut commands,
        [
            (ui.okay, ui_string(&assets, 0x2743, 0x25)),
            (ui.quer, ui_string(&assets, 0x2730, 3)),
        ],
    );

    let rows = [
        (PREFERENCE_ROW_SLOTS[0], None, ui.txta),
        (PREFERENCE_ROW_SLOTS[1], None, ui.txtb),
        (PREFERENCE_ROW_SLOTS[2], Some(ui.optc), ui.txtc),
        (PREFERENCE_ROW_SLOTS[3], Some(ui.optd), ui.txtd),
        (PREFERENCE_ROW_SLOTS[4], Some(ui.opte), ui.txte),
    ];
    for (row, (slot, checkbox, label)) in rows.into_iter().enumerate() {
        // Missing opta/optb: label-only row always uses the "on" caption.
        let caption_on = checkbox.is_none() || preference_row_is_on(&prefs, row);
        let caption = preference_caption(&assets, row, caption_on);
        commands.entity(label).insert((
            PreferenceLabel { ui_row: row },
            Text::new(caption.clone()),
            AccessibleLabel::new(caption),
        ));
        let Some(checkbox) = checkbox else {
            continue;
        };
        let hover = ui_string(&assets, 0x2743, row as i16 + 0x26);
        let mut entity = commands.entity(checkbox);
        entity
            .insert((PreferenceRow { ui_row: row, slot }, HoverHelpText(hover)))
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
        ui.musi,
        MUSIC_PICTURE_BASE,
        PreferenceSlot::MusicVolume,
        MUSIC_SLIDER_SCALE,
        prefs.values[PreferenceSlot::MusicVolume],
        music_hover,
    );
    bind_volume_slider(
        &mut commands,
        &mut assets,
        ui.soun,
        SOUND_PICTURE_BASE,
        PreferenceSlot::SoundVolume,
        SOUND_SLIDER_SCALE,
        prefs.values[PreferenceSlot::SoundVolume],
        sound_hover,
    );

    commands
        .entity(ui.okay)
        .observe(on_preferences_activate)
        .remove::<InteractionDisabled>();

    commands.entity(ui.tpca).remove::<InteractionDisabled>();
    commands.entity(ui.yess).insert(Checked);
    commands.entity(ui.nooo).remove::<Checked>();
    commands.entity(ui.opca).remove::<InteractionDisabled>();
}

#[allow(clippy::too_many_arguments)]
fn bind_volume_slider(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    slider: Entity,
    picture_base: i16,
    slot: PreferenceSlot,
    scale: i16,
    value: i16,
    hover: String,
) {
    let upper = assets
        .indexed_picture(PictureId::new(picture_base))
        .expect("preference slider upper picture");
    let lower = assets
        .indexed_picture(PictureId::new(picture_base + 1))
        .expect("preference slider lower picture");
    let image = assets.add_image(upper.to_image(assets.default_dib_palette()));
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
            PreferenceSliderVisual {
                upper,
                lower,
                off: get_string(assets, 0x2743, 0x3b),
            },
        ))
        .observe(slider_self_update)
        .observe(on_preference_slider_change)
        .observe(on_sound_slider_released)
        .remove::<InteractionDisabled>();
}

fn preference_row_is_on(prefs: &GamePreferences, row: usize) -> bool {
    prefs.values[PREFERENCE_ROW_SLOTS[row]] != 0
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
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    sliders: Query<
        (
            &SliderValue,
            &SliderRange,
            &PreferenceSliderVisual,
            &ImageNode,
            &Node,
        ),
        (With<PreferenceSlider>, Changed<SliderValue>),
    >,
) {
    let mut text = RetailRasterTextPainter::from_preset(
        &fonts,
        &font_assets,
        RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 1,
        },
    )
    .expect("retail preference slider text style");
    for (value, range, visual, image_node, node) in &sliders {
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
        if split < SLIDER_SPLIT_PAD {
            let center = visual.upper.width as i32 / 2;
            let baseline = i32::from(height / 2 + 4);
            text.draw_center(&mut picture, center, baseline, &visual.off, 0x28);
            text.draw_center(&mut picture, center + 1, baseline + 1, &visual.off, 0);
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
    labels: Query<(Entity, &PreferenceLabel)>,
    assets: RetailUiAssets,
) {
    let Ok(row) = rows.get(event.event_target()) else {
        return;
    };
    let Some((label, _)) = labels.iter().find(|(_, label)| label.ui_row == row.ui_row) else {
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
