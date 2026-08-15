pub(super) use super::GameSession;
pub(super) use super::RetailUiAssets;
pub(super) use super::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
pub(super) use super::fill_brackets;
pub(super) use super::format_currency;
pub(super) use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
pub(super) use super::generated;
pub(super) use super::hover_help::get_string;
pub(super) use super::map_preview::{
    compose_owner_preview_indices, compose_owner_preview_indices_with_fill,
    preview_image_from_indices,
};
pub(super) use super::retail::ModalDialog;
pub(super) use super::retail::{RetailTag, find_child, find_descendant};
pub(super) use super::session::apply_turn_stop;
pub(super) use crate::AppState;
pub(super) use crate::RetailAssetsResource;
pub(super) use bevy::input_focus::tab_navigation::TabGroup;
pub(super) use bevy::math::Rect;
pub(super) use bevy::picking::events::{Click, Pointer};
pub(super) use bevy::prelude::*;
pub(super) use bevy::text::LineHeight;
pub(super) use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
pub(super) use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton, ValueChange};
use enum_map::EnumMap;
pub(super) use imperialism_core::*;
pub(super) use imperialism_formats::*;

mod map;
mod panels;
mod prompts;

use map::*;
use panels::*;
use prompts::*;

pub(super) const PANEL_TOP: f32 = 354.0;
pub(super) const PANEL_OFFSCREEN_TOP: f32 = 800.0;
pub(super) const OFFER_SHEET_LEFT: f32 = 8.0;
pub(super) const OFFER_SHEET_TOP: f32 = 7.0;
pub(super) const OFFER_SHEET_OFFSCREEN: f32 = 2000.0;
pub(super) const MAP_LEFT: f32 = 49.0;
pub(super) const MAP_TOP: f32 = 45.0;
pub(super) const MAP_WIDTH: f32 = 540.0;
pub(super) const MAP_HEIGHT: f32 = 300.0;
pub(super) const MAP_TILE_SCALE: u16 = 5;
pub(super) const MAP_ODD_ROW_OFFSET: u16 = 2;
pub(super) const DIPLOMACY_IDLE_CURSOR: u16 = 0x41b;
pub(super) const DIPLOMACY_CURSOR_BY_ACTION: EnumMap<DiplomacyMapAction, u16> =
    EnumMap::from_array([
        0x41b, 0x41b, 0x408, 0x407, 0x406, 0x404, 0x405, 0x411, 0x415, 0x409, 0x41b, 0x40f, 0x410,
        0x3f3, 0x419, 0x41a,
    ]);
pub(super) const GRANT_AMOUNTS: [i32; 4] = [1_000, 3_000, 5_000, 10_000];
pub(super) const TRADE_POLICY_SCORES: [TradePolicyScore; 7] = [
    TradePolicyScore::new(95),
    TradePolicyScore::new(90),
    TradePolicyScore::new(75),
    TradePolicyScore::new(50),
    TradePolicyScore::new(25),
    TradePolicyScore::new(0),
    TradePolicyScore::BOYCOTT,
];
pub(super) const TREATY_POLICIES: [DiplomacyPolicy; 7] = [
    DiplomacyPolicy::JoinEmpire,
    DiplomacyPolicy::Alliance,
    DiplomacyPolicy::NonAggressionPact,
    DiplomacyPolicy::PeaceTreaty,
    DiplomacyPolicy::DeclareWar,
    DiplomacyPolicy::BuildConsulate,
    DiplomacyPolicy::BuildEmbassy,
];
pub(super) const RELATIONSHIP_NOTCH_PALETTES: [u8; 9] =
    [0x20, 0x2d, 0x30, 0x2e, 0x27, 0x24, 0x26, 0x18, 0x14];
pub(super) const RELATIONSHIP_SELF_PALETTE: u8 = 0x22;
pub(super) const TREATY_LABEL_CENTERS: [(f32, f32); 7] = [
    (74.0, 63.0),
    (74.0, 114.0),
    (267.0, 63.0),
    (218.0, 114.0),
    (325.0, 114.0),
    (434.0, 114.0),
    (386.0, 63.0),
];
pub(super) const INFORMATION_BAND_NAMES: [&str; 5] =
    ["Poor", "Fair", "Good", "Excellent", "Awesome"];
pub(super) const DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS: [FourCc; 7] = [
    fourcc!("nam0"),
    fourcc!("nam1"),
    fourcc!("nam2"),
    fourcc!("nam3"),
    fourcc!("nam4"),
    fourcc!("nam5"),
    fourcc!("nam6"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiplomacyTopic {
    Information,
    Treaties,
    Grants,
    Trade,
    Council,
    Offers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiplomacyMode {
    Information { overlay: u8 },
    Treaties { row: usize },
    Grants { row: usize, recurring: bool },
    Trade { row: usize, colony_boycott: bool },
    Council,
    Offers,
}

impl DiplomacyMode {
    fn from_topic(topic: DiplomacyTopic) -> Self {
        match topic {
            DiplomacyTopic::Information => Self::Information { overlay: 0 },
            DiplomacyTopic::Treaties => Self::Treaties { row: 5 },
            DiplomacyTopic::Grants => Self::Grants {
                row: 0,
                recurring: false,
            },
            DiplomacyTopic::Trade => Self::Trade {
                row: 0,
                colony_boycott: false,
            },
            DiplomacyTopic::Council => Self::Council,
            DiplomacyTopic::Offers => Self::Offers,
        }
    }

    fn topic(self) -> DiplomacyTopic {
        match self {
            Self::Information { .. } => DiplomacyTopic::Information,
            Self::Treaties { .. } => DiplomacyTopic::Treaties,
            Self::Grants { .. } => DiplomacyTopic::Grants,
            Self::Trade { .. } => DiplomacyTopic::Trade,
            Self::Council => DiplomacyTopic::Council,
            Self::Offers => DiplomacyTopic::Offers,
        }
    }
}

#[derive(Component, Clone, Copy)]
pub(super) struct DiplomacyScreen {
    framed_nation: NationId,
    mode: DiplomacyMode,
}

impl DiplomacyScreen {
    fn topic(&self) -> DiplomacyTopic {
        self.mode.topic()
    }

    fn interaction_mode(&self) -> i32 {
        match self.mode {
            DiplomacyMode::Information { overlay } => i32::from(overlay),
            DiplomacyMode::Treaties { .. } => 4,
            DiplomacyMode::Grants { .. } => 1,
            DiplomacyMode::Trade { .. } => 2,
            DiplomacyMode::Council => 5,
            DiplomacyMode::Offers => 0,
        }
    }

    fn map_action(&self) -> DiplomacyMapAction {
        match self.mode {
            DiplomacyMode::Information { .. } | DiplomacyMode::Offers => {
                DiplomacyMapAction::InspectNation
            }
            DiplomacyMode::Treaties { row } => match row {
                0 => DiplomacyMapAction::JoinEmpire,
                1 => DiplomacyMapAction::Alliance,
                2 => DiplomacyMapAction::NonAggressionPact,
                3 => DiplomacyMapAction::PeaceTreaty,
                4 => DiplomacyMapAction::DeclareWar,
                5 => DiplomacyMapAction::BuildConsulate,
                6 => DiplomacyMapAction::BuildEmbassy,
                _ => DiplomacyMapAction::InspectNation,
            },
            DiplomacyMode::Grants {
                recurring: true, ..
            } => DiplomacyMapAction::RecurringGrant,
            DiplomacyMode::Grants {
                recurring: false, ..
            } => DiplomacyMapAction::OneTimeGrant,
            DiplomacyMode::Trade {
                colony_boycott: true,
                ..
            } => DiplomacyMapAction::LinkTradePolicy,
            DiplomacyMode::Trade { row: 6, .. } => DiplomacyMapAction::Boycott,
            DiplomacyMode::Trade { .. } => DiplomacyMapAction::TradeSubsidy,
            DiplomacyMode::Council => DiplomacyMapAction::None,
        }
    }

    fn cursor_action(&self) -> DiplomacyMapAction {
        if matches!(self.mode, DiplomacyMode::Council) {
            DiplomacyMapAction::None
        } else {
            self.map_action()
        }
    }

    fn cursor_row(&self) -> usize {
        match self.cursor_action() {
            DiplomacyMapAction::TradeSubsidy => match self.mode {
                DiplomacyMode::Trade { row, .. } => row,
                _ => 0,
            },
            DiplomacyMapAction::OneTimeGrant | DiplomacyMapAction::RecurringGrant => {
                match self.mode {
                    DiplomacyMode::Grants { row, .. } => row,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }
}

#[derive(Component, Clone, Copy)]
pub(super) struct DiplomacyPanel(DiplomacyTopic);

#[derive(Component, Clone, Copy)]
pub(super) enum DiplomacyAction {
    Topic(DiplomacyTopic),
    Grant { row: usize, recurring: bool },
    Trade(usize),
    Treaty(usize),
    Overlay(u8),
    ColonyBoycott,
    AcceptOffer,
    RejectOffer,
}

#[derive(Component)]
pub(super) struct DiplomacyMapPicture;

#[derive(Component)]
pub(super) struct DiplomacyOfferSheet;

#[derive(Component)]
pub(super) struct DiplomacyOfferWait;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiplomacyNationIconKind {
    Compatibility,
    Order,
    Boycott,
}

#[derive(Component, Clone, Copy)]
pub(super) struct DiplomacyNationIcon {
    nation: NationId,
    kind: DiplomacyNationIconKind,
}

#[derive(Clone, Copy)]
pub(super) enum DiplomacyInfoField {
    Name,
    Label(u8),
    Value(u8),
}

#[derive(Component, Clone, Copy)]
pub(super) enum DiplomacyText {
    Treasury,
    Offer,
    Info(DiplomacyInfoField),
    GrantTotal,
    Council(u8),
    NationName(NationId),
    MapKeyMajorName(MajorNationId),
}

#[derive(Component, Clone)]
pub(super) struct DiplomacyMapKey {
    owner: Handle<Image>,
    relationship_notch: Handle<Image>,
    trade: Handle<Image>,
    relationship_type: Handle<Image>,
}

#[derive(Component)]
pub(super) struct DiplomacyNotice(PlayerDiplomacyRejection);

#[derive(Clone, Copy, Debug, Event)]
pub(super) struct OpenDiplomacyRejectionNotice {
    rejection: PlayerDiplomacyRejection,
}

#[derive(Clone, Copy, Debug, Event)]
pub(super) struct OpenDiplomacyEntanglementNotice {
    target: NationId,
    policy: DiplomacyPolicy,
}

#[derive(Component, Clone, Copy)]
pub(super) struct DiplomacyEntanglementNotice {
    target: NationId,
    policy: DiplomacyPolicy,
}

#[derive(Clone)]
pub(super) struct DiplomacyTextStyles {
    title_font: TextFont,
    title_layout: TextLayout,
    title_line_height: LineHeight,
    row_font: TextFont,
    row_layout: TextLayout,
    row_line_height: LineHeight,
    map_font: TextFont,
    map_layout: TextLayout,
    map_line_height: LineHeight,
    key_font: TextFont,
    key_layout: TextLayout,
    key_line_height: LineHeight,
    foreground: Color,
    shadow: Color,
}

#[derive(Clone)]
pub(super) struct DiplomacyBracketPictures {
    information: Handle<Image>,
    council: Handle<Image>,
    treaties: Handle<Image>,
    grants: Handle<Image>,
    trade: Handle<Image>,
}

#[derive(Component, Clone)]
pub(super) struct DiplomacyTopicBracket {
    left: bool,
    pictures: DiplomacyBracketPictures,
}

#[derive(Component, Clone, Copy)]
pub(super) enum DiplomacyEntanglementAction {
    Confirm,
    Dismiss,
}

pub(crate) struct DiplomacyPlugin;

impl Plugin for DiplomacyPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Diplomacy),
            (enter_diplomacy_screen, bind_diplomacy_screen).chain(),
        )
        .add_systems(
            Update,
            (
                bind_diplomacy_notice,
                bind_diplomacy_entanglement_notice,
                sync_diplomacy_offer_sheet,
                sync_diplomacy_controls,
                project_diplomacy_text,
                sync_diplomacy_information,
                render_diplomacy_map,
                sync_diplomacy_map_cursor,
            )
                .chain()
                .run_if(in_state(AppState::Diplomacy)),
        )
        .add_systems(OnExit(AppState::Diplomacy), reset_diplomacy_cursor)
        .add_observer(on_diplomacy_activate.run_if(in_state(AppState::Diplomacy)))
        .add_observer(on_diplomacy_radio_selected.run_if(in_state(AppState::Diplomacy)))
        .add_observer(on_diplomacy_offer_activate.run_if(in_state(AppState::Diplomacy)))
        .add_observer(on_diplomacy_map_click.run_if(in_state(AppState::Diplomacy)))
        .add_observer(open_diplomacy_rejection_notice.run_if(in_state(AppState::Diplomacy)))
        .add_observer(open_diplomacy_entanglement_notice.run_if(in_state(AppState::Diplomacy)));
    }
}

fn enter_diplomacy_screen(mut commands: Commands, session: Res<GameSession>) {
    let root = commands.spawn_scene(generated::diplo_2008()).id();
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let mut screen = DiplomacyScreen {
        framed_nation: source.nation(),
        mode: DiplomacyMode::Information { overlay: 0 },
    };
    if let Some(prompt) = session.game.current_diplomacy_offer() {
        pose_diplomacy_offer(&mut screen, prompt);
    } else if let Some(prompt) = session.game.current_diplomacy_war_join() {
        pose_diplomacy_war_join(&mut screen, prompt);
    }
    commands
        .entity(root)
        .insert((screen, DespawnOnExit(AppState::Diplomacy)));
}

fn bind_diplomacy_screen(
    mut commands: Commands,
    root: Single<Entity, Added<DiplomacyScreen>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_game_status_display(&mut commands, &mut assets, *root, &children, &tags);
    let pictures = DiplomacyBracketPictures {
        information: assets
            .picture(PictureId::new(5001))
            .expect("retail diplomacy information bracket must load"),
        council: assets
            .picture(PictureId::new(5002))
            .expect("retail diplomacy council bracket must load"),
        treaties: assets
            .picture(PictureId::new(5003))
            .expect("retail diplomacy treaties bracket must load"),
        grants: assets
            .picture(PictureId::new(5004))
            .expect("retail diplomacy grants bracket must load"),
        trade: assets
            .picture(PictureId::new(5005))
            .expect("retail diplomacy trade bracket must load"),
    };
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 0,
        })
        .expect("retail diplomacy title text style");
    let (row_font, row_layout, row_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy row text style");
    let (map_font, map_layout, map_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail diplomacy map label style");
    let (key_font, key_layout, key_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail diplomacy map-key text style");
    let styles = DiplomacyTextStyles {
        title_font,
        title_layout,
        title_line_height,
        row_font,
        row_layout,
        row_line_height,
        map_font,
        map_layout,
        map_line_height,
        key_font,
        key_layout,
        key_line_height,
        foreground: assets.palette_color(0x13),
        shadow: assets.palette_color(0xd2),
    };
    let icon_picture = PictureId::new(802);
    let icon_atlas = assets
        .picture(icon_picture)
        .expect("retail diplomacy icon atlas must load");
    let transparent_rgb = assets.default_dib_palette()[0x10].to_array();
    assets
        .with_picture_image_mut(icon_picture, |image| {
            apply_diplomacy_atlas_transparency(image, transparent_rgb);
        })
        .expect("retail diplomacy icon atlas transparency must apply");
    bind_diplomacy_controls(
        &mut commands,
        *root,
        &children,
        &tags,
        pictures,
        styles,
        icon_atlas,
        &mut assets,
        &session,
    );
}

fn on_diplomacy_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
    session: Res<GameSession>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy control has one open Diplomacy screen");
    match *action {
        DiplomacyAction::Topic(topic) => {
            if session.game.current_diplomacy_offer().is_some()
                || session.game.current_diplomacy_war_join().is_some()
            {
                return;
            }
            if screen.topic() == topic {
                return;
            }
            screen.mode = DiplomacyMode::from_topic(topic);
            screen.framed_nation = MajorNationId::from_nation(session.game.turn().active_nation)
                .expect("Diplomacy screen requires an active major nation")
                .nation();
        }
        other => apply_diplomacy_radio_action(other, &mut screen),
    }
}

fn on_diplomacy_radio_selected(
    change: On<ValueChange<bool>>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
) {
    if !change.value {
        return;
    }
    let Ok(action) = actions.get(change.source) else {
        return;
    };
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy control has one open Diplomacy screen");
    apply_diplomacy_radio_action(*action, &mut screen);
}

fn apply_diplomacy_radio_action(action: DiplomacyAction, screen: &mut DiplomacyScreen) {
    match action {
        DiplomacyAction::Grant { row, recurring } => {
            if matches!(screen.mode, DiplomacyMode::Grants { .. }) {
                screen.mode = DiplomacyMode::Grants { row, recurring };
            }
        }
        DiplomacyAction::Trade(row) => {
            if matches!(screen.mode, DiplomacyMode::Trade { .. }) {
                screen.mode = DiplomacyMode::Trade {
                    row,
                    colony_boycott: false,
                };
            }
        }
        DiplomacyAction::Treaty(row) => {
            if matches!(screen.mode, DiplomacyMode::Treaties { .. }) {
                screen.mode = DiplomacyMode::Treaties { row };
            }
        }
        DiplomacyAction::Overlay(overlay) => {
            if matches!(screen.mode, DiplomacyMode::Information { .. }) {
                screen.mode = DiplomacyMode::Information { overlay };
            }
        }
        DiplomacyAction::ColonyBoycott => {
            if let DiplomacyMode::Trade { row, .. } = screen.mode {
                screen.mode = DiplomacyMode::Trade {
                    row,
                    colony_boycott: true,
                };
            }
        }
        DiplomacyAction::Topic(_) | DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer => {
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn treaty_radio_value_change_selects_that_pact() {
        let mut app = App::new();
        app.add_observer(on_diplomacy_radio_selected);
        app.world_mut().spawn(DiplomacyScreen {
            framed_nation: NationId::new(0),
            mode: DiplomacyMode::Treaties { row: 5 },
        });
        let radio = app.world_mut().spawn(DiplomacyAction::Treaty(2)).id();
        app.world_mut().commands().trigger(ValueChange {
            source: radio,
            value: true,
            is_final: true,
        });
        app.world_mut().flush();

        let mut screens = app.world_mut().query::<&DiplomacyScreen>();
        let screen = screens.single(app.world()).unwrap();
        assert_eq!(screen.mode, DiplomacyMode::Treaties { row: 2 });
        assert_eq!(screen.map_action(), DiplomacyMapAction::NonAggressionPact);
    }
}
