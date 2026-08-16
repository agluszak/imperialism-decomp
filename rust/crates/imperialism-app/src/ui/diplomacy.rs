use super::GameSession;
use super::RetailUiAssets;
use super::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::hover_help::get_string;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::random_setup_map::{
    compose_owner_preview_indices, compose_owner_preview_indices_with_fill,
    preview_image_from_indices,
};
use super::retail::{ModalDialog, RetailTree, ancestor_with};
use super::session::apply_turn_stop;
use crate::AppState;
use crate::RetailAssetsResource;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton, ValueChange};
use enum_map::EnumMap;
use imperialism_core::*;
use imperialism_formats::*;

const PANEL_TOP: f32 = 354.0;
const PANEL_OFFSCREEN_TOP: f32 = 800.0;
const OFFER_SHEET_LEFT: f32 = 8.0;
const OFFER_SHEET_TOP: f32 = 7.0;
const OFFER_SHEET_OFFSCREEN: f32 = 2000.0;
const MAP_LEFT: f32 = 49.0;
const MAP_TOP: f32 = 45.0;
const MAP_WIDTH: f32 = 540.0;
const MAP_HEIGHT: f32 = 300.0;
const MAP_TILE_SCALE: u16 = 5;
const MAP_ODD_ROW_OFFSET: u16 = 2;
const DIPLOMACY_IDLE_CURSOR: u16 = 0x41b;
const DIPLOMACY_CURSOR_BY_ACTION: EnumMap<DiplomacyMapAction, u16> = EnumMap::from_array([
    0x41b, 0x41b, 0x408, 0x407, 0x406, 0x404, 0x405, 0x411, 0x415, 0x409, 0x41b, 0x40f, 0x410,
    0x3f3, 0x419, 0x41a,
]);
const GRANT_AMOUNTS: [i32; 4] = [1_000, 3_000, 5_000, 10_000];
const TRADE_POLICY_SCORES: [TradePolicyScore; 7] = [
    TradePolicyScore::new(95),
    TradePolicyScore::new(90),
    TradePolicyScore::new(75),
    TradePolicyScore::new(50),
    TradePolicyScore::new(25),
    TradePolicyScore::new(0),
    TradePolicyScore::BOYCOTT,
];
const TREATY_POLICIES: [DiplomacyPolicy; 7] = [
    DiplomacyPolicy::JoinEmpire,
    DiplomacyPolicy::Alliance,
    DiplomacyPolicy::NonAggressionPact,
    DiplomacyPolicy::PeaceTreaty,
    DiplomacyPolicy::DeclareWar,
    DiplomacyPolicy::BuildConsulate,
    DiplomacyPolicy::BuildEmbassy,
];
const RELATIONSHIP_NOTCH_PALETTES: [u8; 9] = [0x20, 0x2d, 0x30, 0x2e, 0x27, 0x24, 0x26, 0x18, 0x14];
const RELATIONSHIP_SELF_PALETTE: u8 = 0x22;
const TREATY_LABEL_CENTERS: [(f32, f32); 7] = [
    (74.0, 63.0),
    (74.0, 114.0),
    (267.0, 63.0),
    (218.0, 114.0),
    (325.0, 114.0),
    (434.0, 114.0),
    (386.0, 63.0),
];
const INFORMATION_BAND_NAMES: [&str; 5] = ["Poor", "Fair", "Good", "Excellent", "Awesome"];
const DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS: [FourCc; 7] = [
    fourcc!("nam0"),
    fourcc!("nam1"),
    fourcc!("nam2"),
    fourcc!("nam3"),
    fourcc!("nam4"),
    fourcc!("nam5"),
    fourcc!("nam6"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyTopic {
    Information,
    Treaties,
    Grants,
    Trade,
    Council,
    Offers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyMode {
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
struct DiplomacyScreen {
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
struct DiplomacyPanel(DiplomacyTopic);

#[derive(Component, Clone, Copy)]
enum DiplomacyAction {
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
struct DiplomacyMapPicture;

#[derive(Component)]
struct DiplomacyOfferSheet;

#[derive(Component)]
struct DiplomacyOfferWait;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyNationIconKind {
    Compatibility,
    Order,
    Boycott,
}

#[derive(Component, Clone, Copy)]
struct DiplomacyNationIcon {
    nation: NationId,
    kind: DiplomacyNationIconKind,
}

#[derive(Clone, Copy)]
enum DiplomacyInfoField {
    Name,
    Label(u8),
    Value(u8),
}

#[derive(Component, Clone, Copy)]
enum DiplomacyText {
    Treasury,
    Offer,
    Info(DiplomacyInfoField),
    GrantTotal,
    Council(u8),
    NationName(NationId),
    MapKeyMajorName(MajorNationId),
}

#[derive(Component, Clone)]
struct DiplomacyMapKey {
    owner: Handle<Image>,
    relationship_notch: Handle<Image>,
    trade: Handle<Image>,
    relationship_type: Handle<Image>,
}

#[derive(Component)]
struct DiplomacyNotice(PlayerDiplomacyRejection);

#[derive(Clone, Copy, Debug, Event)]
struct OpenDiplomacyRejectionNotice {
    rejection: PlayerDiplomacyRejection,
}

#[derive(Clone, Copy, Debug, Event)]
struct OpenDiplomacyEntanglementNotice {
    target: NationId,
    policy: DiplomacyPolicy,
}

#[derive(Component, Clone, Copy)]
struct DiplomacyEntanglementNotice {
    target: NationId,
    policy: DiplomacyPolicy,
}

#[derive(Clone)]
struct DiplomacyTextStyles {
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
struct DiplomacyBracketPictures {
    information: Handle<Image>,
    council: Handle<Image>,
    treaties: Handle<Image>,
    grants: Handle<Image>,
    trade: Handle<Image>,
}

#[derive(Component, Clone)]
struct DiplomacyTopicBracket {
    left: bool,
    pictures: DiplomacyBracketPictures,
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
        .add_observer(open_diplomacy_rejection_notice.run_if(in_state(AppState::Diplomacy)))
        .add_observer(open_diplomacy_entanglement_notice.run_if(in_state(AppState::Diplomacy)));
    }
}

fn enter_diplomacy_screen(mut commands: Commands, session: Res<GameSession>) {
    let root = commands.spawn_scene(generated::diplo_2008()).id();
    let source = session.active_major_nation();
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
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
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
    let transparent_rgb = assets.default_dib_palette()[0x10].to_array();
    let icon_atlas = assets
        .transformed_picture(icon_picture, |image| {
            apply_diplomacy_atlas_transparency(image, transparent_rgb);
        })
        .expect("retail diplomacy icon atlas transparency must apply");
    bind_diplomacy_controls(
        &mut commands,
        *root,
        &tree,
        pictures,
        styles,
        icon_atlas,
        &mut assets,
        &session,
    );
}

#[allow(clippy::too_many_arguments)]
fn bind_diplomacy_controls(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    pictures: DiplomacyBracketPictures,
    styles: DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
    assets: &mut RetailUiAssets,
    session: &GameSession,
) -> Entity {
    let posing = session.game.current_diplomacy_offer().is_some()
        || session.game.current_diplomacy_war_join().is_some();
    if !posing {
        bind_native_game_screen_nav(commands, root, tree, fourcc!("topB"), Some(fourcc!("too3")));
    }
    let top = tree.find(root, fourcc!("topB"));
    let selected = tree.find(top, fourcc!("dipl"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));

    let main = tree.find(root, fourcc!("main"));
    let view = tree.view(main);
    let information = view.child(fourcc!("info"));
    let treaties = view.child(fourcc!("trty"));
    let grants = view.child(fourcc!("gran"));
    let trade = view.child(fourcc!("trad"));
    let council = view.child(fourcc!("coun"));
    let offers = view.child(fourcc!("offr"));
    let trade_cluster = tree.find(trade, fourcc!("clus"));

    for topic in [
        DiplomacyTopic::Information,
        DiplomacyTopic::Treaties,
        DiplomacyTopic::Grants,
        DiplomacyTopic::Trade,
        DiplomacyTopic::Council,
        DiplomacyTopic::Offers,
    ] {
        let panel = match topic {
            DiplomacyTopic::Information => information,
            DiplomacyTopic::Treaties => treaties,
            DiplomacyTopic::Grants => grants,
            DiplomacyTopic::Trade => trade,
            DiplomacyTopic::Council => council,
            DiplomacyTopic::Offers => offers,
        };
        commands.entity(panel).insert(DiplomacyPanel(topic));
    }

    for (tag, topic) in [
        (fourcc!("inft"), DiplomacyTopic::Information),
        (fourcc!("trtt"), DiplomacyTopic::Treaties),
        (fourcc!("grat"), DiplomacyTopic::Grants),
        (fourcc!("trat"), DiplomacyTopic::Trade),
        (fourcc!("cout"), DiplomacyTopic::Council),
    ] {
        let control = tree.find(root, tag);
        let mut entity = commands.entity(control);
        entity
            .insert(DiplomacyAction::Topic(topic))
            .observe(on_diplomacy_activate);
        if posing {
            entity.insert(InteractionDisabled);
        } else {
            entity.remove::<InteractionDisabled>();
        }
    }
    for (index, tag) in [
        fourcc!("doc0"),
        fourcc!("doc1"),
        fourcc!("doc2"),
        fourcc!("doc3"),
        fourcc!("doc4"),
        fourcc!("doc5"),
        fourcc!("doc6"),
        fourcc!("doc7"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert(DiplomacyAction::Grant {
                row: index / 2,
                recurring: index % 2 != 0,
            })
            .observe(on_diplomacy_radio_selected);
    }
    for (index, tag) in [
        fourcc!("traa"),
        fourcc!("trab"),
        fourcc!("trac"),
        fourcc!("trad"),
        fourcc!("trae"),
        fourcc!("traf"),
        fourcc!("trag"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = tree.find(trade_cluster, tag);
        commands
            .entity(control)
            .insert(DiplomacyAction::Trade(index))
            .observe(on_diplomacy_radio_selected);
    }
    for (index, tag) in [
        fourcc!("ovr0"),
        fourcc!("ovr1"),
        fourcc!("ovr2"),
        fourcc!("ovr4"),
    ]
    .into_iter()
    .enumerate()
    {
        let overlay = [0_u8, 1, 2, 4][index];
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert(DiplomacyAction::Overlay(overlay))
            .remove::<InteractionDisabled>()
            .observe(on_diplomacy_radio_selected);
    }
    for (index, tag) in [
        fourcc!("scr0"),
        fourcc!("scr1"),
        fourcc!("scr2"),
        fourcc!("scr3"),
        fourcc!("scr4"),
        fourcc!("scr5"),
        fourcc!("scr6"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert(DiplomacyAction::Treaty(index))
            .remove::<InteractionDisabled>()
            .observe(on_diplomacy_radio_selected);
    }
    commands
        .entity(tree.find(trade_cluster, fourcc!("link")))
        .insert(DiplomacyAction::ColonyBoycott)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_radio_selected);
    for (tag, action) in [
        (fourcc!("acce"), DiplomacyAction::AcceptOffer),
        (fourcc!("reje"), DiplomacyAction::RejectOffer),
    ] {
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert((action, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_diplomacy_offer_activate);
    }
    for (tag, checked) in [
        (fourcc!("ovr0"), true),
        (fourcc!("ovr1"), false),
        (fourcc!("ovr2"), false),
        (fourcc!("ovr4"), false),
        (fourcc!("scr0"), false),
        (fourcc!("scr1"), false),
        (fourcc!("scr2"), false),
        (fourcc!("scr3"), false),
        (fourcc!("scr4"), false),
        (fourcc!("scr5"), true),
        (fourcc!("scr6"), false),
    ] {
        let control = tree.find(root, tag);
        if checked {
            commands.entity(control).insert(Checked);
        } else {
            commands.entity(control).remove::<Checked>();
        }
    }
    commands
        .entity(tree.find(trade_cluster, fourcc!("link")))
        .remove::<Checked>();

    let map = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(MAP_LEFT),
                top: Val::Px(MAP_TOP),
                width: Val::Px(MAP_WIDTH),
                height: Val::Px(MAP_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::NONE),
            UiButton,
            RelativeCursorPosition::default(),
            DiplomacyMapPicture,
            ZIndex(1),
            ChildOf(main),
        ))
        .observe(on_diplomacy_map_click)
        .id();
    spawn_diplomacy_map_labels(commands, map, &styles, icon_atlas);
    spawn_diplomacy_panel_text(
        commands,
        root,
        tree,
        information,
        treaties,
        grants,
        trade,
        council,
        &styles,
        assets,
    );

    let shee = tree.find(root, fourcc!("shee"));
    let wait = tree.find(root, fourcc!("wait"));
    let prop = tree.find(root, fourcc!("prop"));
    commands.entity(shee).insert(DiplomacyOfferSheet);
    commands.entity(wait).insert(DiplomacyOfferWait);
    let offer_layout = styles.row_layout.with_justify(Justify::Center);
    let entity = spawn_shadowed_text(
        commands,
        prop,
        "",
        0.0,
        12.0,
        291.0,
        &styles.row_font,
        &offer_layout,
        styles.row_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands.entity(entity).insert(DiplomacyText::Offer);

    let treasury = tree.find(root, fourcc!("trea"));
    commands.entity(treasury).insert(DiplomacyText::Treasury);
    let left = tree.find(root, fourcc!("ltab"));
    commands.entity(left).insert(DiplomacyTopicBracket {
        left: true,
        pictures: pictures.clone(),
    });
    let right = tree.find(root, fourcc!("rtab"));
    commands.entity(right).insert(DiplomacyTopicBracket {
        left: false,
        pictures,
    });
    map
}

fn spawn_diplomacy_map_labels(
    commands: &mut Commands,
    map: Entity,
    styles: &DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
) {
    for nation in NationId::all() {
        let entity = spawn_shadowed_text(
            commands,
            map,
            "",
            -45.0,
            -20.0,
            90.0,
            &styles.map_font,
            &styles.map_layout,
            styles.map_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::NationName(nation), Visibility::Hidden));
        for kind in [
            DiplomacyNationIconKind::Compatibility,
            DiplomacyNationIconKind::Order,
            DiplomacyNationIconKind::Boycott,
        ] {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    width: Val::Px(16.0),
                    height: Val::Px(16.0),
                    ..default()
                },
                ImageNode::new(icon_atlas.clone()),
                Visibility::Hidden,
                Pickable::IGNORE,
                ChildOf(map),
                DiplomacyNationIcon { nation, kind },
            ));
        }
    }
}

fn apply_diplomacy_atlas_transparency(image: &mut Image, transparent_rgb: [u8; 3]) {
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    for pixel in pixels.chunks_exact_mut(4) {
        if pixel[..3] == transparent_rgb {
            pixel[3] = 0;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_diplomacy_panel_text(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    information: Entity,
    treaties: Entity,
    grants: Entity,
    trade: Entity,
    council: Entity,
    styles: &DiplomacyTextStyles,
    assets: &mut RetailUiAssets,
) {
    spawn_shadowed_text(
        commands,
        information,
        "Information:",
        15.0,
        13.0,
        95.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    let entity = spawn_shadowed_text(
        commands,
        information,
        "",
        110.0,
        13.0,
        120.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands
        .entity(entity)
        .insert(DiplomacyText::Info(DiplomacyInfoField::Name));
    for (row, top) in [54.0, 71.0, 88.0].into_iter().enumerate() {
        let entity = spawn_shadowed_text(
            commands,
            information,
            "",
            15.0,
            top,
            95.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert(DiplomacyText::Info(DiplomacyInfoField::Label(row as u8)));
        let entity = spawn_shadowed_text(
            commands,
            information,
            "",
            110.0,
            top,
            120.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert(DiplomacyText::Info(DiplomacyInfoField::Value(row as u8)));
    }

    let map_key = tree.find(information, fourcc!("mkey"));
    commands.entity(map_key).insert(DiplomacyMapKey {
        owner: assets
            .picture(PictureId::new(0x1393))
            .expect("retail diplomacy owner map key must load"),
        relationship_type: assets
            .picture(PictureId::new(0x1395))
            .expect("retail diplomacy relationship-type map key must load"),
        relationship_notch: assets
            .picture(PictureId::new(0x1396))
            .expect("retail diplomacy relationship-notch map key must load"),
        trade: assets
            .picture(PictureId::new(0x1397))
            .expect("retail diplomacy trade map key must load"),
    });
    let key_label_layout = styles.key_layout.with_justify(Justify::Left);
    spawn_shadowed_text(
        commands,
        map_key,
        "Map Key",
        106.0,
        12.0,
        100.0,
        &styles.key_font,
        &key_label_layout,
        styles.key_line_height,
        styles.foreground,
        styles.shadow,
    );
    spawn_shadowed_text(
        commands,
        map_key,
        "Minor Nation",
        153.0,
        108.0,
        100.0,
        &styles.key_font,
        &key_label_layout,
        styles.key_line_height,
        styles.foreground,
        styles.shadow,
    );
    for (major, tag) in MajorNationId::all().zip(DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS) {
        commands
            .entity(tree.find(root, tag))
            .insert((DiplomacyText::MapKeyMajorName(major), Visibility::Inherited));
    }

    for (text, left, top, title) in [
        ("Foreign Grants", 15.0, 13.0, true),
        ("Relationship:", 174.0, 13.0, false),
        ("Bad", 276.0, 30.0, false),
        ("Good", 440.0, 30.0, false),
        ("$1,000", 37.0, 115.0, false),
        ("$3,000", 175.0, 115.0, false),
        ("$5,000", 314.0, 115.0, false),
        ("$10,000", 446.0, 115.0, false),
    ] {
        let (font, layout, line_height) = if title {
            (
                &styles.title_font,
                &styles.title_layout,
                styles.title_line_height,
            )
        } else {
            (&styles.row_font, &styles.row_layout, styles.row_line_height)
        };
        spawn_shadowed_text(
            commands,
            grants,
            text,
            left,
            top,
            100.0,
            font,
            layout,
            line_height,
            styles.foreground,
            styles.shadow,
        );
    }
    let entity = spawn_shadowed_text(
        commands,
        grants,
        "",
        15.0,
        37.0,
        180.0,
        &styles.row_font,
        &styles.row_layout,
        styles.row_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands.entity(entity).insert(DiplomacyText::GrantTotal);

    for (text, left, top, title) in [
        ("Trade Policies", 15.0, 13.0, true),
        ("5%", 25.0, 85.0, false),
        ("10%", 74.0, 34.0, false),
        ("25%", 125.0, 85.0, false),
        ("50%", 177.0, 34.0, false),
        ("75%", 228.0, 85.0, false),
        ("100%", 275.0, 34.0, false),
    ] {
        let (font, layout, line_height) = if title {
            (
                &styles.title_font,
                &styles.title_layout,
                styles.title_line_height,
            )
        } else {
            (&styles.row_font, &styles.row_layout, styles.row_line_height)
        };
        spawn_shadowed_text(
            commands,
            trade,
            text,
            left,
            top,
            100.0,
            font,
            layout,
            line_height,
            styles.foreground,
            styles.shadow,
        );
    }
    let centered_layout = styles.row_layout.with_justify(Justify::Center);
    for (text, center) in [
        ("Subsidies", 156.0),
        ("Boycott", 380.0),
        ("Colony Boycott", 473.0),
    ] {
        spawn_shadowed_text(
            commands,
            trade,
            text,
            center - 50.0,
            108.0,
            100.0,
            &styles.row_font,
            &centered_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
    }

    spawn_shadowed_text(
        commands,
        treaties,
        &get_string(assets, 0x2733, 0x20),
        15.0,
        13.0,
        200.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    let treaty_layout = styles.map_layout.with_justify(Justify::Center);
    for (index, (center, top)) in TREATY_LABEL_CENTERS.into_iter().enumerate() {
        spawn_shadowed_text(
            commands,
            treaties,
            &get_string(assets, 0x2733, index as i16 + 6),
            center - 50.0,
            top,
            100.0,
            &styles.map_font,
            &treaty_layout,
            styles.map_line_height,
            styles.foreground,
            styles.shadow,
        );
    }

    let council_title_layout = styles.title_layout.with_justify(Justify::Center);
    let entity = spawn_shadowed_text(
        commands,
        council,
        "",
        0.0,
        36.0,
        518.0,
        &styles.title_font,
        &council_title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands
        .entity(entity)
        .insert((DiplomacyText::Council(0), Visibility::Inherited));
    let council_label_layout = styles.row_layout.with_justify(Justify::Right);
    for row in 0..3_u8 {
        let top = 60.0 + f32::from(row) * 16.0;
        let entity = spawn_shadowed_text(
            commands,
            council,
            "",
            0.0,
            top,
            259.0,
            &styles.row_font,
            &council_label_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::Council(1 + row * 2), Visibility::Inherited));
        let entity = spawn_shadowed_text(
            commands,
            council,
            "",
            263.0,
            top,
            100.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::Council(2 + row * 2), Visibility::Inherited));
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_shadowed_text(
    commands: &mut Commands,
    parent: Entity,
    text: &str,
    left: f32,
    top: f32,
    width: f32,
    font: &TextFont,
    layout: &TextLayout,
    line_height: LineHeight,
    foreground: Color,
    shadow: Color,
) -> Entity {
    commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(left),
                top: Val::Px(top),
                width: Val::Px(width),
                ..default()
            },
            Text::new(text),
            font.clone(),
            *layout,
            line_height,
            TextColor(foreground),
            TextShadow {
                offset: Vec2::new(-1.0, -1.0),
                color: shadow,
            },
            Pickable::IGNORE,
            ChildOf(parent),
        ))
        .id()
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
            screen.framed_nation = session.active_major_nation().nation();
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

fn on_diplomacy_offer_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<RetailAssetsResource>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let accept = match *action {
        DiplomacyAction::AcceptOffer => true,
        DiplomacyAction::RejectOffer => false,
        _ => return,
    };
    if session.game.current_diplomacy_offer().is_none()
        && session.game.current_diplomacy_war_join().is_none()
    {
        return;
    }
    let story_ids = super::session::news_story_ids(assets.as_deref());
    let stop = if session.game.current_diplomacy_offer().is_some() {
        session
            .game
            .answer_current_diplomacy_offer(accept, story_ids)
    } else {
        session
            .game
            .answer_current_diplomacy_war_join(accept, story_ids)
    };
    match stop {
        TurnStop::DiplomacyOffer => {
            let prompt = session
                .game
                .current_diplomacy_offer()
                .expect("diplomacy offer stop requires a current offer");
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy offer answer has one open Diplomacy screen");
            pose_diplomacy_offer(&mut screen, prompt);
        }
        TurnStop::DiplomacyWarJoin => {
            let prompt = session
                .game
                .current_diplomacy_war_join()
                .expect("diplomacy war-join stop requires a current war-join prompt");
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy war-join answer has one open Diplomacy screen");
            pose_diplomacy_war_join(&mut screen, prompt);
        }
        stop => apply_turn_stop(stop, &mut next_state),
    }
}

fn on_diplomacy_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<DiplomacyMapPicture>>,
    modals: Query<(), With<ModalDialog>>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    }
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(tile) = tile_at_diplomacy_position(normalized) else {
        return;
    };
    let Some(target) = session.game.map()[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return;
    };
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy map has one open Diplomacy screen");
    let source = session.active_major_nation();
    let rejection = match screen.mode {
        DiplomacyMode::Information { .. } => {
            if screen.framed_nation != target {
                screen.framed_nation = target;
            }
            None
        }
        DiplomacyMode::Council | DiplomacyMode::Offers => None,
        DiplomacyMode::Treaties { row } => {
            let Some(policy) = TREATY_POLICIES.get(row).copied() else {
                return;
            };
            match session
                .game
                .toggle_player_diplomacy_policy(source, target, policy, false)
            {
                PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => {
                    commands.trigger(OpenDiplomacyEntanglementNotice { target, policy });
                    None
                }
                other => player_diplomacy_rejection(other),
            }
        }
        DiplomacyMode::Grants { row, recurring } => {
            player_diplomacy_rejection(session.game.toggle_player_diplomacy_grant(
                source,
                target,
                DiplomacyGrant {
                    amount: GRANT_AMOUNTS[row],
                    recurring,
                },
            ))
        }
        DiplomacyMode::Trade {
            row,
            colony_boycott,
        } => {
            if colony_boycott {
                player_diplomacy_rejection(
                    session.game.toggle_player_colony_boycott(source, target),
                )
            } else {
                player_diplomacy_rejection(session.game.toggle_player_trade_policy(
                    source,
                    target,
                    TRADE_POLICY_SCORES[row],
                ))
            }
        }
    };
    if let Some(rejection) = rejection {
        commands.trigger(OpenDiplomacyRejectionNotice { rejection });
    }
}

fn player_diplomacy_rejection(
    result: PlayerDiplomacyOrderResult,
) -> Option<PlayerDiplomacyRejection> {
    match result {
        PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
        PlayerDiplomacyOrderResult::Applied
        | PlayerDiplomacyOrderResult::SelectedNation
        | PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => None,
    }
}

fn tile_at_diplomacy_position(normalized: Vec2) -> Option<TileId> {
    let column_pixel = ((normalized.x + 0.5) * MAP_WIDTH).floor();
    let row_pixel = ((normalized.y + 0.5) * MAP_HEIGHT).floor();
    if !(0.0..MAP_WIDTH).contains(&column_pixel) || !(0.0..MAP_HEIGHT).contains(&row_pixel) {
        return None;
    }
    let row = row_pixel as u16 / MAP_TILE_SCALE;
    let odd_offset = MAP_ODD_ROW_OFFSET * (row & 1);
    let column = (column_pixel as u16).checked_sub(odd_offset)? / MAP_TILE_SCALE;
    MapGeometry::new(MapTopology::Bounded).tile(row, column)
}

fn sync_diplomacy_map_cursor(
    maps: Query<&RelativeCursorPosition, With<DiplomacyMapPicture>>,
    modals: Query<(), With<ModalDialog>>,
    screens: Query<&DiplomacyScreen>,
    session: Res<GameSession>,
    mut requested: ResMut<RequestedCursor>,
) {
    if !modals.is_empty() {
        request_arrow_cursor(&mut requested);
        return;
    }
    let Ok(screen) = screens.single() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let Ok(cursor) = maps.single() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    if !cursor.cursor_over() {
        request_arrow_cursor(&mut requested);
        return;
    }
    let Some(normalized) = cursor.normalized else {
        request_turn_event_cursor(&mut requested, DIPLOMACY_IDLE_CURSOR);
        return;
    };
    let source = session.active_major_nation();
    let Some(target) = tile_at_diplomacy_position(normalized).and_then(|tile| {
        session.game.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
    }) else {
        request_turn_event_cursor(&mut requested, DIPLOMACY_IDLE_CURSOR);
        return;
    };
    let mut action = screen.cursor_action();
    if action != DiplomacyMapAction::InspectNation && target == source.nation() {
        action = DiplomacyMapAction::SelectedNation;
    }
    let valid = session
        .game
        .player_diplomacy_map_action_is_valid(source, target, action);
    request_turn_event_cursor(
        &mut requested,
        diplomacy_map_cursor_resource_id(true, action, screen.cursor_row(), valid),
    );
}

fn reset_diplomacy_cursor(mut requested: ResMut<RequestedCursor>) {
    request_arrow_cursor(&mut requested);
}

/// `TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback` cursor id.
fn diplomacy_map_cursor_resource_id(
    nation_hit: bool,
    action: DiplomacyMapAction,
    grant_row: usize,
    valid: bool,
) -> u16 {
    if !nation_hit || !valid {
        return DIPLOMACY_IDLE_CURSOR;
    }
    let mut resource_id = DIPLOMACY_CURSOR_BY_ACTION[action];
    if matches!(
        action,
        DiplomacyMapAction::TradeSubsidy
            | DiplomacyMapAction::OneTimeGrant
            | DiplomacyMapAction::RecurringGrant
    ) {
        resource_id += u16::try_from(grant_row).expect("diplomacy grant row fits u16");
    }
    resource_id
}

fn on_diplomacy_notice_activate(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    notices: Query<(), With<DiplomacyNotice>>,
    mut commands: Commands,
) {
    let root = ancestor_with(activate.entity, &parents, &notices)
        .expect("diplomacy notice close belongs to its dialog");
    commands.entity(root).despawn();
}

fn open_diplomacy_rejection_notice(
    request: On<OpenDiplomacyRejectionNotice>,
    mut commands: Commands,
) {
    spawn_linger_dialog(
        &mut commands,
        DiplomacyNotice(request.rejection),
        AppState::Diplomacy,
        20,
    );
}

fn bind_diplomacy_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyNotice), Added<DiplomacyNotice>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let body = get_string(&assets, 0x2754, notice.0.proposal_mode() - 1);
    let linger = bind_linger_dialog(root, &tree);
    linger.set_title(
        &mut commands,
        &mut assets,
        "Report from your\nForeign Minister\n\n",
    );
    linger.set_body(&mut commands, &mut assets, body);
    let source = session.active_major_nation();
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(linger.coat).insert(ImageNode::new(image));
    }
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_notice_activate);
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn open_diplomacy_entanglement_notice(
    request: On<OpenDiplomacyEntanglementNotice>,
    mut commands: Commands,
) {
    spawn_linger_dialog(
        &mut commands,
        DiplomacyEntanglementNotice {
            target: request.target,
            policy: request.policy,
        },
        AppState::Diplomacy,
        20,
    );
}

fn bind_diplomacy_entanglement_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyEntanglementNotice), Added<DiplomacyEntanglementNotice>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let title = get_string(&assets, 0x275d, 5);
    let body = diplomacy_entanglement_body(&session.game, &assets, notice.target, notice.policy);
    let linger = bind_linger_dialog(root, &tree);
    linger.set_title(&mut commands, &mut assets, title);
    linger.set_body(&mut commands, &mut assets, body);
    let source = session.active_major_nation();
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(linger.coat).insert(ImageNode::new(image));
    }
    commands
        .entity(linger.okay)
        .insert(DiplomacyEntanglementAction::Confirm)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
    commands
        .entity(linger.cancel)
        .insert(DiplomacyEntanglementAction::Dismiss)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
}

#[derive(Component, Clone, Copy)]
enum DiplomacyEntanglementAction {
    Confirm,
    Dismiss,
}

fn on_diplomacy_entanglement_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyEntanglementAction>,
    parents: Query<&ChildOf>,
    notices: Query<(Entity, &DiplomacyEntanglementNotice)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let root = ancestor_with(activate.entity, &parents, &notices)
        .expect("diplomacy entanglement close belongs to its dialog");
    let (_, notice) = notices
        .get(root)
        .expect("diplomacy entanglement close belongs to its dialog");
    let target = notice.target;
    let policy = notice.policy;
    commands.entity(root).despawn();
    if !matches!(*action, DiplomacyEntanglementAction::Confirm) {
        return;
    }
    let source = session.active_major_nation();
    if let Some(rejection) = player_diplomacy_rejection(
        session
            .game
            .toggle_player_diplomacy_policy(source, target, policy, true),
    ) {
        commands.trigger(OpenDiplomacyRejectionNotice { rejection });
    }
}

fn diplomacy_entanglement_body(
    state: &GameState,
    assets: &RetailUiAssets,
    target: NationId,
    policy: DiplomacyPolicy,
) -> String {
    let target_name = state.nations().display_name(target).unwrap_or("");
    let intro_index = if policy == DiplomacyPolicy::Alliance {
        0
    } else {
        4
    };
    let intro = fill_brackets(&get_string(assets, 0x275d, intro_index), &[target_name]);
    let mut names = String::new();
    for major in MajorNationId::all() {
        if state.diplomacy().relationships[target][major.nation()] != DiplomaticRelationship::War {
            continue;
        }
        let Some(name) = state.nations().display_name(major.nation()) else {
            continue;
        };
        names.push_str("   ");
        names.push_str(name);
        names.push('\n');
    }
    format!("{intro}\n{names}")
}

fn pose_diplomacy_offer(screen: &mut DiplomacyScreen, prompt: DiplomacyOfferPrompt) {
    screen.mode = DiplomacyMode::Offers;
    screen.framed_nation = prompt.source;
}

fn pose_diplomacy_war_join(screen: &mut DiplomacyScreen, prompt: DiplomacyWarJoinPrompt) {
    screen.mode = DiplomacyMode::Offers;
    screen.framed_nation = prompt.target;
}

fn nation_label(state: &GameState, nation: NationId) -> String {
    state
        .nations()
        .display_name(nation)
        .unwrap_or("")
        .to_string()
}

fn major_at_war(state: &GameState, first: NationId, second: NationId) -> bool {
    state.diplomacy().relationships[first][second] == DiplomaticRelationship::War
}

fn offer_has_alliance_entanglements(state: &GameState, source: NationId, target: NationId) -> bool {
    MajorNationId::all().any(|nation| {
        let other = nation.nation();
        other != source
            && other != target
            && major_at_war(state, other, target)
            && !major_at_war(state, source, other)
    })
}

fn offer_has_peace_entanglements(state: &GameState, source: NationId, target: NationId) -> bool {
    MajorNationId::all().any(|nation| {
        let other = nation.nation();
        other != source
            && other != target
            && state.diplomacy().relationships[source][other] == DiplomaticRelationship::Alliance
            && major_at_war(state, other, target)
    })
}

fn war_join_adds_entanglements(state: &GameState, prompt: DiplomacyWarJoinPrompt) -> bool {
    let human = prompt.nation.nation();
    match prompt.kind {
        DiplomacyWarJoinKind::DefendMinor | DiplomacyWarJoinKind::AnnexMinor => {
            MajorNationId::all().any(|nation| {
                let other = nation.nation();
                other != prompt.source
                    && major_at_war(state, other, prompt.target)
                    && !major_at_war(state, other, human)
            })
        }
        DiplomacyWarJoinKind::JoinTargetAlly => MajorNationId::all().any(|nation| {
            let other = nation.nation();
            state.diplomacy().relationships[prompt.source][other]
                == DiplomaticRelationship::Alliance
                && !major_at_war(state, other, human)
        }),
        DiplomacyWarJoinKind::JoinSourceAlly => false,
    }
}

fn diplomacy_offer_message(state: &GameState, assets: &RetailAssetsResource) -> Option<String> {
    let prompt = state.current_diplomacy_offer()?;
    let target = nation_label(state, prompt.source);
    let (group, index) = match prompt.policy {
        DiplomacyPolicy::JoinEmpire => (0x274a, 0),
        DiplomacyPolicy::Alliance
            if offer_has_alliance_entanglements(state, prompt.nation.nation(), prompt.source) =>
        {
            (0x274a, 8)
        }
        DiplomacyPolicy::Alliance => (0x274a, 1),
        DiplomacyPolicy::NonAggressionPact => (0x274a, 2),
        DiplomacyPolicy::PeaceTreaty
            if offer_has_peace_entanglements(state, prompt.nation.nation(), prompt.source) =>
        {
            (0x274a, 9)
        }
        DiplomacyPolicy::PeaceTreaty => (0x274a, 3),
        DiplomacyPolicy::JoinEmpireWithWarEntanglements => (0x274a, 4),
        _ => return None,
    };
    Some(fill_brackets(
        &assets.get_string(group, index),
        &[&target, &target],
    ))
}

fn diplomacy_war_join_message(state: &GameState, assets: &RetailAssetsResource) -> Option<String> {
    let prompt = state.current_diplomacy_war_join()?;
    let minor = nation_label(state, prompt.target);
    let enemy = nation_label(state, prompt.source);
    let entangled = war_join_adds_entanglements(state, prompt);
    let (index, args): (i16, [&str; 4]) = match prompt.kind {
        DiplomacyWarJoinKind::DefendMinor => {
            (if entangled { 4 } else { 0 }, [&enemy, &minor, &enemy, ""])
        }
        DiplomacyWarJoinKind::JoinTargetAlly => (
            if entangled { 5 } else { 1 },
            [&enemy, &minor, &minor, &enemy],
        ),
        DiplomacyWarJoinKind::JoinSourceAlly => (2, [&enemy, &minor, &enemy, &minor]),
        DiplomacyWarJoinKind::AnnexMinor => (
            if entangled { 8 } else { 3 },
            [&minor, &enemy, &minor, &minor],
        ),
    };
    Some(fill_brackets(&assets.get_string(0x2729, index), &args))
}

fn sync_diplomacy_controls(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut panels: Query<(&DiplomacyPanel, &mut Node)>,
    controls: Query<(Entity, &DiplomacyAction, Option<&Checked>)>,
    mut brackets: Query<(&DiplomacyTopicBracket, &mut ImageNode, &mut Visibility)>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    for (panel, mut node) in &mut panels {
        node.top = Val::Px(if panel.0 == screen.topic() {
            PANEL_TOP
        } else {
            PANEL_OFFSCREEN_TOP
        });
    }
    for (entity, action, checked) in &controls {
        let selected = match (*action, screen.mode) {
            (
                DiplomacyAction::Grant { row, recurring },
                DiplomacyMode::Grants {
                    row: selected_row,
                    recurring: selected_recurring,
                },
            ) => row == selected_row && recurring == selected_recurring,
            (
                DiplomacyAction::Trade(row),
                DiplomacyMode::Trade {
                    row: selected_row,
                    colony_boycott: false,
                },
            ) => row == selected_row,
            (DiplomacyAction::Treaty(row), DiplomacyMode::Treaties { row: selected_row }) => {
                row == selected_row
            }
            (DiplomacyAction::Overlay(mode), DiplomacyMode::Information { overlay }) => {
                overlay == mode
            }
            (
                DiplomacyAction::ColonyBoycott,
                DiplomacyMode::Trade {
                    colony_boycott: true,
                    ..
                },
            ) => true,
            (
                DiplomacyAction::Topic(_)
                | DiplomacyAction::AcceptOffer
                | DiplomacyAction::RejectOffer,
                _,
            ) => continue,
            _ => false,
        };
        set_checked(&mut commands, entity, checked.is_some(), selected);
    }
    for (bracket, mut image, mut visibility) in &mut brackets {
        let visible = bracket.left
            == matches!(
                screen.topic(),
                DiplomacyTopic::Information | DiplomacyTopic::Council
            );
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        let picture = match screen.topic() {
            DiplomacyTopic::Information => &bracket.pictures.information,
            DiplomacyTopic::Treaties => &bracket.pictures.treaties,
            DiplomacyTopic::Grants => &bracket.pictures.grants,
            DiplomacyTopic::Trade => &bracket.pictures.trade,
            DiplomacyTopic::Council => &bracket.pictures.council,
            // Offers uses the sheet overlay, not a topic-bracket picture.
            DiplomacyTopic::Offers => {
                *visibility = Visibility::Hidden;
                continue;
            }
        };
        image.image = picture.clone();
    }
}

fn locate_offer_sheet(node: &mut Node, visible: bool) {
    if visible {
        node.left = Val::Px(OFFER_SHEET_LEFT);
        node.top = Val::Px(OFFER_SHEET_TOP);
    } else {
        node.left = Val::Px(OFFER_SHEET_OFFSCREEN);
        node.top = Val::Px(OFFER_SHEET_OFFSCREEN);
    }
}

fn sync_diplomacy_offer_sheet(
    mut commands: Commands,
    session: Res<GameSession>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut sheets: Query<&mut Node, (With<DiplomacyOfferSheet>, Without<DiplomacyOfferWait>)>,
    mut waits: Query<&mut Node, (With<DiplomacyOfferWait>, Without<DiplomacyOfferSheet>)>,
    controls: Query<(Entity, &DiplomacyAction)>,
) {
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy state has one Diplomacy screen");
    if let Some(prompt) = session.game.current_diplomacy_offer() {
        if screen.mode != DiplomacyMode::Offers || screen.framed_nation != prompt.source {
            pose_diplomacy_offer(&mut screen, prompt);
        }
    } else if let Some(prompt) = session.game.current_diplomacy_war_join()
        && (screen.mode != DiplomacyMode::Offers || screen.framed_nation != prompt.target)
    {
        pose_diplomacy_war_join(&mut screen, prompt);
    }
    if !session.is_changed() && !screen.is_changed() && !screen.is_added() {
        return;
    }
    let posing = session.game.current_diplomacy_offer().is_some()
        || session.game.current_diplomacy_war_join().is_some();
    for mut node in &mut sheets {
        locate_offer_sheet(&mut node, posing);
    }
    for mut node in &mut waits {
        locate_offer_sheet(&mut node, false);
    }
    for (entity, action) in &controls {
        match *action {
            DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer => {
                if posing {
                    commands.entity(entity).remove::<InteractionDisabled>();
                } else {
                    commands.entity(entity).insert(InteractionDisabled);
                }
            }
            DiplomacyAction::Topic(_) => {
                if posing {
                    commands.entity(entity).insert(InteractionDisabled);
                } else {
                    commands.entity(entity).remove::<InteractionDisabled>();
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::type_complexity)]
fn project_diplomacy_text(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    assets: Res<RetailAssetsResource>,
    mut texts: Query<
        (
            &DiplomacyText,
            &mut Text,
            Option<&mut Node>,
            Option<&mut Visibility>,
        ),
        Without<DiplomacyNationIcon>,
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    let source = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = state.nations().major(source);
    let (name, labels_by_row, values_by_row) = diplomacy_information(state, screen.framed_nation);
    let offer = diplomacy_offer_message(state, &assets)
        .or_else(|| diplomacy_war_join_message(state, &assets));
    let show_map_key_names = match screen.mode {
        DiplomacyMode::Information { overlay } => overlay == 0,
        _ => true,
    };
    let council = council_panel_text(state, &assets);
    for (kind, mut text, mut node, mut visibility) in &mut texts {
        match *kind {
            DiplomacyText::Treasury => text.0 = format_currency(major.common.treasury),
            DiplomacyText::GrantTotal => {
                text.0 = format!(
                    "Promised Grants: {}",
                    format_currency(major.economy.grant_total_cost)
                );
            }
            DiplomacyText::Offer => {
                if let Some(message) = &offer {
                    text.0.clone_from(message);
                }
            }
            DiplomacyText::Info(DiplomacyInfoField::Name) => text.0.clone_from(&name),
            DiplomacyText::Info(DiplomacyInfoField::Label(row)) => {
                text.0.clone_from(&labels_by_row[usize::from(row)]);
            }
            DiplomacyText::Info(DiplomacyInfoField::Value(row)) => {
                text.0.clone_from(&values_by_row[usize::from(row)]);
            }
            DiplomacyText::MapKeyMajorName(major) => {
                text.0.clear();
                text.0
                    .push_str(state.nations().display_name(major.nation()).unwrap_or(""));
                if let Some(visibility) = visibility.as_mut() {
                    **visibility = if show_map_key_names {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                }
            }
            DiplomacyText::Council(0) => {
                text.0.clone_from(&council.title);
                if let Some(visibility) = visibility.as_mut() {
                    **visibility = Visibility::Visible;
                }
            }
            DiplomacyText::Council(index) => {
                let row = usize::from((index - 1) / 2);
                let is_value = index % 2 == 0;
                if let Some(rows) = &council.rows {
                    text.0
                        .clone_from(if is_value { &rows[row].1 } else { &rows[row].0 });
                    if let Some(visibility) = visibility.as_mut() {
                        **visibility = Visibility::Visible;
                    }
                } else {
                    text.0.clear();
                    if let Some(visibility) = visibility.as_mut() {
                        **visibility = Visibility::Hidden;
                    }
                }
            }
            DiplomacyText::NationName(nation) => {
                let Some(visibility) = visibility.as_mut() else {
                    continue;
                };
                let Some(anchor) = representative_tile_for_nation(state, nation) else {
                    **visibility = Visibility::Hidden;
                    continue;
                };
                let Some(display_name) = state.nations().display_name(nation) else {
                    **visibility = Visibility::Hidden;
                    continue;
                };
                if display_name.is_empty() {
                    **visibility = Visibility::Hidden;
                    continue;
                }
                if let Some(node) = node.as_mut() {
                    let (row, column) = state.map().geometry().row_column(anchor);
                    let offset = f32::from(MajorNationId::from_nation(nation).is_none());
                    node.left = Val::Px(f32::from(column) * 5.0 - 45.0 + offset);
                    node.top = Val::Px(f32::from(row) * 5.0 - 6.0 + offset);
                }
                text.0.clear();
                text.0.push_str(display_name);
                **visibility = Visibility::Visible;
            }
        }
    }
}

fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut map_keys: Query<(&DiplomacyMapKey, &mut ImageNode), Without<DiplomacyNationIcon>>,
    mut icons: Query<
        (
            &DiplomacyNationIcon,
            &mut ImageNode,
            &mut Node,
            &mut Visibility,
        ),
        Without<DiplomacyText>,
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    for (map_key, mut image) in &mut map_keys {
        image.image = match screen.mode {
            DiplomacyMode::Information { overlay: 1 } => map_key.relationship_notch.clone(),
            DiplomacyMode::Information { overlay: 2 } => map_key.trade.clone(),
            DiplomacyMode::Information { overlay: 4 } => map_key.relationship_type.clone(),
            _ => map_key.owner.clone(),
        };
    }

    let mode = screen.interaction_mode();
    let show_compat = matches!(mode, 1 | 2 | 4);
    let framed_major = MajorNationId::from_nation(screen.framed_nation);
    let framed_trade = state.nation(screen.framed_nation);
    for (icon, mut image, mut node, mut visibility) in &mut icons {
        let (anchor, atlas_offset, left_offset, top_offset) = match icon.kind {
            DiplomacyNationIconKind::Compatibility => {
                let level = state.diplomacy().mission_levels[screen.framed_nation][icon.nation];
                let atlas_offset = if !show_compat {
                    None
                } else {
                    match level {
                        DiplomaticMissionLevel::None => None,
                        DiplomaticMissionLevel::TradeConsulate => Some(0x170),
                        DiplomaticMissionLevel::Embassy => Some(0x180),
                    }
                };
                (
                    state.nations().home_tile(icon.nation),
                    atlas_offset,
                    0.0,
                    -8.0,
                )
            }
            DiplomacyNationIconKind::Order => {
                let atlas_offset = match mode {
                    4 => framed_major.and_then(|major| {
                        state
                            .nations()
                            .major(major)
                            .economy
                            .diplomacy_policy_by_nation[icon.nation]
                            .and_then(diplomacy_policy_icon_offset)
                    }),
                    2 => framed_trade.and_then(|common| {
                        let policy = common.trade_policy_by_nation[icon.nation];
                        let colony_boycott = framed_major.is_some_and(|major| {
                            state.nations().major(major).economy.colony_boycott_flags[icon.nation]
                                != 0
                        });
                        if policy == TradePolicyScore::BOYCOTT && colony_boycott {
                            Some(0x190)
                        } else {
                            trade_policy_icon_offset(policy)
                        }
                    }),
                    1 => framed_major.and_then(|major| {
                        state
                            .nations()
                            .major(major)
                            .economy
                            .diplomacy_grants_by_nation[icon.nation]
                            .and_then(diplomacy_grant_icon_offset)
                    }),
                    _ => None,
                };
                (
                    representative_tile_for_nation(state, icon.nation),
                    atlas_offset,
                    0.0,
                    8.0,
                )
            }
            DiplomacyNationIconKind::Boycott => {
                let mut offset_overlay = false;
                let show = mode == 2
                    && framed_major.is_some_and(|major| {
                        state.nations().major(major).economy.colony_boycott_flags[icon.nation] != 0
                    })
                    && !framed_trade.is_some_and(|common| {
                        common.trade_policy_by_nation[icon.nation] == TradePolicyScore::BOYCOTT
                    });
                let atlas_offset = if show {
                    offset_overlay = framed_trade.is_some_and(|common| {
                        common.trade_policy_by_nation[icon.nation] != TradePolicyScore::NEUTRAL
                    });
                    Some(0xc0)
                } else {
                    None
                };
                (
                    representative_tile_for_nation(state, icon.nation),
                    atlas_offset,
                    if offset_overlay { 16.0 } else { 0.0 },
                    8.0,
                )
            }
        };
        let Some(anchor) = anchor else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let Some(atlas_offset) = atlas_offset else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let (row, column) = state.map().geometry().row_column(anchor);
        node.left = Val::Px(f32::from(column) * 5.0 - 8.0 + left_offset);
        node.top = Val::Px(f32::from(row) * 5.0 + top_offset);
        image.rect = Some(Rect::new(
            atlas_offset as f32,
            0.0,
            (atlas_offset + 16) as f32,
            16.0,
        ));
        *visibility = Visibility::Visible;
    }
}

fn render_diplomacy_map(
    mut commands: Commands,
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    screen: Single<Ref<DiplomacyScreen>>,
    map: Single<(Entity, Option<&ImageNode>), With<DiplomacyMapPicture>>,
) {
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let (entity, image_node) = map.into_inner();
    let state = &session.game;
    let framed = screen.framed_nation;
    let pixels = match screen.interaction_mode() {
        1 => compose_owner_preview_indices_with_fill(
            |tile| state.map()[tile].owner_nation,
            framed,
            |nation| {
                RELATIONSHIP_NOTCH_PALETTES
                    [usize::from(state.diplomacy_relationship_notch(framed, nation))]
            },
        ),
        4 => compose_owner_preview_indices_with_fill(
            |tile| state.map()[tile].owner_nation,
            framed,
            |nation| diplomacy_relationship_fill(state, framed, nation),
        ),
        _ => compose_owner_preview_indices(|tile| state.map()[tile].owner_nation, framed),
    };
    let image = preview_image_from_indices(&pixels, assets.default_dib_palette());
    if let Some(image_node) = image_node {
        assets.replace_image(&image_node.image, image);
    } else {
        let handle = assets.add_image(image);
        commands.entity(entity).insert(ImageNode::new(handle));
    }
}

fn diplomacy_information(
    state: &GameState,
    nation: NationId,
) -> (String, [String; 3], [String; 3]) {
    let name = state
        .nations()
        .display_name(nation)
        .unwrap_or_default()
        .to_owned();
    let mut labels = ["Provinces:".to_owned(), String::new(), String::new()];
    let mut values = [
        state
            .nations()
            .owned_region_count(nation)
            .unwrap_or_default()
            .to_string(),
        String::new(),
        String::new(),
    ];
    match state.nations().country_status(nation) {
        Some(CountryStatus::ColonyOf(master)) => {
            let master = state.nations().display_name(master).unwrap_or_default();
            labels[1] = format!("Colony of {master}");
        }
        Some(CountryStatus::ProtectorateOf(_)) => labels[1] = "Anarchy".to_owned(),
        Some(CountryStatus::Independent) => {
            if let Some(major) = MajorNationId::from_nation(nation) {
                labels[1] = "Military:".to_owned();
                labels[2] = "Industry:".to_owned();
                values[1] = INFORMATION_BAND_NAMES
                    [usize::from(state.diplomacy_military_power_band(major))]
                .to_owned();
                values[2] = INFORMATION_BAND_NAMES
                    [usize::from(state.diplomacy_industry_band(major))]
                .to_owned();
            } else {
                let minor = MinorNationId::new(nation.get());
                labels[1] = "Most Favored".to_owned();
                labels[2] = "Trading Nation:".to_owned();
                values[2] = state
                    .favorite_trade_partner(minor)
                    .and_then(|partner| state.nations().display_name(partner.nation()))
                    .unwrap_or("None")
                    .to_owned();
            }
        }
        None => {}
    }
    (name, labels, values)
}

fn diplomacy_grant_icon_offset(grant: DiplomacyGrant) -> Option<usize> {
    let row = GRANT_AMOUNTS
        .iter()
        .position(|amount| *amount == grant.amount)?;
    Some((if grant.recurring { 17 + row } else { 13 + row }) * 16)
}

fn diplomacy_policy_icon_offset(policy: DiplomacyPolicy) -> Option<usize> {
    Some(match policy {
        DiplomacyPolicy::JoinEmpire | DiplomacyPolicy::JoinEmpireWithWarEntanglements => 0x40,
        DiplomacyPolicy::Alliance => 0x30,
        DiplomacyPolicy::NonAggressionPact => 0x20,
        DiplomacyPolicy::PeaceTreaty => 0x00,
        DiplomacyPolicy::DeclareWar => 0x10,
        DiplomacyPolicy::BuildConsulate => 0x150,
        DiplomacyPolicy::BuildEmbassy => 0x160,
    })
}

fn trade_policy_icon_offset(policy: TradePolicyScore) -> Option<usize> {
    TRADE_POLICY_SCORES
        .iter()
        .position(|candidate| *candidate == policy)
        .map(|row| (row + 5) * 16)
}

fn diplomacy_relationship_fill(state: &GameState, framed: NationId, nation: NationId) -> u8 {
    if nation == framed {
        return RELATIONSHIP_SELF_PALETTE;
    }
    relationship_type_palette(state.diplomacy().relationships[framed][nation])
}

fn relationship_type_palette(relationship: DiplomaticRelationship) -> u8 {
    // Mode-4 fills use `g_aDiplomacyRelationPaletteColorCodes` through `TViewMgr::GetColor`.
    match relationship {
        DiplomaticRelationship::Alliance => 0x1b,
        DiplomaticRelationship::NonAggressionPact => 0x21,
        DiplomaticRelationship::Peace => 0x29,
        DiplomaticRelationship::JoinedEmpire => 0x22,
        DiplomaticRelationship::War => 0x17,
    }
}

struct CouncilPanelText {
    title: String,
    rows: Option<[(String, String); 3]>,
}

fn council_panel_text(state: &GameState, assets: &RetailAssetsResource) -> CouncilPanelText {
    let congress = &state.diplomacy().congress;
    if let (Some(chairman), Some(counterpart)) = (congress.chairman, congress.counterpart) {
        let decade = (state.turn().economic_turn / 4) / 10 * 10 + 1815;
        CouncilPanelText {
            title: fill_brackets(&assets.get_string(0x2733, 0x35), &[&decade.to_string()]),
            rows: Some([
                (
                    format!(
                        "{}:",
                        state
                            .nations()
                            .display_name(chairman.nation())
                            .unwrap_or("")
                    ),
                    congress.chairman_support.to_string(),
                ),
                (
                    format!(
                        "{}:",
                        state
                            .nations()
                            .display_name(counterpart.nation())
                            .unwrap_or("")
                    ),
                    congress.counterpart_support.to_string(),
                ),
                (
                    assets.get_string(0x2733, 0x36),
                    congress.neutral_support.to_string(),
                ),
            ]),
        }
    } else {
        CouncilPanelText {
            title: assets.get_string(0x2733, 0x34),
            rows: None,
        }
    }
}
fn representative_tile_for_nation(state: &GameState, nation: NationId) -> Option<TileId> {
    let home_region_class = state
        .nations()
        .home_tile(nation)
        .and_then(|tile| state.map()[tile].province)
        .and_then(|province| state.map().provinces[province].region_class);
    let geometry = state.map().geometry();
    let mut column_sum = 0_u32;
    let mut row_sum = 0_u32;
    let mut tile_count = 0_u32;
    let mut west_count = 0_u32;
    let mut east_count = 0_u32;
    let mut fallback = None;

    for tile in TileId::all() {
        if state.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
            != Some(nation)
        {
            continue;
        }
        fallback = Some(tile);
        if let Some(home_region_class) = home_region_class
            && state.map()[tile]
                .province
                .and_then(|province| state.map().provinces[province].region_class)
                != Some(home_region_class)
        {
            continue;
        }
        let (row, column) = geometry.row_column(tile);
        if column < 25 {
            west_count += 1;
        }
        if column > 83 {
            east_count += 1;
        }
        column_sum += u32::from(column);
        row_sum += u32::from(row);
        tile_count += 1;
    }

    if tile_count == 0 {
        return (state
            .nations()
            .owned_region_count(nation)
            .unwrap_or_default()
            > 0)
        .then_some(fallback)
        .flatten();
    }
    if west_count != 0 && east_count != 0 {
        column_sum += west_count * u32::from(STRATEGIC_MAP_WIDTH);
    }
    let column = (column_sum / tile_count) % u32::from(STRATEGIC_MAP_WIDTH);
    let row = row_sum / tile_count;
    Some(TileId::new(
        (row * u32::from(STRATEGIC_MAP_WIDTH) + column) as u16,
    ))
}

fn set_checked(
    commands: &mut Commands,
    entity: Entity,
    currently_checked: bool,
    should_be_checked: bool,
) {
    if currently_checked == should_be_checked {
        return;
    }
    if should_be_checked {
        commands.entity(entity).insert(Checked);
    } else {
        commands.entity(entity).remove::<Checked>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_type_fill_uses_get_color_of_retail_relation_codes() {
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::Alliance),
            0x1b
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::NonAggressionPact),
            0x21
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::Peace),
            0x29
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::JoinedEmpire),
            0x22
        );
        assert_eq!(relationship_type_palette(DiplomaticRelationship::War), 0x17);
    }

    #[test]
    fn treaty_radio_value_change_selects_that_pact() {
        let mut app = App::new();
        app.world_mut().spawn(DiplomacyScreen {
            framed_nation: NationId::new(0),
            mode: DiplomacyMode::Treaties { row: 5 },
        });
        let radio = app
            .world_mut()
            .spawn(DiplomacyAction::Treaty(2))
            .observe(on_diplomacy_radio_selected)
            .id();
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

    #[test]
    fn idle_cursor_when_the_pointer_is_not_over_a_nation() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(false, DiplomacyMapAction::DeclareWar, 0, true),
            DIPLOMACY_IDLE_CURSOR
        );
    }

    #[test]
    fn invalid_target_uses_the_idle_diplomacy_cursor() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::Alliance, 0, false),
            DIPLOMACY_IDLE_CURSOR
        );
    }

    #[test]
    fn inspect_and_treaty_actions_use_the_retail_cursor_ids() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::InspectNation, 0, true),
            0x3f3
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::DeclareWar, 0, true),
            0x405
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::BuildEmbassy, 0, true),
            0x41a
        );
    }

    #[test]
    fn grant_and_subsidy_rows_offset_the_base_cursor_id() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::OneTimeGrant, 3, true),
            0x414
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::RecurringGrant, 1, true),
            0x416
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::TradeSubsidy, 2, true),
            0x40b
        );
    }

    use crate::ui::test_support::beginning_of_game_parts;

    fn fixture_parts() -> GameStateParts {
        beginning_of_game_parts()
    }

    fn rebuild_nations(
        parts: &mut GameStateParts,
        mutate: impl Fn(MajorNationId, &mut MajorNation),
    ) {
        let majors = MajorNationTable::from_fn(|id| {
            let mut major = parts.nations.major(id).clone();
            mutate(id, &mut major);
            major
        });
        let minors = MinorNationTable::from_array(std::array::from_fn(|index| {
            parts
                .nations
                .minor(MinorNationId::new(MajorNationId::COUNT + index as u8))
                .cloned()
        }));
        parts.nations = Nations::new(majors, minors);
    }

    fn alliance_offer_state() -> GameState {
        let mut parts = fixture_parts();
        let player = MajorNationId::from_nation(parts.turn.active_nation)
            .expect("beginning-of-game fixture names a major nation");
        let computer = MajorNationId::new(if player.get() == 0 { 1 } else { 0 });
        rebuild_nations(&mut parts, |id, major| {
            if id != computer {
                return;
            }
            major.auto = Some(AutoGreatPowerState::default());
            major.economy.diplomacy_policy_by_nation[player.nation()] =
                Some(DiplomacyPolicy::Alliance);
        });
        let mut state = GameState::from_parts(parts);
        let TurnStop::DiplomacyOffer = state.finish_player_orders(true, &[]) else {
            panic!("alliance offer must stop for the diplomacy-offer dialog");
        };
        state
    }

    fn war_join_state() -> GameState {
        let mut parts = fixture_parts();
        let player = MajorNationId::from_nation(parts.turn.active_nation)
            .expect("beginning-of-game fixture names a major nation");
        let computer = MajorNationId::new(if player.get() == 0 { 1 } else { 0 });
        let minor = NationId::new(7);
        rebuild_nations(&mut parts, |id, major| {
            if id != computer {
                return;
            }
            major.auto = Some(AutoGreatPowerState::default());
            major.economy.diplomacy_policy_by_nation[minor] = Some(DiplomacyPolicy::DeclareWar);
        });
        parts.diplomacy.mission_levels[player.nation()][minor] = DiplomaticMissionLevel::Embassy;
        parts.diplomacy.mission_levels[minor][player.nation()] = DiplomaticMissionLevel::Embassy;
        parts.diplomacy.standings[player.nation()][minor] = 0xff;
        parts.diplomacy.standings[minor][player.nation()] = 0xff;
        for other in MajorNationId::all() {
            if other == player {
                continue;
            }
            parts.diplomacy.mission_levels[minor][other.nation()] = DiplomaticMissionLevel::None;
            parts.diplomacy.standings[minor][other.nation()] = 0x5a;
        }
        let mut state = GameState::from_parts(parts);
        state.set_country_status(minor, CountryStatus::Independent);
        let TurnStop::DiplomacyWarJoin = state.finish_player_orders(true, &[]) else {
            panic!("declare-war on the favorite's minor must stop for the war-join dialog");
        };
        state
    }

    fn dialog_app(state: GameState) -> (App, Entity, Entity) {
        let framed = state
            .current_diplomacy_offer()
            .map(|prompt| prompt.source)
            .or_else(|| {
                state
                    .current_diplomacy_war_join()
                    .map(|prompt| prompt.target)
            })
            .expect("dialog app requires a posed diplomacy continuation");
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_resource(GameSession { game: state })
            .insert_state(AppState::Diplomacy);
        app.world_mut().spawn(DiplomacyScreen {
            framed_nation: framed,
            mode: DiplomacyMode::Offers,
        });
        let accept = app
            .world_mut()
            .spawn(DiplomacyAction::AcceptOffer)
            .observe(on_diplomacy_offer_activate)
            .id();
        let reject = app
            .world_mut()
            .spawn(DiplomacyAction::RejectOffer)
            .observe(on_diplomacy_offer_activate)
            .id();
        (app, accept, reject)
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn accepting_a_diplomacy_offer_calls_the_core_offer_answer() {
        let state = alliance_offer_state();
        let prompt = state
            .current_diplomacy_offer()
            .expect("alliance fixture poses an offer");
        let (mut app, accept, _) = dialog_app(state);
        activate(&mut app, accept);
        let game = &app.world().resource::<GameSession>().game;
        assert!(game.current_diplomacy_offer().is_none());
        assert_eq!(
            game.diplomacy().relationships[prompt.nation.nation()][prompt.source],
            DiplomaticRelationship::Alliance
        );
    }

    #[test]
    fn rejecting_a_war_join_calls_the_core_war_join_answer() {
        let state = war_join_state();
        assert!(state.current_diplomacy_war_join().is_some());
        let (mut app, _, reject) = dialog_app(state);
        activate(&mut app, reject);
        let game = &app.world().resource::<GameSession>().game;
        assert!(game.current_diplomacy_war_join().is_none());
        assert!(game.current_diplomacy_offer().is_none());
    }
}
