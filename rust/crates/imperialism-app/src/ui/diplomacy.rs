use super::GameSession;
use super::RetailUiAssets;
use super::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use super::diplomacy_map::{
    DiplomacyLabelSeed, DiplomacyMapGeometry, compose_diplomacy_map, draw_diplomacy_map_labels,
    layout_diplomacy_map_labels,
};
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::hover_help::retail_string;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::{RetailTree, ancestor_with};
use super::retail_raster::{IndexedRasterExt, indexed_picture};
use super::retail_raster_text::RetailRasterTextPainter;
use super::satellite_preview::nation_owner_palette;
use super::session::apply_turn_stop;
use crate::AppState;
use crate::{RetailAssetsResource, RetailFonts};
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

#[derive(Clone, Copy)]
enum DiplomacyRelationshipNotch {
    Hostile,
    VeryUnfriendly,
    Unfriendly,
    Reserved,
    Neutral,
    Friendly,
    VeryFriendly,
    Allied,
    Devoted,
}

impl DiplomacyRelationshipNotch {
    fn from_standing(standing: i16) -> Self {
        if standing <= 0x14 {
            Self::Hostile
        } else if standing <= 0x31 {
            Self::VeryUnfriendly
        } else if standing <= 0x4f {
            Self::Unfriendly
        } else if standing <= 0x64 {
            Self::Reserved
        } else if standing <= 0x87 {
            Self::Neutral
        } else if standing <= 0xaa {
            Self::Friendly
        } else if standing <= 0xcd {
            Self::VeryFriendly
        } else if standing <= 0xf0 {
            Self::Allied
        } else {
            Self::Devoted
        }
    }

    fn palette(self) -> u8 {
        match self {
            Self::Hostile => 0x20,
            Self::VeryUnfriendly => 0x2d,
            Self::Unfriendly => 0x30,
            Self::Reserved => 0x2e,
            Self::Neutral => 0x27,
            Self::Friendly => 0x24,
            Self::VeryFriendly => 0x26,
            Self::Allied => 0x18,
            Self::Devoted => 0x14,
        }
    }
}

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
enum DiplomacyInformationOverlay {
    Owner,
    RelationshipNotch,
    Trade,
    RelationshipType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TradePolicyChoice {
    Policy(TradePolicyScore),
    ColonyBoycott,
}

impl TradePolicyChoice {
    fn map_action(self) -> DiplomacyMapAction {
        match self {
            Self::ColonyBoycott => DiplomacyMapAction::LinkTradePolicy,
            Self::Policy(score) if score == TradePolicyScore::BOYCOTT => {
                DiplomacyMapAction::Boycott
            }
            Self::Policy(_) => DiplomacyMapAction::TradeSubsidy,
        }
    }

    fn score(self) -> Option<TradePolicyScore> {
        match self {
            Self::Policy(score) => Some(score),
            Self::ColonyBoycott => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyMode {
    Information {
        overlay: DiplomacyInformationOverlay,
    },
    Treaty(DiplomacyPolicy),
    Grant {
        amount: i32,
        recurring: bool,
    },
    Trade(TradePolicyChoice),
    Council,
    Offers,
}

impl DiplomacyMode {
    fn from_topic(topic: DiplomacyTopic) -> Self {
        match topic {
            DiplomacyTopic::Information => Self::Information {
                overlay: DiplomacyInformationOverlay::Owner,
            },
            DiplomacyTopic::Treaties => Self::Treaty(DiplomacyPolicy::BuildConsulate),
            DiplomacyTopic::Grants => Self::Grant {
                amount: GRANT_AMOUNTS[0],
                recurring: false,
            },
            DiplomacyTopic::Trade => Self::Trade(TradePolicyChoice::Policy(TRADE_POLICY_SCORES[0])),
            DiplomacyTopic::Council => Self::Council,
            DiplomacyTopic::Offers => Self::Offers,
        }
    }

    fn topic(self) -> DiplomacyTopic {
        match self {
            Self::Information { .. } => DiplomacyTopic::Information,
            Self::Treaty(_) => DiplomacyTopic::Treaties,
            Self::Grant { .. } => DiplomacyTopic::Grants,
            Self::Trade(_) => DiplomacyTopic::Trade,
            Self::Council => DiplomacyTopic::Council,
            Self::Offers => DiplomacyTopic::Offers,
        }
    }

    fn map_action(self) -> DiplomacyMapAction {
        match self {
            Self::Information { .. } | Self::Offers => DiplomacyMapAction::InspectNation,
            Self::Treaty(policy) => policy
                .map_action()
                .expect("treaty mode holds a map-selectable policy"),
            Self::Grant {
                recurring: true, ..
            } => DiplomacyMapAction::RecurringGrant,
            Self::Grant {
                recurring: false, ..
            } => DiplomacyMapAction::OneTimeGrant,
            Self::Trade(choice) => choice.map_action(),
            Self::Council => DiplomacyMapAction::None,
        }
    }

    fn selected_radio(self) -> Option<DiplomacyAction> {
        match self {
            Self::Grant { amount, recurring } => Some(DiplomacyAction::Grant { amount, recurring }),
            Self::Trade(choice) => Some(DiplomacyAction::Trade(choice)),
            Self::Treaty(policy) => Some(DiplomacyAction::Treaty(policy)),
            Self::Information { overlay } => Some(DiplomacyAction::Overlay(overlay)),
            Self::Council | Self::Offers => None,
        }
    }

    fn cursor_offset(self) -> usize {
        match self {
            Self::Grant { amount, .. } => GRANT_AMOUNTS
                .iter()
                .position(|&candidate| candidate == amount)
                .unwrap_or(0),
            Self::Trade(choice) => choice
                .score()
                .and_then(|score| {
                    TRADE_POLICY_SCORES
                        .iter()
                        .position(|&candidate| candidate == score)
                })
                .unwrap_or(0),
            _ => 0,
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

    fn map_action(&self) -> DiplomacyMapAction {
        self.mode.map_action()
    }
}

#[derive(Component, Clone, Copy)]
struct DiplomacyPanel(DiplomacyTopic);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyAction {
    Topic(DiplomacyTopic),
    Grant { amount: i32, recurring: bool },
    Trade(TradePolicyChoice),
    Treaty(DiplomacyPolicy),
    Overlay(DiplomacyInformationOverlay),
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

#[derive(Component, Clone, Copy)]
enum DiplomacyText {
    Treasury,
    Offer,
    NationName,
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
    map_font: TextFont,
    map_layout: TextLayout,
    map_line_height: LineHeight,
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
                render_diplomacy_panels,
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
        mode: DiplomacyMode::from_topic(DiplomacyTopic::Information),
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
    let (map_font, map_layout, map_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail diplomacy map label style");
    let styles = DiplomacyTextStyles {
        map_font,
        map_layout,
        map_line_height,
        foreground: assets.palette_color(0x13),
        shadow: assets.palette_color(0xd2),
    };
    let icon_picture = PictureId::new(802);
    let icon_atlas = assets
        .transparent_picture(icon_picture, 0x10)
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
        bind_native_game_screen_nav(
            commands,
            root,
            tree,
            fourcc!("topB"),
            Some(fourcc!("too3")),
            true,
        );
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
        if topic != DiplomacyTopic::Offers {
            let picture = indexed_picture(518, 122, 0x10);
            let image =
                assets.add_image(picture.to_keyed_image(assets.default_dib_palette(), 0x10));
            commands.entity(panel).insert(ImageNode::new(image));
        }
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
    let start_radio = DiplomacyMode::from_topic(DiplomacyTopic::Information).selected_radio();
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
        let action = DiplomacyAction::Grant {
            amount: GRANT_AMOUNTS[index / 2],
            recurring: index % 2 != 0,
        };
        let control = tree.find(root, tag);
        let mut entity = commands.entity(control);
        entity.insert(action).observe(on_diplomacy_radio_selected);
        if start_radio == Some(action) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
    }
    for (score, tag) in TRADE_POLICY_SCORES.into_iter().zip([
        fourcc!("traa"),
        fourcc!("trab"),
        fourcc!("trac"),
        fourcc!("trad"),
        fourcc!("trae"),
        fourcc!("traf"),
        fourcc!("trag"),
    ]) {
        let action = DiplomacyAction::Trade(TradePolicyChoice::Policy(score));
        let control = tree.find(trade_cluster, tag);
        let mut entity = commands.entity(control);
        entity.insert(action).observe(on_diplomacy_radio_selected);
        if start_radio == Some(action) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
    }
    for (overlay, tag) in [
        (DiplomacyInformationOverlay::Owner, fourcc!("ovr0")),
        (
            DiplomacyInformationOverlay::RelationshipNotch,
            fourcc!("ovr1"),
        ),
        (DiplomacyInformationOverlay::Trade, fourcc!("ovr2")),
        (
            DiplomacyInformationOverlay::RelationshipType,
            fourcc!("ovr4"),
        ),
    ] {
        let action = DiplomacyAction::Overlay(overlay);
        let control = tree.find(root, tag);
        let mut entity = commands.entity(control);
        entity
            .insert(action)
            .remove::<InteractionDisabled>()
            .observe(on_diplomacy_radio_selected);
        if start_radio == Some(action) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
    }
    for (policy, tag) in TREATY_POLICIES.into_iter().zip([
        fourcc!("scr0"),
        fourcc!("scr1"),
        fourcc!("scr2"),
        fourcc!("scr3"),
        fourcc!("scr4"),
        fourcc!("scr5"),
        fourcc!("scr6"),
    ]) {
        let action = DiplomacyAction::Treaty(policy);
        let control = tree.find(root, tag);
        let mut entity = commands.entity(control);
        entity
            .insert(action)
            .remove::<InteractionDisabled>()
            .observe(on_diplomacy_radio_selected);
        if start_radio == Some(action) {
            entity.insert(Checked);
        } else {
            entity.remove::<Checked>();
        }
    }
    commands
        .entity(tree.find(trade_cluster, fourcc!("link")))
        .insert(DiplomacyAction::Trade(TradePolicyChoice::ColonyBoycott))
        .remove::<InteractionDisabled>()
        .remove::<Checked>()
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
            DiplomacyMapGeometry::default(),
            ZIndex(1),
            ChildOf(main),
        ))
        .observe(on_diplomacy_map_click)
        .id();
    spawn_diplomacy_map_labels(commands, map, &styles, icon_atlas);
    bind_diplomacy_map_key(commands, root, tree, information, assets);

    let shee = tree.find(root, fourcc!("shee"));
    let wait = tree.find(root, fourcc!("wait"));
    let prop = tree.find(root, fourcc!("prop"));
    commands.entity(shee).insert(DiplomacyOfferSheet);
    commands.entity(wait).insert(DiplomacyOfferWait);
    commands.entity(prop).insert(DiplomacyText::Offer);

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
            .insert((DiplomacyText::NationName, Visibility::Hidden));
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

fn bind_diplomacy_map_key(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    information: Entity,
    assets: &mut RetailUiAssets,
) {
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
    for (major, tag) in MajorNationId::all().zip(DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS) {
        commands
            .entity(tree.find(root, tag))
            .insert((DiplomacyText::MapKeyMajorName(major), Visibility::Inherited));
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
    let next = match action {
        DiplomacyAction::Grant { amount, recurring } => DiplomacyMode::Grant { amount, recurring },
        DiplomacyAction::Trade(choice) => DiplomacyMode::Trade(choice),
        DiplomacyAction::Treaty(policy) => DiplomacyMode::Treaty(policy),
        DiplomacyAction::Overlay(overlay) => DiplomacyMode::Information { overlay },
        DiplomacyAction::Topic(_) | DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer => {
            return;
        }
    };
    if screen.topic() == next.topic() {
        screen.mode = next;
    }
}

fn on_diplomacy_offer_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
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
    let stop = if session.game.current_diplomacy_offer().is_some() {
        session.game.answer_current_diplomacy_offer(accept)
    } else {
        session.game.answer_current_diplomacy_war_join(accept)
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
    maps: Query<(&RelativeCursorPosition, &DiplomacyMapGeometry), With<DiplomacyMapPicture>>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok((cursor, geometry)) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    };
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(target) = geometry.nation_at_normalized(normalized) else {
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
        DiplomacyMode::Treaty(policy) => {
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
        DiplomacyMode::Grant { amount, recurring } => {
            player_diplomacy_rejection(session.game.toggle_player_diplomacy_grant(
                source,
                target,
                DiplomacyGrant { amount, recurring },
            ))
        }
        DiplomacyMode::Trade(choice) => match choice.score() {
            None => player_diplomacy_rejection(
                session.game.toggle_player_colony_boycott(source, target),
            ),
            Some(score) => player_diplomacy_rejection(
                session
                    .game
                    .toggle_player_trade_policy(source, target, score),
            ),
        },
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
        | PlayerDiplomacyOrderResult::NotApplied
        | PlayerDiplomacyOrderResult::SelectedNation
        | PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => None,
    }
}

fn sync_diplomacy_map_cursor(
    maps: Query<(&RelativeCursorPosition, &DiplomacyMapGeometry), With<DiplomacyMapPicture>>,
    screens: Query<&DiplomacyScreen>,
    session: Res<GameSession>,
    mut requested: ResMut<RequestedCursor>,
) {
    let Ok(screen) = screens.single() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let Ok((cursor, geometry)) = maps.single() else {
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
    let Some(target) = geometry.nation_at_normalized(normalized) else {
        request_turn_event_cursor(&mut requested, DIPLOMACY_IDLE_CURSOR);
        return;
    };
    let mut action = screen.map_action();
    if action != DiplomacyMapAction::InspectNation && target == source.nation() {
        action = DiplomacyMapAction::SelectedNation;
    }
    let valid = session
        .game
        .player_diplomacy_map_action_is_valid(source, target, action);
    request_turn_event_cursor(
        &mut requested,
        diplomacy_map_cursor_resource_id(true, action, screen.mode.cursor_offset(), valid),
    );
}

fn reset_diplomacy_cursor(mut requested: ResMut<RequestedCursor>) {
    request_arrow_cursor(&mut requested);
}

/// `TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback` cursor id.
fn diplomacy_map_cursor_resource_id(
    nation_hit: bool,
    action: DiplomacyMapAction,
    row_offset: usize,
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
        resource_id += u16::try_from(row_offset).expect("diplomacy grant row fits u16");
    }
    resource_id
}

fn open_diplomacy_rejection_notice(
    request: On<OpenDiplomacyRejectionNotice>,
    mut commands: Commands,
) {
    spawn_linger_dialog(
        &mut commands,
        DiplomacyNotice(request.rejection),
        AppState::Diplomacy,
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
    let body = retail_string(&assets, StringGroup::new(0x2754).offset((notice.0.proposal_mode() - 1) as u16));
    let linger = bind_linger_dialog(&mut commands, root, &tree);
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
    commands.entity(linger.okay).remove::<InteractionDisabled>();
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
    let title = retail_string(&assets, StringGroup::new(0x275d).offset(5));
    let body = diplomacy_entanglement_body(&session.game, &assets, notice.target, notice.policy);
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_title(&mut commands, &mut assets, title);
    linger.set_body(&mut commands, &mut assets, body);
    let source = session.active_major_nation();
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(linger.coat).insert(ImageNode::new(image));
    }
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
    commands
        .entity(linger.cancel)
        .remove::<InteractionDisabled>();
}

fn on_diplomacy_entanglement_activate(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    notices: Query<(Entity, &DiplomacyEntanglementNotice)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let root = ancestor_with(activate.entity, &parents, &notices)
        .expect("diplomacy entanglement close belongs to its dialog");
    let (_, notice) = notices
        .get(root)
        .expect("diplomacy entanglement close belongs to its dialog");
    let target = notice.target;
    let policy = notice.policy;
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
    let intro = fill_brackets(&retail_string(assets, StringGroup::new(0x275d).offset((intro_index) as u16)), &[target_name]);
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
        &assets.string(StringGroup::new((group) as u16).offset((index) as u16)).expect("retail string"),
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
    Some(fill_brackets(&assets.string(StringGroup::new(0x2729).offset((index) as u16)).expect("retail string"), &args))
}

fn draw_diplomacy_text(
    picture: &mut IndexedPicture,
    painter: &mut RetailRasterTextPainter<'_>,
    origin: IVec2,
    text: &str,
) {
    painter.draw(picture, origin, text, 0xd2);
    painter.draw(picture, origin + IVec2::ONE, text, 0x13);
}

fn draw_diplomacy_text_right(
    picture: &mut IndexedPicture,
    painter: &mut RetailRasterTextPainter<'_>,
    right: i32,
    baseline: i32,
    text: &str,
) {
    painter.draw_right(picture, right, baseline, text, 0xd2);
    painter.draw_right(picture, right + 1, baseline + 1, text, 0x13);
}

fn draw_diplomacy_text_center(
    picture: &mut IndexedPicture,
    painter: &mut RetailRasterTextPainter<'_>,
    center: i32,
    baseline: i32,
    text: &str,
) {
    painter.draw_center(picture, center, baseline, text, 0xd2);
    painter.draw_center(picture, center + 1, baseline + 1, text, 0x13);
}

fn diplomacy_text_painter<'a>(
    fonts: &RetailFonts,
    font_assets: &'a Assets<Font>,
    point_size: i32,
) -> RetailRasterTextPainter<'a> {
    RetailRasterTextPainter::from_preset(
        fonts,
        font_assets,
        RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size,
            alignment: 0,
        },
    )
    .expect("retail Diplomacy custom-drawing text style")
}

fn render_diplomacy_panels(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut images: ResMut<Assets<Image>>,
    panels: Query<(&DiplomacyPanel, &ImageNode)>,
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
    let mut title = diplomacy_text_painter(&fonts, &font_assets, 14);
    let mut row = diplomacy_text_painter(&fonts, &font_assets, 12);
    let mut small = diplomacy_text_painter(&fonts, &font_assets, 10);
    let mut council_paint = diplomacy_text_painter(&fonts, &font_assets, 18);
    let strings = |index| retail.string(StringGroup::new(0x2733).offset((index) as u16)).expect("retail string");
    let (name, labels, values) = diplomacy_information(state, screen.framed_nation);
    let council = council_panel_text(state, &retail);

    for (panel, image_node) in &panels {
        let mut picture = indexed_picture(518, 122, 0x10);
        match panel.0 {
            DiplomacyTopic::Information => {
                draw_diplomacy_text(&mut picture, &mut title, IVec2::new(15, 13), &strings(0));
                draw_diplomacy_text(&mut picture, &mut title, IVec2::new(110, 13), &name);
                for (index, baseline) in [54, 71, 88].into_iter().enumerate() {
                    draw_diplomacy_text(
                        &mut picture,
                        &mut row,
                        IVec2::new(15, baseline),
                        &labels[index],
                    );
                    draw_diplomacy_text(
                        &mut picture,
                        &mut row,
                        IVec2::new(110, baseline),
                        &values[index],
                    );
                }
            }
            DiplomacyTopic::Treaties => {
                draw_diplomacy_text(&mut picture, &mut title, IVec2::new(15, 13), &strings(0x20));
                for (index, (center, baseline)) in TREATY_LABEL_CENTERS.into_iter().enumerate() {
                    draw_diplomacy_text_center(
                        &mut picture,
                        &mut small,
                        center as i32,
                        baseline as i32,
                        &strings(index as i16 + 6),
                    );
                }
            }
            DiplomacyTopic::Grants => {
                for (text, origin, is_title) in [
                    (strings(0x21), IVec2::new(15, 13), true),
                    (strings(0x22), IVec2::new(174, 13), false),
                    (strings(0x23), IVec2::new(276, 30), false),
                    (strings(0x24), IVec2::new(440, 30), false),
                    (strings(0x26), IVec2::new(37, 115), false),
                    (strings(0x27), IVec2::new(175, 115), false),
                    (strings(0x28), IVec2::new(314, 115), false),
                    (strings(0x29), IVec2::new(446, 115), false),
                ] {
                    if is_title {
                        draw_diplomacy_text(&mut picture, &mut title, origin, &text);
                    } else {
                        draw_diplomacy_text(&mut picture, &mut row, origin, &text);
                    }
                }
                draw_diplomacy_text(
                    &mut picture,
                    &mut row,
                    IVec2::new(15, 37),
                    &format!(
                        "{} {}",
                        strings(0x25),
                        format_currency(major.economy.grant_total_cost)
                    ),
                );
            }
            DiplomacyTopic::Trade => {
                draw_diplomacy_text(&mut picture, &mut title, IVec2::new(15, 13), &strings(0x2a));
                for (index, origin) in [
                    IVec2::new(25, 85),
                    IVec2::new(74, 34),
                    IVec2::new(125, 85),
                    IVec2::new(177, 34),
                    IVec2::new(228, 85),
                    IVec2::new(275, 34),
                ]
                .into_iter()
                .enumerate()
                {
                    draw_diplomacy_text(
                        &mut picture,
                        &mut row,
                        origin,
                        &strings(index as i16 + 0x2b),
                    );
                }
                for (index, center) in [156, 380, 473].into_iter().enumerate() {
                    draw_diplomacy_text_center(
                        &mut picture,
                        &mut row,
                        center,
                        108,
                        &strings(index as i16 + 0x31),
                    );
                }
            }
            DiplomacyTopic::Council => {
                draw_diplomacy_text_center(
                    &mut picture,
                    &mut council_paint,
                    259,
                    36,
                    &council.title,
                );
                if let Some(rows) = &council.rows {
                    for (row, (label, value)) in rows.iter().enumerate() {
                        let baseline = 60 + row as i32 * 16;
                        draw_diplomacy_text_right(&mut picture, &mut title, 259, baseline, label);
                        draw_diplomacy_text(
                            &mut picture,
                            &mut title,
                            IVec2::new(263, baseline),
                            value,
                        );
                    }
                }
            }
            DiplomacyTopic::Offers => continue,
        }
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
        }
    }
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
        if matches!(
            *action,
            DiplomacyAction::Topic(_) | DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer
        ) {
            continue;
        }
        set_checked(
            &mut commands,
            entity,
            checked.is_some(),
            screen.mode.selected_radio() == Some(*action),
        );
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
        (&DiplomacyText, &mut Text, Option<&mut Visibility>),
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
    let offer = diplomacy_offer_message(state, &assets)
        .or_else(|| diplomacy_war_join_message(state, &assets));
    let show_map_key_names = match screen.mode {
        DiplomacyMode::Information { overlay } => overlay == DiplomacyInformationOverlay::Owner,
        _ => true,
    };
    for (kind, mut text, mut visibility) in &mut texts {
        match *kind {
            DiplomacyText::Treasury => text.0 = format_currency(major.common.treasury),
            DiplomacyText::Offer => {
                if let Some(message) = &offer {
                    text.0.clone_from(message);
                }
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
            DiplomacyText::NationName => {
                if let Some(visibility) = visibility.as_mut() {
                    **visibility = Visibility::Hidden;
                }
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
            DiplomacyMode::Information {
                overlay: DiplomacyInformationOverlay::RelationshipNotch,
            } => map_key.relationship_notch.clone(),
            DiplomacyMode::Information {
                overlay: DiplomacyInformationOverlay::Trade,
            } => map_key.trade.clone(),
            DiplomacyMode::Information {
                overlay: DiplomacyInformationOverlay::RelationshipType,
            } => map_key.relationship_type.clone(),
            _ => map_key.owner.clone(),
        };
    }

    let show_compat = !matches!(
        screen.mode,
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::Owner,
        } | DiplomacyMode::Council
            | DiplomacyMode::Offers
    );
    let show_trade_orders = matches!(
        screen.mode,
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::Trade,
        } | DiplomacyMode::Trade(_)
    );
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
                let atlas_offset = match screen.mode {
                    DiplomacyMode::Information {
                        overlay: DiplomacyInformationOverlay::RelationshipType,
                    }
                    | DiplomacyMode::Treaty(_) => framed_major.and_then(|major| {
                        state
                            .nations()
                            .major(major)
                            .economy
                            .diplomacy_policy_by_nation[icon.nation]
                            .and_then(diplomacy_policy_icon_offset)
                    }),
                    DiplomacyMode::Information {
                        overlay: DiplomacyInformationOverlay::Trade,
                    }
                    | DiplomacyMode::Trade(_) => framed_trade.and_then(|common| {
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
                    DiplomacyMode::Information {
                        overlay: DiplomacyInformationOverlay::RelationshipNotch,
                    }
                    | DiplomacyMode::Grant { .. } => framed_major.and_then(|major| {
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
                let show = show_trade_orders
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
    font_assets: Res<Assets<Font>>,
    screen: Single<Ref<DiplomacyScreen>>,
    map: Single<(Entity, Option<&ImageNode>), With<DiplomacyMapPicture>>,
) {
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let (entity, image_node) = map.into_inner();
    let state = &session.game;
    let framed = screen.framed_nation;
    let owner_at = |tile: TileId| {
        state.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
    };
    let fill = |nation: NationId| match screen.mode {
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::RelationshipNotch,
        }
        | DiplomacyMode::Grant { .. } => {
            DiplomacyRelationshipNotch::from_standing(state.diplomacy_standing(framed, nation))
                .palette()
        }
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::RelationshipType,
        }
        | DiplomacyMode::Treaty(_) => diplomacy_relationship_fill(state, framed, nation),
        _ => nation_owner_palette(nation),
    };
    let (mut picture, geometry) = compose_diplomacy_map(owner_at, fill, Some(framed));
    let mut painter = RetailRasterTextPainter::from_preset(
        assets.fonts(),
        &font_assets,
        RetailTextStylePreset {
            font_family: 0,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        },
    )
    .expect("retail Diplomacy map label style");
    let mut seeds = [None; NationId::COUNT as usize];
    for nation in NationId::all() {
        let Some(name) = state.nations().display_name(nation) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(anchor) = state.ocean_overlay_anchor_for_nation(nation) else {
            continue;
        };
        let (row, column) = state.map().geometry().row_column(anchor);
        seeds[usize::from(nation.get())] = Some(DiplomacyLabelSeed { name, column, row });
    }
    let labels = layout_diplomacy_map_labels(&seeds, |name| painter.measure(name));
    draw_diplomacy_map_labels(&mut picture, &mut painter, &seeds, &labels);
    let image = picture.to_keyed_image(assets.default_dib_palette(), 0x10);
    let mut entity_commands = commands.entity(entity);
    entity_commands.insert(geometry);
    if let Some(image_node) = image_node {
        assets.replace_image(&image_node.image, image);
    } else {
        let handle = assets.add_image(image);
        entity_commands.insert(ImageNode::new(handle));
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
            title: fill_brackets(&assets.string(StringGroup::new(0x2733).offset(0x35)).expect("retail string"), &[&decade.to_string()]),
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
                    assets.string(StringGroup::new(0x2733).offset(0x36)).expect("retail string"),
                    congress.neutral_support.to_string(),
                ),
            ]),
        }
    } else {
        CouncilPanelText {
            title: assets.string(StringGroup::new(0x2733).offset(0x34)).expect("retail string"),
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
    use indexmap::IndexMap;

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
            mode: DiplomacyMode::Treaty(DiplomacyPolicy::BuildConsulate),
        });
        let radio = app
            .world_mut()
            .spawn(DiplomacyAction::Treaty(DiplomacyPolicy::NonAggressionPact))
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
        assert_eq!(
            screen.mode,
            DiplomacyMode::Treaty(DiplomacyPolicy::NonAggressionPact)
        );
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
        let minors = MinorNationId::all()
            .filter_map(|id| parts.nations.minor(id).cloned().map(|minor| (id, minor)))
            .collect::<IndexMap<_, _>>();
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
        let TurnStop::DiplomacyOffer = state.finish_player_orders(true) else {
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
        let TurnStop::DiplomacyWarJoin = state.finish_player_orders(true) else {
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
            .insert_resource(GameSession::new(state))
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
