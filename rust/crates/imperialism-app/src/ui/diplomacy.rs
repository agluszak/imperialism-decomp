use super::GameSession;
use super::RetailUiAssets;
use super::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use super::diplomacy_map::{DiplomacyMapGeometry, compose_diplomacy_map};
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::retail::RetailTree;
use super::retail_raster::{IndexedRasterExt, indexed_picture};
use super::satellite_preview::nation_owner_palette;
use super::session::apply_turn_stop;
use crate::AppState;
use crate::RetailAssetsResource;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton, ValueChange};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyAction {
    Grant { amount: i32, recurring: bool },
    Trade(TradePolicyChoice),
    Treaty(DiplomacyPolicy),
    Overlay(DiplomacyInformationOverlay),
}

#[derive(Component)]
struct DiplomacyView {
    information: Entity,
    treaties: Entity,
    grants: Entity,
    trade: Entity,
    council: Entity,
    offers: Entity,
    topic_tabs: [Entity; 5],
    grant_radios: [Entity; 8],
    trade_radios: [Entity; 7],
    colony_boycott: Entity,
    overlay_radios: [Entity; 4],
    treaty_radios: [Entity; 7],
    accept: Entity,
    reject: Entity,
    offer_sheet: Entity,
    offer_wait: Entity,
    treasury: Entity,
    offer_text: Entity,
    map_key: Entity,
    map_key_names: [Entity; 7],
    left_bracket: Entity,
    right_bracket: Entity,
    brackets: DiplomacyBracketPictures,
    map_key_owner: Handle<Image>,
    map_key_relationship_notch: Handle<Image>,
    map_key_trade: Handle<Image>,
    map_key_relationship_type: Handle<Image>,
}

impl DiplomacyView {
    fn panel(&self, topic: DiplomacyTopic) -> Entity {
        match topic {
            DiplomacyTopic::Information => self.information,
            DiplomacyTopic::Treaties => self.treaties,
            DiplomacyTopic::Grants => self.grants,
            DiplomacyTopic::Trade => self.trade,
            DiplomacyTopic::Council => self.council,
            DiplomacyTopic::Offers => self.offers,
        }
    }
}

#[derive(Component)]
struct DiplomacyMapPicture;

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
struct DiplomacyBracketPictures {
    information: Handle<Image>,
    council: Handle<Image>,
    treaties: Handle<Image>,
    grants: Handle<Image>,
    trade: Handle<Image>,
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
                pose_diplomacy_from_session,
                render_diplomacy_chrome,
                render_diplomacy_panels,
                layout_diplomacy_panel_text,
                sync_diplomacy_information,
                render_diplomacy_map,
                super::diplomacy_map::layout_diplomacy_nation_label_entities,
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
    mut session: ResMut<GameSession>,
) {
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
    let pictures = DiplomacyBracketPictures {
        information: assets.picture(PictureId::new(5001)),
        council: assets.picture(PictureId::new(5002)),
        treaties: assets.picture(PictureId::new(5003)),
        grants: assets.picture(PictureId::new(5004)),
        trade: assets.picture(PictureId::new(5005)),
    };
    let icon_picture = PictureId::new(802);
    let icon_atlas = assets.keyed_picture(icon_picture, 0x10);
    let view = bind_diplomacy_controls(
        &mut commands,
        *root,
        &tree,
        pictures,
        icon_atlas,
        &mut assets,
        &mut session,
    );
    commands.entity(*root).insert(view);
}

#[allow(clippy::too_many_arguments)]
fn bind_diplomacy_controls(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    pictures: DiplomacyBracketPictures,
    icon_atlas: Handle<Image>,
    assets: &mut RetailUiAssets,
    session: &mut GameSession,
) -> DiplomacyView {
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
            AppState::Diplomacy,
        );
    } else {
        let top = tree.find(root, fourcc!("topB"));
        commands
            .entity(tree.find(top, fourcc!("dipl")))
            .insert((Checked, InteractionDisabled));
    }

    let main = tree.find(root, fourcc!("main"));
    let view = tree.view(main);
    let information = view.child(fourcc!("info"));
    let treaties = view.child(fourcc!("trty"));
    let grants = view.child(fourcc!("gran"));
    let trade = view.child(fourcc!("trad"));
    let council = view.child(fourcc!("coun"));
    let offers = view.child(fourcc!("offr"));
    let trade_cluster = tree.find(trade, fourcc!("clus"));

    for panel in [information, treaties, grants, trade, council] {
        let picture = indexed_picture(518, 122, 0x10);
        let image = assets.add_image(picture.to_keyed_image(assets.default_dib_palette(), 0x10));
        commands.entity(panel).insert(ImageNode::new(image));
    }

    let topic_tabs = [
        (fourcc!("inft"), DiplomacyTopic::Information),
        (fourcc!("trtt"), DiplomacyTopic::Treaties),
        (fourcc!("grat"), DiplomacyTopic::Grants),
        (fourcc!("trat"), DiplomacyTopic::Trade),
        (fourcc!("cout"), DiplomacyTopic::Council),
    ]
    .map(|(tag, topic)| {
        let control = tree.find(root, tag);
        let mut entity = commands.entity(control);
        entity.observe(
            move |_activate: On<Activate>,
                  mut screens: Query<&mut DiplomacyScreen>,
                  session: Res<GameSession>| {
                let mut screen = screens
                    .single_mut()
                    .expect("Diplomacy control has one open Diplomacy screen");
                select_diplomacy_topic(topic, &mut screen, &session);
            },
        );
        if posing {
            entity.insert(InteractionDisabled);
        } else {
            entity.remove::<InteractionDisabled>();
        }
        control
    });

    let start_radio = DiplomacyMode::from_topic(DiplomacyTopic::Information).selected_radio();
    let grant_radios = [
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
    .map(|(index, tag)| {
        let action = DiplomacyAction::Grant {
            amount: GRANT_AMOUNTS[index / 2],
            recurring: index % 2 != 0,
        };
        bind_diplomacy_radio(commands, tree.find(root, tag), action, start_radio)
    })
    .collect::<Vec<_>>()
    .try_into()
    .expect("eight grant radios");

    let trade_radios = TRADE_POLICY_SCORES
        .into_iter()
        .zip([
            fourcc!("traa"),
            fourcc!("trab"),
            fourcc!("trac"),
            fourcc!("trad"),
            fourcc!("trae"),
            fourcc!("traf"),
            fourcc!("trag"),
        ])
        .map(|(score, tag)| {
            let action = DiplomacyAction::Trade(TradePolicyChoice::Policy(score));
            bind_diplomacy_radio(commands, tree.find(trade_cluster, tag), action, start_radio)
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("seven trade radios");

    let overlay_radios = [
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
    ]
    .map(|(overlay, tag)| {
        let action = DiplomacyAction::Overlay(overlay);
        let control = tree.find(root, tag);
        commands.entity(control).remove::<InteractionDisabled>();
        bind_diplomacy_radio(commands, control, action, start_radio)
    });

    let treaty_radios = TREATY_POLICIES
        .into_iter()
        .zip([
            fourcc!("scr0"),
            fourcc!("scr1"),
            fourcc!("scr2"),
            fourcc!("scr3"),
            fourcc!("scr4"),
            fourcc!("scr5"),
            fourcc!("scr6"),
        ])
        .map(|(policy, tag)| {
            let action = DiplomacyAction::Treaty(policy);
            let control = tree.find(root, tag);
            commands.entity(control).remove::<InteractionDisabled>();
            bind_diplomacy_radio(commands, control, action, start_radio)
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("seven treaty radios");

    let colony_boycott = tree.find(trade_cluster, fourcc!("link"));
    commands
        .entity(colony_boycott)
        .remove::<InteractionDisabled>()
        .remove::<Checked>();
    bind_diplomacy_radio(
        commands,
        colony_boycott,
        DiplomacyAction::Trade(TradePolicyChoice::ColonyBoycott),
        start_radio,
    );

    let accept = tree.find(root, fourcc!("acce"));
    let reject = tree.find(root, fourcc!("reje"));
    for (control, accept) in [(accept, true), (reject, false)] {
        commands
            .entity(control)
            .remove::<InteractionDisabled>()
            .observe(
                move |_activate: On<Activate>,
                      mut screens: Query<&mut DiplomacyScreen>,
                      mut session: ResMut<GameSession>,
                      mut next_state: ResMut<NextState<AppState>>| {
                    answer_diplomacy_offer(accept, &mut screens, &mut session, &mut next_state);
                },
            );
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
    let countries = session
        .game
        .nations()
        .common_states()
        .map(|(nation, common)| (nation, common.display_name.clone()))
        .filter(|(_, name)| !name.is_empty())
        .collect::<Vec<_>>();
    let mut labels = Vec::new();
    for (nation, name) in countries {
        if let Some(anchor) = session.game.overlay_anchor_for_nation(nation) {
            labels.push((nation, name, anchor));
        }
    }
    super::diplomacy_map::spawn_diplomacy_nation_labels(commands, assets, map, labels);
    spawn_diplomacy_map_icons(commands, map, icon_atlas);

    let map_key = tree.find(information, fourcc!("mkey"));
    let map_key_owner = assets.picture(PictureId::new(0x1393));
    let map_key_relationship_type = assets.picture(PictureId::new(0x1395));
    let map_key_relationship_notch = assets.picture(PictureId::new(0x1396));
    let map_key_trade = assets.picture(PictureId::new(0x1397));
    let map_key_names = MajorNationId::all()
        .zip(DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS)
        .map(|(_, tag)| {
            let entity = tree.find(root, tag);
            commands.entity(entity).insert(Visibility::Inherited);
            entity
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("seven map-key major names");

    DiplomacyView {
        information,
        treaties,
        grants,
        trade,
        council,
        offers,
        topic_tabs,
        grant_radios,
        trade_radios,
        colony_boycott,
        overlay_radios,
        treaty_radios,
        accept,
        reject,
        offer_sheet: tree.find(root, fourcc!("shee")),
        offer_wait: tree.find(root, fourcc!("wait")),
        treasury: tree.find(root, fourcc!("trea")),
        offer_text: tree.find(root, fourcc!("prop")),
        map_key,
        map_key_names,
        left_bracket: tree.find(root, fourcc!("ltab")),
        right_bracket: tree.find(root, fourcc!("rtab")),
        brackets: pictures,
        map_key_owner,
        map_key_relationship_notch,
        map_key_trade,
        map_key_relationship_type,
    }
}

fn bind_diplomacy_radio(
    commands: &mut Commands,
    control: Entity,
    action: DiplomacyAction,
    start_radio: Option<DiplomacyAction>,
) -> Entity {
    let mut entity = commands.entity(control);
    entity.observe(
        move |change: On<ValueChange<bool>>, mut screens: Query<&mut DiplomacyScreen>| {
            if !change.value {
                return;
            }
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy control has one open Diplomacy screen");
            apply_diplomacy_radio_action(action, &mut screen);
        },
    );
    if start_radio == Some(action) {
        entity.insert(Checked);
    } else {
        entity.remove::<Checked>();
    }
    control
}

fn spawn_diplomacy_map_icons(commands: &mut Commands, map: Entity, icon_atlas: Handle<Image>) {
    for nation in NationId::all() {
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

fn select_diplomacy_topic(
    topic: DiplomacyTopic,
    screen: &mut DiplomacyScreen,
    session: &GameSession,
) {
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

fn apply_diplomacy_radio_action(action: DiplomacyAction, screen: &mut DiplomacyScreen) {
    let next = match action {
        DiplomacyAction::Grant { amount, recurring } => DiplomacyMode::Grant { amount, recurring },
        DiplomacyAction::Trade(choice) => DiplomacyMode::Trade(choice),
        DiplomacyAction::Treaty(policy) => DiplomacyMode::Treaty(policy),
        DiplomacyAction::Overlay(overlay) => DiplomacyMode::Information { overlay },
    };
    if screen.topic() == next.topic() {
        screen.mode = next;
    }
}

fn answer_diplomacy_offer(
    accept: bool,
    screens: &mut Query<&mut DiplomacyScreen>,
    session: &mut GameSession,
    next_state: &mut NextState<AppState>,
) {
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
        stop => apply_turn_stop(stop, next_state),
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
    let body = assets.get_string(0x2754, (notice.0.proposal_mode() - 1) as u16);
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_title(
        &mut commands,
        &mut assets,
        "Report from your\nForeign Minister\n\n",
    );
    linger.set_body(&mut commands, &mut assets, body);
    let source = session.active_major_nation();
    let coat_picture = diplomacy_coat_picture(source);
    commands
        .entity(linger.coat)
        .insert(ImageNode::new(assets.picture(coat_picture)));
    commands.entity(linger.okay).remove::<InteractionDisabled>();
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn diplomacy_coat_picture(nation: MajorNationId) -> PictureId {
    PictureId::new(9500).offset(i16::from(nation.get()))
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
    let title = assets.get_string(0x275d, 5);
    let body = diplomacy_entanglement_body(&session.game, &assets, notice.target, notice.policy);
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_title(&mut commands, &mut assets, title);
    linger.set_body(&mut commands, &mut assets, body);
    let source = session.active_major_nation();
    let target = notice.target;
    let policy = notice.policy;
    commands.entity(linger.coat).insert(ImageNode::new(
        assets.picture(diplomacy_coat_picture(source)),
    ));
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(
            move |_: On<Activate>, mut session: ResMut<GameSession>, mut commands: Commands| {
                let source = session.active_major_nation();
                if let Some(rejection) = player_diplomacy_rejection(
                    session
                        .game
                        .toggle_player_diplomacy_policy(source, target, policy, true),
                ) {
                    commands.trigger(OpenDiplomacyRejectionNotice { rejection });
                }
            },
        );
    commands
        .entity(linger.cancel)
        .remove::<InteractionDisabled>();
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
    let intro = fill_brackets(&assets.get_string(0x275d, intro_index), &[target_name]);
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
    let (index, args): (u16, [&str; 4]) = match prompt.kind {
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

/// One text child of a diplomacy topic panel (Information/Treaties/Grants/Trade/
/// Council). Panels composite only the transparent base; their text is ordinary
/// Bevy text positioned by `render_diplomacy_panels`.
#[derive(Component)]
struct DiplomacyPanelText {
    origin: IVec2,
    alignment: Justify,
}

#[allow(clippy::too_many_arguments)]
fn spawn_panel_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    panel: Entity,
    text: String,
    origin: IVec2,
    preset: RetailTextStylePreset,
    alignment: Justify,
) {
    let (font, _layout, line_height, _) = assets.text_style(preset);
    let logical_height = resolve_retail_text_style(preset)
        .map(|style| style.logical_pixel_height)
        .unwrap_or(14);
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(origin.x),
            top: px((origin.y - logical_height) as f32),
            ..default()
        },
        Text::new(text),
        font,
        TextLayout::justify(alignment),
        line_height,
        TextColor(assets.palette_color(0xd2)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0x13),
        },
        Pickable::IGNORE,
        DiplomacyPanelText { origin, alignment },
        ChildOf(panel),
    ));
}

/// Retail draws a single intrinsic string at its measured origin.  Bevy needs
/// one layout pass before the corresponding centered/right-aligned origin is
/// known; no fabricated wrapping rectangle is involved.
fn layout_diplomacy_panel_text(mut labels: Query<(&DiplomacyPanelText, &ComputedNode, &mut Node)>) {
    for (label, computed, mut node) in &mut labels {
        let width = computed.size.x;
        if width <= 0.0 {
            continue;
        }
        let left = match label.alignment {
            Justify::Center => label.origin.x as f32 - width / 2.0,
            Justify::Right => label.origin.x as f32 - width,
            _ => label.origin.x as f32,
        };
        node.left = px(left);
    }
}

fn render_diplomacy_panels(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    view: Single<Ref<DiplomacyView>>,
    mut assets: RetailUiAssets,
    panel_texts: Query<Entity, With<DiplomacyPanelText>>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() && !view.is_added() {
        return;
    }
    let view = view.into_inner();
    for entity in &panel_texts {
        commands.entity(entity).despawn();
    }
    let state = &session.game;
    let source = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = state.nations().major(source);
    let title = RetailTextStylePreset::built(14, 0);
    let row = RetailTextStylePreset::built(12, 0);
    let small = RetailTextStylePreset::explicit(1, 0, 10, 0);
    let council = RetailTextStylePreset::built(18, 0);
    let strings = |assets: &RetailUiAssets, index: u16| assets.get_string(0x2733, index);
    let (name, labels, values) = diplomacy_information(state, screen.framed_nation);
    let council_data = council_panel_text(state, &assets);

    for topic in [
        DiplomacyTopic::Information,
        DiplomacyTopic::Treaties,
        DiplomacyTopic::Grants,
        DiplomacyTopic::Trade,
        DiplomacyTopic::Council,
    ] {
        let panel = view.panel(topic);
        match topic {
            DiplomacyTopic::Information => {
                let panel_text = strings(&assets, 0);
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    panel_text,
                    IVec2::new(15, 13),
                    title,
                    Justify::Left,
                );
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    name.clone(),
                    IVec2::new(110, 13),
                    title,
                    Justify::Left,
                );
                for (index, baseline) in [54, 71, 88].into_iter().enumerate() {
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        labels[index].clone(),
                        IVec2::new(15, baseline),
                        row,
                        Justify::Left,
                    );
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        values[index].clone(),
                        IVec2::new(110, baseline),
                        row,
                        Justify::Left,
                    );
                }
            }
            DiplomacyTopic::Treaties => {
                let panel_text = strings(&assets, 0x20);
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    panel_text,
                    IVec2::new(74, 15),
                    title,
                    Justify::Center,
                );
                for (index, (center, baseline)) in TREATY_LABEL_CENTERS.into_iter().enumerate() {
                    let panel_text = strings(&assets, index as u16 + 6);
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        panel_text,
                        IVec2::new(center as i32, baseline as i32),
                        small,
                        Justify::Center,
                    );
                }
            }
            DiplomacyTopic::Grants => {
                for (text, origin, is_title) in [
                    (strings(&assets, 0x21), IVec2::new(15, 13), true),
                    (strings(&assets, 0x22), IVec2::new(174, 13), false),
                    (strings(&assets, 0x23), IVec2::new(276, 30), false),
                    (strings(&assets, 0x24), IVec2::new(440, 30), false),
                    (strings(&assets, 0x26), IVec2::new(37, 115), false),
                    (strings(&assets, 0x27), IVec2::new(175, 115), false),
                    (strings(&assets, 0x28), IVec2::new(314, 115), false),
                    (strings(&assets, 0x29), IVec2::new(446, 115), false),
                ] {
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        text,
                        origin,
                        if is_title { title } else { row },
                        Justify::Left,
                    );
                }
                let panel_text = format!(
                    "{} {}",
                    strings(&assets, 0x25),
                    format_currency(major.economy.grant_total_cost)
                );
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    panel_text,
                    IVec2::new(15, 37),
                    row,
                    Justify::Left,
                );
            }
            DiplomacyTopic::Trade => {
                let panel_text = strings(&assets, 0x2a);
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    panel_text,
                    IVec2::new(15, 13),
                    title,
                    Justify::Left,
                );
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
                    let panel_text = strings(&assets, index as u16 + 0x2b);
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        panel_text,
                        origin,
                        row,
                        Justify::Left,
                    );
                }
                for (index, center) in [156, 380, 473].into_iter().enumerate() {
                    let panel_text = strings(&assets, index as u16 + 0x31);
                    spawn_panel_text(
                        &mut commands,
                        &mut assets,
                        panel,
                        panel_text,
                        IVec2::new(center, 108),
                        row,
                        Justify::Center,
                    );
                }
            }
            DiplomacyTopic::Council => {
                spawn_panel_text(
                    &mut commands,
                    &mut assets,
                    panel,
                    council_data.title.clone(),
                    IVec2::new(259, 36),
                    council,
                    Justify::Center,
                );
                if let Some(rows) = &council_data.rows {
                    for (row, (label, value)) in rows.iter().enumerate() {
                        let baseline = 60 + row as i32 * 16;
                        spawn_panel_text(
                            &mut commands,
                            &mut assets,
                            panel,
                            label.clone(),
                            IVec2::new(259, baseline),
                            title,
                            Justify::Right,
                        );
                        spawn_panel_text(
                            &mut commands,
                            &mut assets,
                            panel,
                            value.clone(),
                            IVec2::new(263, baseline),
                            title,
                            Justify::Left,
                        );
                    }
                }
            }
            DiplomacyTopic::Offers => {}
        }
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

fn pose_diplomacy_from_session(
    session: Res<GameSession>,
    mut screens: Query<&mut DiplomacyScreen>,
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
}

fn render_diplomacy_chrome(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    view: Single<Ref<DiplomacyView>>,
    assets: Res<RetailAssetsResource>,
    mut nodes: Query<&mut Node>,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
    checked: Query<(), With<Checked>>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() && !view.is_added() {
        return;
    }
    let view = view.into_inner();
    for topic in [
        DiplomacyTopic::Information,
        DiplomacyTopic::Treaties,
        DiplomacyTopic::Grants,
        DiplomacyTopic::Trade,
        DiplomacyTopic::Council,
        DiplomacyTopic::Offers,
    ] {
        let mut node = nodes
            .get_mut(view.panel(topic))
            .expect("bound diplomacy panel must exist");
        node.top = Val::Px(if topic == screen.topic() {
            PANEL_TOP
        } else {
            PANEL_OFFSCREEN_TOP
        });
    }

    let selected = screen.mode.selected_radio();
    for (index, entity) in view.grant_radios.into_iter().enumerate() {
        let action = DiplomacyAction::Grant {
            amount: GRANT_AMOUNTS[index / 2],
            recurring: index % 2 != 0,
        };
        set_checked(
            &mut commands,
            entity,
            checked.contains(entity),
            selected == Some(action),
        );
    }
    for (score, entity) in TRADE_POLICY_SCORES.into_iter().zip(view.trade_radios) {
        let action = DiplomacyAction::Trade(TradePolicyChoice::Policy(score));
        set_checked(
            &mut commands,
            entity,
            checked.contains(entity),
            selected == Some(action),
        );
    }
    set_checked(
        &mut commands,
        view.colony_boycott,
        checked.contains(view.colony_boycott),
        selected == Some(DiplomacyAction::Trade(TradePolicyChoice::ColonyBoycott)),
    );
    for (overlay, entity) in [
        DiplomacyInformationOverlay::Owner,
        DiplomacyInformationOverlay::RelationshipNotch,
        DiplomacyInformationOverlay::Trade,
        DiplomacyInformationOverlay::RelationshipType,
    ]
    .into_iter()
    .zip(view.overlay_radios)
    {
        let action = DiplomacyAction::Overlay(overlay);
        set_checked(
            &mut commands,
            entity,
            checked.contains(entity),
            selected == Some(action),
        );
    }
    for (policy, entity) in TREATY_POLICIES.into_iter().zip(view.treaty_radios) {
        let action = DiplomacyAction::Treaty(policy);
        set_checked(
            &mut commands,
            entity,
            checked.contains(entity),
            selected == Some(action),
        );
    }

    let left_visible = matches!(
        screen.topic(),
        DiplomacyTopic::Information | DiplomacyTopic::Council
    );
    for (entity, left) in [(view.left_bracket, true), (view.right_bracket, false)] {
        let visible = left == left_visible && screen.topic() != DiplomacyTopic::Offers;
        *visibilities
            .get_mut(entity)
            .expect("bound diplomacy bracket must exist") = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        if screen.topic() == DiplomacyTopic::Offers {
            continue;
        }
        let picture = match screen.topic() {
            DiplomacyTopic::Information => &view.brackets.information,
            DiplomacyTopic::Treaties => &view.brackets.treaties,
            DiplomacyTopic::Grants => &view.brackets.grants,
            DiplomacyTopic::Trade => &view.brackets.trade,
            DiplomacyTopic::Council => &view.brackets.council,
            DiplomacyTopic::Offers => continue,
        };
        images
            .get_mut(entity)
            .expect("bound diplomacy bracket must exist")
            .image = picture.clone();
    }

    let posing = session.game.current_diplomacy_offer().is_some()
        || session.game.current_diplomacy_war_join().is_some();
    locate_offer_sheet(
        &mut nodes
            .get_mut(view.offer_sheet)
            .expect("bound diplomacy offer sheet must exist"),
        posing,
    );
    locate_offer_sheet(
        &mut nodes
            .get_mut(view.offer_wait)
            .expect("bound diplomacy offer wait must exist"),
        false,
    );
    for entity in view.topic_tabs {
        if posing {
            commands.entity(entity).insert(InteractionDisabled);
        } else {
            commands.entity(entity).remove::<InteractionDisabled>();
        }
    }
    for entity in [view.accept, view.reject] {
        if posing {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }

    let state = &session.game;
    let source = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = state.nations().major(source);
    texts
        .get_mut(view.treasury)
        .expect("bound diplomacy treasury text must exist")
        .0 = format_currency(major.common.treasury);
    if let Some(message) = diplomacy_offer_message(state, &assets)
        .or_else(|| diplomacy_war_join_message(state, &assets))
    {
        texts
            .get_mut(view.offer_text)
            .expect("bound diplomacy offer text must exist")
            .0 = message;
    }
    let show_map_key_names = match screen.mode {
        DiplomacyMode::Information { overlay } => overlay == DiplomacyInformationOverlay::Owner,
        _ => true,
    };
    for (major, entity) in MajorNationId::all().zip(view.map_key_names) {
        let text = &mut texts
            .get_mut(entity)
            .expect("bound diplomacy map-key name must exist")
            .0;
        text.clear();
        text.push_str(state.nations().display_name(major.nation()).unwrap_or(""));
        *visibilities
            .get_mut(entity)
            .expect("bound diplomacy map-key name must exist") = if show_map_key_names {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    view: Single<&DiplomacyView>,
    mut map_keys: Query<&mut ImageNode, Without<DiplomacyNationIcon>>,
    mut icons: Query<(
        &DiplomacyNationIcon,
        &mut ImageNode,
        &mut Node,
        &mut Visibility,
    )>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    map_keys
        .get_mut(view.map_key)
        .expect("bound diplomacy map key must exist")
        .image = match screen.mode {
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::RelationshipNotch,
        } => view.map_key_relationship_notch.clone(),
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::Trade,
        } => view.map_key_trade.clone(),
        DiplomacyMode::Information {
            overlay: DiplomacyInformationOverlay::RelationshipType,
        } => view.map_key_relationship_type.clone(),
        _ => view.map_key_owner.clone(),
    };

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
    let (picture, geometry) = compose_diplomacy_map(owner_at, fill, Some(framed));
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

fn council_panel_text(state: &GameState, assets: &RetailUiAssets) -> CouncilPanelText {
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
        let action = DiplomacyAction::Treaty(DiplomacyPolicy::NonAggressionPact);
        let radio = app
            .world_mut()
            .spawn_empty()
            .observe(
                move |change: On<ValueChange<bool>>, mut screens: Query<&mut DiplomacyScreen>| {
                    if !change.value {
                        return;
                    }
                    let mut screen = screens
                        .single_mut()
                        .expect("Diplomacy control has one open Diplomacy screen");
                    apply_diplomacy_radio_action(action, &mut screen);
                },
            )
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
            .spawn_empty()
            .observe(
                move |_activate: On<Activate>,
                      mut screens: Query<&mut DiplomacyScreen>,
                      mut session: ResMut<GameSession>,
                      mut next_state: ResMut<NextState<AppState>>| {
                    answer_diplomacy_offer(true, &mut screens, &mut session, &mut next_state);
                },
            )
            .id();
        let reject = app
            .world_mut()
            .spawn_empty()
            .observe(
                move |_activate: On<Activate>,
                      mut screens: Query<&mut DiplomacyScreen>,
                      mut session: ResMut<GameSession>,
                      mut next_state: ResMut<NextState<AppState>>| {
                    answer_diplomacy_offer(false, &mut screens, &mut session, &mut next_state);
                },
            )
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
