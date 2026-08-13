use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::hover_help::get_string;
use super::random_setup_map::{
    compose_owner_preview_indices, compose_owner_preview_indices_with_fill,
    preview_image_from_indices,
};
use super::retail::ModalDialog;
use super::retail::{RetailTag, find_child, find_descendant};
use super::session::apply_turn_stop;
use crate::AppState;
use crate::RetailAssetsResource;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
use imperialism_core::*;
use imperialism_formats::*;

const PANEL_TOP: f32 = 354.0;
const PANEL_OFFSCREEN_TOP: f32 = 800.0;
const MAP_LEFT: f32 = 49.0;
const MAP_TOP: f32 = 45.0;
const MAP_WIDTH: f32 = 540.0;
const MAP_HEIGHT: f32 = 300.0;
const MAP_TILE_SCALE: u16 = 5;
const MAP_ODD_ROW_OFFSET: u16 = 2;
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

#[derive(Component, Clone, Copy)]
struct DiplomacyScreen {
    framed_nation: NationId,
    topic: DiplomacyTopic,
    grant_row: usize,
    recurring_grant: bool,
    trade_row: usize,
    treaty_row: usize,
    overlay: u8,
    colony_boycott: bool,
}

impl DiplomacyScreen {
    fn interaction_mode(&self) -> i32 {
        match self.topic {
            DiplomacyTopic::Information => i32::from(self.overlay),
            DiplomacyTopic::Treaties => 4,
            DiplomacyTopic::Grants => 1,
            DiplomacyTopic::Trade => 2,
            DiplomacyTopic::Council => 5,
            DiplomacyTopic::Offers => 0,
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

#[derive(Component)]
struct DiplomacyOfferText;

#[derive(Component)]
struct DiplomacyTreasury;

#[derive(Component, Clone, Copy)]
struct DiplomacyNationLabel {
    nation: NationId,
    shadow: bool,
}

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
struct DiplomacyInfoText(DiplomacyInfoField);

#[derive(Component, Clone, Copy)]
struct DiplomacyMapKeyMajorName(MajorNationId);

#[derive(Component, Clone)]
struct DiplomacyMapKey {
    owner: Handle<Image>,
    relationship_notch: Handle<Image>,
    trade: Handle<Image>,
    relationship_type: Handle<Image>,
}

#[derive(Component)]
struct DiplomacyGrantTotal;

#[derive(Component)]
struct DiplomacyCouncilText(u8);

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
                sync_diplomacy_controls,
                sync_diplomacy_offer_sheet,
                sync_diplomacy_information,
                render_diplomacy_map,
            )
                .chain()
                .run_if(in_state(AppState::Diplomacy)),
        )
        .add_observer(on_diplomacy_activate.run_if(in_state(AppState::Diplomacy)))
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
        topic: DiplomacyTopic::Information,
        grant_row: 0,
        recurring_grant: false,
        trade_row: 0,
        treaty_row: 5,
        overlay: 0,
        colony_boycott: false,
    };
    if let Some(framed) = diplomacy_interrupt_frame(&session.game) {
        screen.topic = DiplomacyTopic::Offers;
        screen.framed_nation = framed;
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
    bind_game_status_display(
        &mut commands,
        &mut assets,
        *root,
        &children,
        &tags,
        &session,
    );
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

#[allow(clippy::too_many_arguments)]
fn bind_diplomacy_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    pictures: DiplomacyBracketPictures,
    styles: DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
    assets: &mut RetailUiAssets,
    session: &GameSession,
) -> Entity {
    if !diplomacy_interrupt(&session.game) {
        bind_native_game_screen_nav(
            commands,
            root,
            children,
            tags,
            fourcc!("topB"),
            Some(fourcc!("too3")),
        );
    }
    let top = find_descendant(root, fourcc!("topB"), children, tags);
    let selected = find_descendant(top, fourcc!("dipl"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));

    let main = find_descendant(root, fourcc!("main"), children, tags);
    let information = find_child(main, fourcc!("info"), children, tags);
    let treaties = find_child(main, fourcc!("trty"), children, tags);
    let grants = find_child(main, fourcc!("gran"), children, tags);
    let trade = find_child(main, fourcc!("trad"), children, tags);
    let council = find_child(main, fourcc!("coun"), children, tags);
    let offers = find_child(main, fourcc!("offr"), children, tags);
    let trade_cluster = find_descendant(trade, fourcc!("clus"), children, tags);

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
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Topic(topic))
            .remove::<InteractionDisabled>();
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
        let control = find_descendant(root, tag, children, tags);
        commands.entity(control).insert(DiplomacyAction::Grant {
            row: index / 2,
            recurring: index % 2 != 0,
        });
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
        let control = find_descendant(trade_cluster, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Trade(index));
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
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Overlay(overlay))
            .remove::<InteractionDisabled>();
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
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Treaty(index))
            .remove::<InteractionDisabled>();
    }
    commands
        .entity(find_descendant(
            trade_cluster,
            fourcc!("link"),
            children,
            tags,
        ))
        .insert(DiplomacyAction::ColonyBoycott)
        .remove::<InteractionDisabled>();
    for (tag, action) in [
        (fourcc!("acce"), DiplomacyAction::AcceptOffer),
        (fourcc!("reje"), DiplomacyAction::RejectOffer),
    ] {
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert((action, ActivateOnPress))
            .remove::<InteractionDisabled>();
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
        let control = find_descendant(root, tag, children, tags);
        if checked {
            commands.entity(control).insert(Checked);
        } else {
            commands.entity(control).remove::<Checked>();
        }
    }
    commands
        .entity(find_descendant(
            trade_cluster,
            fourcc!("link"),
            children,
            tags,
        ))
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
        .id();
    spawn_diplomacy_map_labels(commands, map, &styles, icon_atlas);
    spawn_diplomacy_panel_text(
        commands,
        root,
        children,
        tags,
        information,
        treaties,
        grants,
        trade,
        council,
        &styles,
        assets,
    );

    let shee = find_descendant(root, fourcc!("shee"), children, tags);
    let wait = find_descendant(root, fourcc!("wait"), children, tags);
    let prop = find_descendant(root, fourcc!("prop"), children, tags);
    commands.entity(shee).insert(DiplomacyOfferSheet);
    commands.entity(wait).insert(DiplomacyOfferWait);
    let offer_layout = styles.row_layout.with_justify(Justify::Center);
    for entity in spawn_shadowed_text(
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
    ) {
        commands.entity(entity).insert(DiplomacyOfferText);
    }

    let treasury = find_descendant(root, fourcc!("trea"), children, tags);
    commands.entity(treasury).insert(DiplomacyTreasury);
    let left = find_descendant(root, fourcc!("ltab"), children, tags);
    commands.entity(left).insert(DiplomacyTopicBracket {
        left: true,
        pictures: pictures.clone(),
    });
    let right = find_descendant(root, fourcc!("rtab"), children, tags);
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
        let labels = spawn_shadowed_text(
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
        commands.entity(labels[0]).insert((
            DiplomacyNationLabel {
                nation,
                shadow: true,
            },
            Visibility::Hidden,
        ));
        commands.entity(labels[1]).insert((
            DiplomacyNationLabel {
                nation,
                shadow: false,
            },
            Visibility::Hidden,
        ));
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
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
    let name = spawn_shadowed_text(
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
    for entity in name {
        commands
            .entity(entity)
            .insert(DiplomacyInfoText(DiplomacyInfoField::Name));
    }
    for (row, top) in [54.0, 71.0, 88.0].into_iter().enumerate() {
        let label = spawn_shadowed_text(
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
        for entity in label {
            commands
                .entity(entity)
                .insert(DiplomacyInfoText(DiplomacyInfoField::Label(row as u8)));
        }
        let value = spawn_shadowed_text(
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
        for entity in value {
            commands
                .entity(entity)
                .insert(DiplomacyInfoText(DiplomacyInfoField::Value(row as u8)));
        }
    }

    let map_key = find_descendant(information, fourcc!("mkey"), children, tags);
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
    for (major, tag) in (0..MajorNationId::COUNT)
        .map(MajorNationId::new)
        .zip(DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS)
    {
        commands
            .entity(find_descendant(root, tag, children, tags))
            .insert((DiplomacyMapKeyMajorName(major), Visibility::Inherited));
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
    let total = spawn_shadowed_text(
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
    for entity in total {
        commands.entity(entity).insert(DiplomacyGrantTotal);
    }

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
    let title = spawn_shadowed_text(
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
    for entity in title {
        commands
            .entity(entity)
            .insert((DiplomacyCouncilText(0), Visibility::Inherited));
    }
    let council_label_layout = styles.row_layout.with_justify(Justify::Right);
    for row in 0..3_u8 {
        let top = 60.0 + f32::from(row) * 16.0;
        let label = spawn_shadowed_text(
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
        for entity in label {
            commands
                .entity(entity)
                .insert((DiplomacyCouncilText(1 + row * 2), Visibility::Inherited));
        }
        let value = spawn_shadowed_text(
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
        for entity in value {
            commands
                .entity(entity)
                .insert((DiplomacyCouncilText(2 + row * 2), Visibility::Inherited));
        }
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
) -> [Entity; 2] {
    let spawn = |commands: &mut Commands, left, top, color| {
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
                TextColor(color),
                Pickable::IGNORE,
                ChildOf(parent),
            ))
            .id()
    };
    [
        spawn(commands, left, top, shadow),
        spawn(commands, left + 1.0, top + 1.0, foreground),
    ]
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
            if diplomacy_interrupt(&session.game) {
                return;
            }
            if screen.topic == topic {
                return;
            }
            screen.topic = topic;
            screen.framed_nation = MajorNationId::from_nation(session.game.turn().active_nation)
                .expect("Diplomacy screen requires an active major nation")
                .nation();
            match topic {
                DiplomacyTopic::Information => screen.overlay = 0,
                DiplomacyTopic::Treaties => screen.treaty_row = 5,
                DiplomacyTopic::Council | DiplomacyTopic::Offers => {}
                DiplomacyTopic::Grants => {
                    screen.grant_row = 0;
                    screen.recurring_grant = false;
                }
                DiplomacyTopic::Trade => {
                    screen.trade_row = 0;
                    screen.colony_boycott = false;
                }
            }
        }
        DiplomacyAction::Grant { row, recurring } => {
            if screen.grant_row != row || screen.recurring_grant != recurring {
                screen.grant_row = row;
                screen.recurring_grant = recurring;
            }
        }
        DiplomacyAction::Trade(row) => {
            screen.trade_row = row;
            screen.colony_boycott = false;
        }
        DiplomacyAction::Treaty(row) => screen.treaty_row = row,
        DiplomacyAction::Overlay(mode) => screen.overlay = mode,
        DiplomacyAction::ColonyBoycott => screen.colony_boycott = true,
        DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer => {}
    }
}

fn on_diplomacy_offer_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    retail: Res<RetailAssetsResource>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let accept = match *action {
        DiplomacyAction::AcceptOffer => true,
        DiplomacyAction::RejectOffer => false,
        _ => return,
    };
    if !diplomacy_interrupt(&session.game) {
        return;
    }
    let news_story_ids = retail.assets().news_table().story_ids();
    let stop = if session.game.current_diplomacy_offer().is_some() {
        session
            .game
            .answer_current_diplomacy_offer(accept, news_story_ids)
    } else {
        session
            .game
            .answer_current_diplomacy_war_join(accept, news_story_ids)
    };
    match stop {
        TurnStop::DiplomacyOffer(prompt) => {
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy offer answer has one open Diplomacy screen");
            screen.topic = DiplomacyTopic::Offers;
            screen.framed_nation = prompt.source;
        }
        TurnStop::DiplomacyWarJoin(prompt) => {
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy war-join answer has one open Diplomacy screen");
            screen.topic = DiplomacyTopic::Offers;
            screen.framed_nation = prompt.target;
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
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let rejection = match screen.topic {
        DiplomacyTopic::Information => {
            if screen.framed_nation != target {
                screen.framed_nation = target;
            }
            None
        }
        DiplomacyTopic::Council | DiplomacyTopic::Offers => None,
        DiplomacyTopic::Treaties => {
            let Some(policy) = TREATY_POLICIES.get(screen.treaty_row).copied() else {
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
        DiplomacyTopic::Grants => {
            player_diplomacy_rejection(session.game.toggle_player_diplomacy_grant(
                source,
                target,
                DiplomacyGrant {
                    amount: GRANT_AMOUNTS[screen.grant_row],
                    recurring: screen.recurring_grant,
                },
            ))
        }
        DiplomacyTopic::Trade => {
            if screen.colony_boycott {
                player_diplomacy_rejection(
                    session.game.toggle_player_colony_boycott(source, target),
                )
            } else {
                player_diplomacy_rejection(session.game.toggle_player_trade_policy(
                    source,
                    target,
                    TRADE_POLICY_SCORES[screen.trade_row],
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

fn on_diplomacy_notice_activate(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    notices: Query<(), With<DiplomacyNotice>>,
    mut commands: Commands,
) {
    let mut entity = activate.entity;
    loop {
        if notices.contains(entity) {
            commands.entity(entity).despawn();
            return;
        }
        entity = parents
            .get(entity)
            .expect("diplomacy notice close belongs to its dialog")
            .parent();
    }
}

fn open_diplomacy_rejection_notice(
    request: On<OpenDiplomacyRejectionNotice>,
    mut commands: Commands,
) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        DiplomacyNotice(request.rejection),
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::Diplomacy),
    ));
}

fn bind_diplomacy_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyNotice), Added<DiplomacyNotice>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let notice_color = TextColor(assets.palette_color(0));
    let title = find_descendant(root, fourcc!("titl"), &children, &tags);
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail diplomacy notice title style");
    commands.entity(title).insert((
        Text::new("Report from your\nForeign Minister\n\n"),
        title_font,
        title_layout,
        title_line_height,
        notice_color,
    ));
    let body = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy notice body style");
    commands.entity(body).insert((
        Text::new(get_string(&assets, 0x2754, notice.0.proposal_mode() - 1)),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let coat = find_descendant(root, fourcc!("coat"), &children, &tags);
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_notice_activate);
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    commands.entity(cancel).insert(Visibility::Hidden);
}

fn open_diplomacy_entanglement_notice(
    request: On<OpenDiplomacyEntanglementNotice>,
    mut commands: Commands,
) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        DiplomacyEntanglementNotice {
            target: request.target,
            policy: request.policy,
        },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::Diplomacy),
    ));
}

fn bind_diplomacy_entanglement_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyEntanglementNotice), Added<DiplomacyEntanglementNotice>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let notice_color = TextColor(assets.palette_color(0));
    let title = find_descendant(root, fourcc!("titl"), &children, &tags);
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail diplomacy entanglement title style");
    commands.entity(title).insert((
        Text::new(get_string(&assets, 0x275d, 5)),
        title_font,
        title_layout,
        title_line_height,
        notice_color,
    ));
    let body = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy entanglement body style");
    commands.entity(body).insert((
        Text::new(diplomacy_entanglement_body(
            &session.game,
            &assets,
            notice.target,
            notice.policy,
        )),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let coat = find_descendant(root, fourcc!("coat"), &children, &tags);
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .insert(DiplomacyEntanglementAction::Confirm)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    commands
        .entity(cancel)
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
    let mut entity = activate.entity;
    let notice = loop {
        if let Ok(notice) = notices.get(entity) {
            break notice;
        }
        entity = parents
            .get(entity)
            .expect("diplomacy entanglement close belongs to its dialog")
            .parent();
    };
    let (root, notice) = notice;
    let target = notice.target;
    let policy = notice.policy;
    commands.entity(root).despawn();
    if !matches!(*action, DiplomacyEntanglementAction::Confirm) {
        return;
    }
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
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
    for major in (0..MajorNationId::COUNT).map(MajorNationId::new) {
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

fn diplomacy_interrupt(state: &GameState) -> bool {
    state.current_diplomacy_offer().is_some() || state.current_diplomacy_war_join().is_some()
}

fn diplomacy_interrupt_frame(state: &GameState) -> Option<NationId> {
    if let Some(prompt) = state.current_diplomacy_offer() {
        return Some(prompt.source);
    }
    state
        .current_diplomacy_war_join()
        .map(|prompt| prompt.target)
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

fn diplomacy_offer_message(state: &GameState, assets: &RetailUiAssets) -> Option<String> {
    if let Some(prompt) = state.current_diplomacy_offer() {
        let target = nation_label(state, prompt.source);
        let (group, index) = match prompt.policy {
            DiplomacyPolicy::JoinEmpire => (0x274a, 0),
            DiplomacyPolicy::Alliance
                if offer_has_alliance_entanglements(
                    state,
                    prompt.nation.nation(),
                    prompt.source,
                ) =>
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
        return Some(fill_brackets(
            &get_string(assets, group, index),
            &[&target, &target],
        ));
    }
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
    Some(fill_brackets(&get_string(assets, 0x2729, index), &args))
}

fn fill_brackets(template: &str, args: &[&str]) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '[' {
            let mut scan = index + 1;
            while scan < chars.len() && chars[scan] != ']' && !chars[scan].is_ascii_digit() {
                scan += 1;
            }
            if scan < chars.len() && chars[scan].is_ascii_digit() {
                let slot = (chars[scan] as u8 - b'0') as usize;
                if slot >= 1 && slot <= args.len() {
                    out.push_str(args[slot - 1]);
                }
                while scan < chars.len() && chars[scan] != ']' {
                    scan += 1;
                }
                index = scan.saturating_add(1);
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sync_diplomacy_controls(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut panels: Query<(&DiplomacyPanel, &mut Node)>,
    controls: Query<(Entity, &DiplomacyAction, Option<&Checked>)>,
    mut brackets: Query<(&DiplomacyTopicBracket, &mut ImageNode, &mut Visibility)>,
    mut treasury: Query<&mut Text, With<DiplomacyTreasury>>,
    mut grant_totals: Query<&mut Text, (With<DiplomacyGrantTotal>, Without<DiplomacyTreasury>)>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    for (panel, mut node) in &mut panels {
        node.top = Val::Px(if panel.0 == screen.topic {
            PANEL_TOP
        } else {
            PANEL_OFFSCREEN_TOP
        });
    }
    for (entity, action, checked) in &controls {
        let selected = match *action {
            DiplomacyAction::Grant { row, recurring } => {
                screen.topic == DiplomacyTopic::Grants
                    && row == screen.grant_row
                    && recurring == screen.recurring_grant
            }
            DiplomacyAction::Trade(row) => {
                screen.topic == DiplomacyTopic::Trade
                    && !screen.colony_boycott
                    && row == screen.trade_row
            }
            DiplomacyAction::Treaty(row) => {
                screen.topic == DiplomacyTopic::Treaties && row == screen.treaty_row
            }
            DiplomacyAction::Overlay(mode) => {
                screen.topic == DiplomacyTopic::Information && screen.overlay == mode
            }
            DiplomacyAction::ColonyBoycott => {
                screen.topic == DiplomacyTopic::Trade && screen.colony_boycott
            }
            DiplomacyAction::Topic(_)
            | DiplomacyAction::AcceptOffer
            | DiplomacyAction::RejectOffer => continue,
        };
        set_checked(&mut commands, entity, checked.is_some(), selected);
    }
    for (bracket, mut image, mut visibility) in &mut brackets {
        let visible = bracket.left
            == matches!(
                screen.topic,
                DiplomacyTopic::Information | DiplomacyTopic::Council
            );
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        let picture = match screen.topic {
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
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = session.game.nations().major(source);
    for mut text in &mut treasury {
        text.0 = format_currency(major.common.treasury);
    }
    for mut text in &mut grant_totals {
        text.0 = format!(
            "Promised Grants: {}",
            format_currency(major.economy.grant_total_cost)
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn sync_diplomacy_offer_sheet(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    assets: RetailUiAssets,
    mut texts: Query<&mut Text, With<DiplomacyOfferText>>,
    mut sheets: Query<&mut Visibility, (With<DiplomacyOfferSheet>, Without<DiplomacyOfferWait>)>,
    mut waits: Query<&mut Visibility, (With<DiplomacyOfferWait>, Without<DiplomacyOfferSheet>)>,
    controls: Query<(Entity, &DiplomacyAction)>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let message = diplomacy_offer_message(&session.game, &assets);
    let posing = message.is_some();
    for mut visibility in &mut sheets {
        *visibility = if posing {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
    }
    for mut visibility in &mut waits {
        *visibility = Visibility::Hidden;
    }
    if let Some(message) = message {
        for mut text in &mut texts {
            text.0 = message.clone();
        }
    }
    for (entity, action) in &controls {
        if !matches!(
            *action,
            DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer
        ) {
            continue;
        }
        if posing {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    assets: Res<RetailAssetsResource>,
    mut information: Query<
        (&DiplomacyInfoText, &mut Text),
        (
            Without<DiplomacyNationLabel>,
            Without<DiplomacyMapKeyMajorName>,
            Without<DiplomacyCouncilText>,
        ),
    >,
    mut map_key_names: Query<
        (&DiplomacyMapKeyMajorName, &mut Text, &mut Visibility),
        Without<DiplomacyNationIcon>,
    >,
    mut map_keys: Query<(&DiplomacyMapKey, &mut ImageNode), Without<DiplomacyNationIcon>>,
    mut council_text: Query<
        (&DiplomacyCouncilText, &mut Text, &mut Visibility),
        (
            Without<DiplomacyInfoText>,
            Without<DiplomacyNationLabel>,
            Without<DiplomacyNationIcon>,
            Without<DiplomacyMapKeyMajorName>,
        ),
    >,
    mut labels: Query<
        (&DiplomacyNationLabel, &mut Text, &mut Node, &mut Visibility),
        (
            Without<DiplomacyNationIcon>,
            Without<DiplomacyMapKeyMajorName>,
            Without<DiplomacyInfoText>,
            Without<DiplomacyCouncilText>,
        ),
    >,
    mut icons: Query<
        (
            &DiplomacyNationIcon,
            &mut ImageNode,
            &mut Node,
            &mut Visibility,
        ),
        (Without<DiplomacyNationLabel>, Without<DiplomacyMapKey>),
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    let (name, labels_by_row, values_by_row) = diplomacy_information(state, screen.framed_nation);
    for (field, mut text) in &mut information {
        text.0 = match field.0 {
            DiplomacyInfoField::Name => name.clone(),
            DiplomacyInfoField::Label(row) => labels_by_row[usize::from(row)].clone(),
            DiplomacyInfoField::Value(row) => values_by_row[usize::from(row)].clone(),
        };
    }
    let show_map_key_names = screen.topic != DiplomacyTopic::Information || screen.overlay == 0;
    for (major, mut text, mut visibility) in &mut map_key_names {
        text.0.clear();
        text.0
            .push_str(state.nations().display_name(major.0.nation()).unwrap_or(""));
        *visibility = if show_map_key_names {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    for (map_key, mut image) in &mut map_keys {
        image.image = match screen.overlay {
            1 => map_key.relationship_notch.clone(),
            2 => map_key.trade.clone(),
            4 => map_key.relationship_type.clone(),
            _ => map_key.owner.clone(),
        };
    }
    let council = council_panel_text(state, &assets);
    for (field, mut text, mut visibility) in &mut council_text {
        match field.0 {
            0 => {
                text.0.clone_from(&council.title);
                *visibility = Visibility::Visible;
            }
            index => {
                let row = usize::from((index - 1) / 2);
                let is_value = index % 2 == 0;
                if let Some(rows) = &council.rows {
                    text.0
                        .clone_from(if is_value { &rows[row].1 } else { &rows[row].0 });
                    *visibility = Visibility::Visible;
                } else {
                    text.0.clear();
                    *visibility = Visibility::Hidden;
                }
            }
        }
    }

    for (label, mut text, mut node, mut visibility) in &mut labels {
        let Some(anchor) = representative_tile_for_nation(state, label.nation) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let Some(display_name) = state.nations().display_name(label.nation) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        if display_name.is_empty() {
            *visibility = Visibility::Hidden;
            continue;
        }
        let (row, column) = state.map().geometry().row_column(anchor);
        let is_major = MajorNationId::from_nation(label.nation).is_some();
        let offset = f32::from(if is_major == label.shadow { 1_u8 } else { 0 });
        node.left = Val::Px(f32::from(column) * 5.0 - 45.0 + offset);
        node.top = Val::Px(f32::from(row) * 5.0 - 6.0 + offset);
        text.0.clear();
        text.0.push_str(display_name);
        *visibility = Visibility::Visible;
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
    match state.diplomacy().relationships[framed][nation] {
        DiplomaticRelationship::Alliance => 0x22,
        DiplomaticRelationship::NonAggressionPact => 0x1b,
        DiplomaticRelationship::Peace => 0x21,
        DiplomaticRelationship::JoinedEmpire => 0x29,
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

    for index in 0..TileId::COUNT {
        let tile = TileId::new(index);
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
