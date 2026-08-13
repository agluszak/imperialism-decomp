use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::bind_native_game_screen_nav;
use super::generated;
use super::random_setup::GameSession;
use super::random_setup_map::{compose_owner_preview_indices, preview_image_from_indices};
use super::retail::ModalDialog;
use super::retail::{RetailTag, find_child, find_descendant};
use crate::AppState;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, Button as UiButton};
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
}

#[derive(Component, Clone, Copy)]
struct DiplomacyPanel(DiplomacyTopic);

#[derive(Component, Clone, Copy)]
enum DiplomacyAction {
    Topic(DiplomacyTopic),
    Grant { row: usize, recurring: bool },
    Trade(usize),
}

#[derive(Component)]
struct DiplomacyMapPicture;

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

#[derive(Component)]
struct DiplomacyGrantTotal;

#[derive(Component)]
struct DiplomacyNoticeClose(Entity);

#[derive(Component)]
struct DiplomacyNotice(PlayerDiplomacyRejection);

#[derive(Clone, Copy, Debug, Event)]
struct OpenDiplomacyRejectionNotice {
    rejection: PlayerDiplomacyRejection,
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
    offers: Handle<Image>,
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
                sync_diplomacy_controls,
                sync_diplomacy_information,
                render_diplomacy_map,
            )
                .chain()
                .run_if(in_state(AppState::Diplomacy)),
        )
        .add_observer(on_diplomacy_activate.run_if(in_state(AppState::Diplomacy)))
        .add_observer(on_diplomacy_map_click.run_if(in_state(AppState::Diplomacy)))
        .add_observer(open_diplomacy_rejection_notice.run_if(in_state(AppState::Diplomacy)))
        .add_observer(on_diplomacy_notice_activate);
    }
}

fn enter_diplomacy_screen(mut commands: Commands, session: Res<GameSession>) {
    let root = commands.spawn_scene(generated::diplo_2008()).id();
    let source = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    commands.entity(root).insert((
        DiplomacyScreen {
            framed_nation: source.nation(),
            topic: DiplomacyTopic::Information,
            grant_row: 0,
            recurring_grant: false,
            trade_row: 0,
        },
        DespawnOnExit(AppState::Diplomacy),
    ));
}

fn bind_diplomacy_screen(
    mut commands: Commands,
    root: Single<Entity, Added<DiplomacyScreen>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
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
        offers: assets
            .picture(PictureId::new(5007))
            .expect("retail diplomacy offers bracket must load"),
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
    );
}

fn bind_diplomacy_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    pictures: DiplomacyBracketPictures,
    styles: DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
) -> Entity {
    bind_native_game_screen_nav(
        commands,
        root,
        children,
        tags,
        fourcc!("topB"),
        Some(fourcc!("too3")),
    );
    let top = find_descendant(root, fourcc!("topB"), children, tags);
    let selected = find_descendant(top, fourcc!("dipl"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    commands
        .entity(find_descendant(root, fourcc!("quer"), children, tags))
        .insert(InteractionDisabled);

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

    for tag in [
        fourcc!("ovr0"),
        fourcc!("ovr1"),
        fourcc!("ovr2"),
        fourcc!("ovr4"),
        fourcc!("scr0"),
        fourcc!("scr1"),
        fourcc!("scr2"),
        fourcc!("scr3"),
        fourcc!("scr4"),
        fourcc!("scr5"),
        fourcc!("scr6"),
        fourcc!("link"),
        fourcc!("reje"),
        fourcc!("acce"),
    ] {
        let control = if tag == fourcc!("link") {
            find_descendant(trade_cluster, tag, children, tags)
        } else {
            find_descendant(root, tag, children, tags)
        };
        commands.entity(control).insert(InteractionDisabled);
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
        grants,
        trade,
        &styles,
    );

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
    grants: Entity,
    trade: Entity,
    styles: &DiplomacyTextStyles,
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
            .insert(DiplomacyMapKeyMajorName(major));
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
            if screen.topic == topic {
                return;
            }
            screen.topic = topic;
            screen.framed_nation = MajorNationId::from_nation(session.0.turn().active_nation)
                .expect("Diplomacy screen requires an active major nation")
                .nation();
            match topic {
                DiplomacyTopic::Information
                | DiplomacyTopic::Treaties
                | DiplomacyTopic::Council
                | DiplomacyTopic::Offers => {}
                DiplomacyTopic::Grants => {
                    screen.grant_row = 0;
                    screen.recurring_grant = false;
                }
                DiplomacyTopic::Trade => screen.trade_row = 0,
            }
        }
        DiplomacyAction::Grant { row, recurring } => {
            if screen.grant_row != row || screen.recurring_grant != recurring {
                screen.grant_row = row;
                screen.recurring_grant = recurring;
            }
        }
        DiplomacyAction::Trade(row) if screen.trade_row != row => {
            screen.trade_row = row;
        }
        DiplomacyAction::Trade(_) => {}
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
    let Some(target) = session.0.map[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return;
    };
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy map has one open Diplomacy screen");
    let source = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let rejection =
        match screen.topic {
            DiplomacyTopic::Information => {
                if screen.framed_nation != target {
                    screen.framed_nation = target;
                }
                None
            }
            DiplomacyTopic::Treaties | DiplomacyTopic::Council | DiplomacyTopic::Offers => {
                if screen.framed_nation != target {
                    screen.framed_nation = target;
                }
                None
            }
            DiplomacyTopic::Grants => match session.0.toggle_player_diplomacy_grant(
                source,
                target,
                DiplomacyGrant {
                    amount: GRANT_AMOUNTS[screen.grant_row],
                    recurring: screen.recurring_grant,
                },
            ) {
                PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
                PlayerDiplomacyOrderResult::Applied
                | PlayerDiplomacyOrderResult::SelectedNation => None,
            },
            DiplomacyTopic::Trade => match session.0.toggle_player_trade_policy(
                source,
                target,
                TRADE_POLICY_SCORES[screen.trade_row],
            ) {
                PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
                PlayerDiplomacyOrderResult::Applied
                | PlayerDiplomacyOrderResult::SelectedNation => None,
            },
        };
    if let Some(rejection) = rejection {
        commands.trigger(OpenDiplomacyRejectionNotice { rejection });
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
    closes: Query<&DiplomacyNoticeClose>,
    mut commands: Commands,
) {
    let Ok(close) = closes.get(activate.entity) else {
        return;
    };
    commands.entity(close.0).despawn();
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
        Text::new(diplomacy_rejection_text(notice.0)),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let coat = find_descendant(root, fourcc!("coat"), &children, &tags);
    let source = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .insert(DiplomacyNoticeClose(root))
        .remove::<InteractionDisabled>();
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    commands.entity(cancel).insert(Visibility::Hidden);
}

fn diplomacy_rejection_text(rejection: PlayerDiplomacyRejection) -> &'static str {
    match rejection {
        PlayerDiplomacyRejection::TargetIsNotIndependent => {
            "Your Excellency, we cannot make diplomatic overtures directly to a colony. We must approach its ruling Great Power."
        }
        PlayerDiplomacyRejection::EmbassyRequired => {
            "Your Excellency, we must establish an embassy before we can propose such an elaborate treaty."
        }
        PlayerDiplomacyRejection::TradeConsulateRequired => {
            "Your excellency, we must establish a trade consulate before we can propose complex trade agreements."
        }
        PlayerDiplomacyRejection::AlliedNationCannotBeBoycotted => {
            "We cannot boycott one of our allies, Your Excellency."
        }
        PlayerDiplomacyRejection::InsufficientGrantFunds => {
            "Unfortunately Your Excellency, we do not have enough money to offer so large a grant."
        }
    }
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
                screen.topic == DiplomacyTopic::Trade && row == screen.trade_row
            }
            DiplomacyAction::Topic(_) => continue,
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
        image.image = match screen.topic {
            DiplomacyTopic::Information => bracket.pictures.information.clone(),
            DiplomacyTopic::Treaties => bracket.pictures.treaties.clone(),
            DiplomacyTopic::Grants => bracket.pictures.grants.clone(),
            DiplomacyTopic::Trade => bracket.pictures.trade.clone(),
            DiplomacyTopic::Council => bracket.pictures.council.clone(),
            DiplomacyTopic::Offers => bracket.pictures.offers.clone(),
        };
    }
    let source = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = session.0.nations().major(source);
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

#[allow(clippy::type_complexity)]
fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut information: Query<
        (&DiplomacyInfoText, &mut Text),
        (
            Without<DiplomacyNationLabel>,
            Without<DiplomacyMapKeyMajorName>,
        ),
    >,
    mut map_key_names: Query<
        (&DiplomacyMapKeyMajorName, &mut Text),
        (Without<DiplomacyInfoText>, Without<DiplomacyNationLabel>),
    >,
    mut labels: Query<
        (&DiplomacyNationLabel, &mut Text, &mut Node, &mut Visibility),
        (
            Without<DiplomacyNationIcon>,
            Without<DiplomacyMapKeyMajorName>,
        ),
    >,
    mut icons: Query<
        (
            &DiplomacyNationIcon,
            &mut ImageNode,
            &mut Node,
            &mut Visibility,
        ),
        Without<DiplomacyNationLabel>,
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.0;
    let (name, labels_by_row, values_by_row) = diplomacy_information(state, screen.framed_nation);
    for (field, mut text) in &mut information {
        text.0 = match field.0 {
            DiplomacyInfoField::Name => name.clone(),
            DiplomacyInfoField::Label(row) => labels_by_row[usize::from(row)].clone(),
            DiplomacyInfoField::Value(row) => values_by_row[usize::from(row)].clone(),
        };
    }
    for (major, mut text) in &mut map_key_names {
        text.0.clear();
        text.0
            .push_str(state.nations().display_name(major.0.nation()).unwrap_or(""));
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
        let (row, column) = state.map.geometry().row_column(anchor);
        let is_major = MajorNationId::from_nation(label.nation).is_some();
        let offset = f32::from(if is_major == label.shadow { 1_u8 } else { 0 });
        node.left = Val::Px(f32::from(column) * 5.0 - 45.0 + offset);
        node.top = Val::Px(f32::from(row) * 5.0 - 6.0 + offset);
        text.0.clear();
        text.0.push_str(display_name);
        *visibility = Visibility::Visible;
    }

    let source = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = state.nations().major(source);
    for (icon, mut image, mut node, mut visibility) in &mut icons {
        let (anchor, atlas_offset, top_offset) = match icon.kind {
            DiplomacyNationIconKind::Compatibility => {
                let level = state.diplomacy().mission_levels[screen.framed_nation][icon.nation];
                let atlas_offset = match (screen.topic, level) {
                    (DiplomacyTopic::Information | DiplomacyTopic::Offers, _)
                    | (_, DiplomaticMissionLevel::None) => None,
                    (_, DiplomaticMissionLevel::TradeConsulate) => Some(0x170),
                    (_, DiplomaticMissionLevel::Embassy) => Some(0x180),
                };
                (state.nations().home_tile(icon.nation), atlas_offset, -8.0)
            }
            DiplomacyNationIconKind::Order => {
                let atlas_offset = match screen.topic {
                    DiplomacyTopic::Information
                    | DiplomacyTopic::Treaties
                    | DiplomacyTopic::Council
                    | DiplomacyTopic::Offers => None,
                    DiplomacyTopic::Grants => major.economy.diplomacy_grants_by_nation[icon.nation]
                        .and_then(diplomacy_grant_icon_offset),
                    DiplomacyTopic::Trade => {
                        let policy = major.common.trade_policy_by_nation[icon.nation];
                        TRADE_POLICY_SCORES
                            .iter()
                            .position(|candidate| *candidate == policy)
                            .map(|row| (row + 5) * 16)
                    }
                };
                (
                    representative_tile_for_nation(state, icon.nation),
                    atlas_offset,
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
        let (row, column) = state.map.geometry().row_column(anchor);
        node.left = Val::Px(f32::from(column) * 5.0 - 8.0);
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
    screens: Query<Ref<DiplomacyScreen>>,
    maps: Query<(Entity, Option<&ImageNode>), With<DiplomacyMapPicture>>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let (entity, image_node) = maps.single().expect("Diplomacy screen has one map picture");
    let pixels = compose_owner_preview_indices(
        |tile| session.0.map[tile].owner_nation,
        screen.framed_nation,
    );
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

fn representative_tile_for_nation(state: &GameState, nation: NationId) -> Option<TileId> {
    let home_region_class = state
        .nations()
        .home_tile(nation)
        .and_then(|tile| state.map[tile].province)
        .and_then(|province| state.map.provinces[province].region_class);
    let geometry = state.map.geometry();
    let mut column_sum = 0_u32;
    let mut row_sum = 0_u32;
    let mut tile_count = 0_u32;
    let mut west_count = 0_u32;
    let mut east_count = 0_u32;
    let mut fallback = None;

    for index in 0..TileId::COUNT {
        let tile = TileId::new(index);
        if state.map[tile].owner_nation.and_then(TileOwnerTag::nation) != Some(nation) {
            continue;
        }
        fallback = Some(tile);
        if let Some(home_region_class) = home_region_class
            && state.map[tile]
                .province
                .and_then(|province| state.map.provinces[province].region_class)
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
