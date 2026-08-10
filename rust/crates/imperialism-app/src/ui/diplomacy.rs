use super::catalog::{
    ModalDialog, SpawnedView, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view,
};
use super::game_shell::{GameScreenRoot, bind_game_screen_nav, diplomacy_view_id, disable_control};
use super::random_setup::GameSession;
use super::random_setup_map::{compose_owner_preview_indices, preview_image_from_indices};
use crate::AppState;
use bevy::log::warn;
use bevy::math::Rect;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
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

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    let view_id = diplomacy_view_id();
    catalog.require_unique_bindings(
        &view_id,
        &[
            fourcc!("main"),
            fourcc!("info"),
            fourcc!("mkey"),
            fourcc!("gran"),
            fourcc!("docs"),
            fourcc!("trty"),
            fourcc!("scro"),
            fourcc!("coun"),
            fourcc!("offr"),
            fourcc!("shee"),
            fourcc!("prop"),
            fourcc!("reje"),
            fourcc!("acce"),
            fourcc!("wait"),
            fourcc!("text"),
            fourcc!("quer"),
            fourcc!("ltab"),
            fourcc!("rtab"),
            fourcc!("inft"),
            fourcc!("cout"),
            fourcc!("trtt"),
            fourcc!("grat"),
            fourcc!("trat"),
            fourcc!("dipl"),
            fourcc!("trea"),
        ],
    )?;
    catalog.require_unique_bindings(
        &diplomacy_notice_view_id(),
        &[
            fourcc!("WIND"),
            fourcc!("DLOG"),
            fourcc!("titl"),
            fourcc!("okay"),
            fourcc!("cncl"),
            fourcc!("coat"),
            fourcc!("info"),
        ],
    )?;
    for tag in [
        fourcc!("ovr0"),
        fourcc!("ovr1"),
        fourcc!("ovr2"),
        fourcc!("ovr4"),
        fourcc!("doc0"),
        fourcc!("doc1"),
        fourcc!("doc2"),
        fourcc!("doc3"),
        fourcc!("doc4"),
        fourcc!("doc5"),
        fourcc!("doc6"),
        fourcc!("doc7"),
        fourcc!("scr0"),
        fourcc!("scr1"),
        fourcc!("scr2"),
        fourcc!("scr3"),
        fourcc!("scr4"),
        fourcc!("scr5"),
        fourcc!("scr6"),
        fourcc!("traa"),
        fourcc!("trab"),
        fourcc!("trac"),
        fourcc!("trad"),
        fourcc!("trae"),
        fourcc!("traf"),
        fourcc!("trag"),
        fourcc!("link"),
    ] {
        let parent = if tag.as_str().starts_with("doc") {
            fourcc!("docs")
        } else if tag.as_str().starts_with("scr") {
            fourcc!("scro")
        } else if tag.as_str().starts_with("tra") || tag == fourcc!("link") {
            fourcc!("clus")
        } else {
            fourcc!("info")
        };
        catalog.require_control_under(&view_id, tag, &[parent])?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiplomacyTopic {
    Information,
    Grants,
    Trade,
}

#[derive(Component, Clone, Copy)]
struct DiplomacyScreen {
    source: MajorNationId,
    framed_nation: NationId,
    topic: DiplomacyTopic,
    grant_row: usize,
    recurring_grant: bool,
    trade_row: usize,
}

#[derive(Component, Clone, Copy)]
struct DiplomacyTopicControl(DiplomacyTopic);

#[derive(Component, Clone, Copy)]
struct DiplomacyPanel(DiplomacyTopic);

#[derive(Component, Clone, Copy)]
struct DiplomacyGrantControl {
    row: usize,
    recurring: bool,
}

#[derive(Component, Clone, Copy)]
struct DiplomacyTradeControl(usize);

#[derive(Component)]
struct DiplomacyMapHit;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct DiplomacyMapSelection(NationId);

#[derive(Component, Default)]
struct DiplomacyMapPicture {
    rendered_selection: Option<NationId>,
    image: Option<Handle<Image>>,
}

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

#[derive(Clone, Copy, Debug, Event)]
struct OpenDiplomacyRejectionNotice {
    source: MajorNationId,
    rejection: PlayerDiplomacyRejection,
}

#[derive(Clone)]
struct DiplomacyTextStyles {
    title_font: TextFont,
    title_layout: TextLayout,
    row_font: TextFont,
    row_layout: TextLayout,
    map_font: TextFont,
    map_layout: TextLayout,
    key_font: TextFont,
    key_layout: TextLayout,
    foreground: Color,
    shadow: Color,
}

#[derive(Clone)]
struct DiplomacyBracketPictures {
    information: Handle<Image>,
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
        app.add_systems(OnEnter(AppState::Diplomacy), enter_diplomacy_screen)
            .add_systems(
                Update,
                (
                    sync_diplomacy_controls,
                    sync_diplomacy_information,
                    render_diplomacy_map,
                )
                    .chain()
                    .run_if(in_state(AppState::Diplomacy)),
            )
            .add_observer(on_diplomacy_activate)
            .add_observer(on_diplomacy_map_click)
            .add_observer(open_diplomacy_rejection_notice)
            .add_observer(on_diplomacy_notice_activate);
    }
}

fn diplomacy_notice_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Linger.rsrc".to_owned(),
        resource_id: 2020,
    }
}

fn enter_diplomacy_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    session: Option<Res<GameSession>>,
) {
    let view_id = diplomacy_view_id();
    let view = catalog
        .view(&view_id)
        .expect("validated diplomacy-screen catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(AppState::Diplomacy)));

    let Some(session) = session else {
        warn!("diplomacy screen opened without an authoritative game session");
        return;
    };
    let Some(source) = MajorNationId::from_nation(session.0.turn.active_nation) else {
        warn!(
            "diplomacy screen opened for non-major nation {:?}",
            session.0.turn.active_nation
        );
        return;
    };
    let pictures = DiplomacyBracketPictures {
        information: assets
            .picture(PictureId::new(5001))
            .expect("retail diplomacy information bracket must load"),
        grants: assets
            .picture(PictureId::new(5004))
            .expect("retail diplomacy grants bracket must load"),
        trade: assets
            .picture(PictureId::new(5005))
            .expect("retail diplomacy trade bracket must load"),
    };
    let (title_font, title_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 0,
        })
        .expect("retail diplomacy title text style");
    let (row_font, row_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy row text style");
    let (map_font, map_layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 10,
            alignment: 1,
        })
        .expect("retail diplomacy map label style");
    let (key_font, key_layout, _) = assets
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
        row_font,
        row_layout,
        map_font,
        map_layout,
        key_font,
        key_layout,
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
    bind_diplomacy_screen(
        &mut commands,
        &catalog,
        &spawned,
        source,
        pictures,
        styles,
        icon_atlas,
    );
}

fn bind_diplomacy_screen(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    source: MajorNationId,
    pictures: DiplomacyBracketPictures,
    styles: DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
) -> Entity {
    commands.entity(spawned.root).insert(DiplomacyScreen {
        source,
        framed_nation: source.nation(),
        topic: DiplomacyTopic::Information,
        grant_row: 0,
        recurring_grant: false,
        trade_row: 0,
    });

    let selected = spawned
        .require_under(catalog, fourcc!("topB"), fourcc!("dipl"))
        .expect("validated selected diplomacy binding");
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    disable_control(commands, spawned, fourcc!("quer"));

    for (tag, topic) in [
        (fourcc!("info"), DiplomacyTopic::Information),
        (fourcc!("gran"), DiplomacyTopic::Grants),
        (fourcc!("trad"), DiplomacyTopic::Trade),
    ] {
        let panel = require_direct_path(catalog, spawned, &[fourcc!("main"), tag]);
        commands.entity(panel).insert(DiplomacyPanel(topic));
    }

    for (tag, topic) in [
        (fourcc!("inft"), DiplomacyTopic::Information),
        (fourcc!("grat"), DiplomacyTopic::Grants),
        (fourcc!("trat"), DiplomacyTopic::Trade),
    ] {
        let control = spawned
            .require_unique(tag)
            .expect("validated diplomacy topic binding");
        commands
            .entity(control)
            .insert(DiplomacyTopicControl(topic))
            .remove::<InteractionDisabled>();
    }
    for tag in [fourcc!("trtt"), fourcc!("cout")] {
        disable_control(commands, spawned, tag);
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
        let control = spawned
            .require_unique(tag)
            .expect("validated diplomacy grant binding");
        commands.entity(control).insert(DiplomacyGrantControl {
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
        let control = require_direct_path(
            catalog,
            spawned,
            &[fourcc!("main"), fourcc!("trad"), fourcc!("clus"), tag],
        );
        commands
            .entity(control)
            .insert(DiplomacyTradeControl(index));
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
            require_direct_path(
                catalog,
                spawned,
                &[fourcc!("main"), fourcc!("trad"), fourcc!("clus"), tag],
            )
        } else {
            spawned
                .require_unique(tag)
                .expect("validated unsupported diplomacy control")
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
        let control = spawned
            .require_unique(tag)
            .expect("validated diplomacy default selection");
        if checked {
            commands.entity(control).insert(Checked);
        } else {
            commands.entity(control).remove::<Checked>();
        }
    }
    commands
        .entity(require_direct_path(
            catalog,
            spawned,
            &[
                fourcc!("main"),
                fourcc!("trad"),
                fourcc!("clus"),
                fourcc!("link"),
            ],
        ))
        .remove::<Checked>();

    let main = spawned
        .require_unique(fourcc!("main"))
        .expect("validated diplomacy map binding");
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
            DiplomacyMapHit,
            DiplomacyMapSelection(source.nation()),
            DiplomacyMapPicture::default(),
            ZIndex(1),
            ChildOf(main),
        ))
        .id();
    spawn_diplomacy_map_labels(commands, map, &styles, icon_atlas);
    spawn_diplomacy_panel_text(commands, catalog, spawned, &styles);

    let treasury = spawned
        .require_unique(fourcc!("trea"))
        .expect("validated diplomacy treasury binding");
    commands
        .entity(treasury)
        .insert((Text::new(""), DiplomacyTreasury));
    let left = spawned
        .require_unique(fourcc!("ltab"))
        .expect("validated diplomacy left bracket binding");
    commands.entity(left).insert((
        ImageNode::new(pictures.information.clone()),
        DiplomacyTopicBracket {
            left: true,
            pictures: pictures.clone(),
        },
    ));
    let right = spawned
        .require_unique(fourcc!("rtab"))
        .expect("validated diplomacy right bracket binding");
    commands.entity(right).insert((
        ImageNode::new(pictures.information.clone()),
        DiplomacyTopicBracket {
            left: false,
            pictures,
        },
    ));
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

fn spawn_diplomacy_panel_text(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    styles: &DiplomacyTextStyles,
) {
    let information = require_direct_path(catalog, spawned, &[fourcc!("main"), fourcc!("info")]);
    spawn_shadowed_text(
        commands,
        information,
        "Information:",
        15.0,
        13.0,
        95.0,
        &styles.title_font,
        &styles.title_layout,
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
            styles.foreground,
            styles.shadow,
        );
        for entity in value {
            commands
                .entity(entity)
                .insert(DiplomacyInfoText(DiplomacyInfoField::Value(row as u8)));
        }
    }

    let map_key = require_direct_path(
        catalog,
        spawned,
        &[fourcc!("main"), fourcc!("info"), fourcc!("mkey")],
    );
    let key_layout = styles.key_layout.with_justify(Justify::Center);
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
        styles.foreground,
        styles.shadow,
    );
    for (major, (left, top)) in (0..MajorNationId::COUNT).map(MajorNationId::new).zip([
        (44.0, 19.0),
        (44.0, 44.0),
        (44.0, 68.0),
        (44.0, 93.0),
        (153.0, 19.0),
        (153.0, 44.0),
        (153.0, 68.0),
    ]) {
        let names = spawn_shadowed_text(
            commands,
            map_key,
            "",
            left,
            top,
            70.0,
            &styles.key_font,
            &key_layout,
            styles.foreground,
            styles.shadow,
        );
        for (offset, entity) in names.into_iter().enumerate() {
            let offset = offset as f32;
            commands.entity(entity).insert((
                DiplomacyMapKeyMajorName(major),
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(left + offset),
                    top: Val::Px(top + offset),
                    width: Val::Px(70.0),
                    height: Val::Px(25.0),
                    ..default()
                },
            ));
        }
    }

    let grants = require_direct_path(catalog, spawned, &[fourcc!("main"), fourcc!("gran")]);
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
        let (font, layout) = if title {
            (&styles.title_font, &styles.title_layout)
        } else {
            (&styles.row_font, &styles.row_layout)
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
        styles.foreground,
        styles.shadow,
    );
    for entity in total {
        commands.entity(entity).insert(DiplomacyGrantTotal);
    }

    let trade = require_direct_path(catalog, spawned, &[fourcc!("main"), fourcc!("trad")]);
    for (text, left, top, title) in [
        ("Trade Policies", 15.0, 13.0, true),
        ("5%", 25.0, 85.0, false),
        ("10%", 74.0, 34.0, false),
        ("25%", 125.0, 85.0, false),
        ("50%", 177.0, 34.0, false),
        ("75%", 228.0, 85.0, false),
        ("100%", 275.0, 34.0, false),
    ] {
        let (font, layout) = if title {
            (&styles.title_font, &styles.title_layout)
        } else {
            (&styles.row_font, &styles.row_layout)
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

fn require_direct_path(
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    tags: &[FourCc],
) -> Entity {
    let view = catalog
        .view(&spawned.view_id)
        .expect("spawned diplomacy view remains cataloged");
    let mut parent = None;
    for (depth, &tag) in tags.iter().enumerate() {
        let mut matches = view
            .nodes
            .iter()
            .filter(|node| (depth == 0 || node.parent == parent) && node.tag == tag);
        let node = matches
            .next()
            .unwrap_or_else(|| panic!("missing direct diplomacy path element {tag}"));
        assert!(
            matches.next().is_none(),
            "ambiguous direct diplomacy path element {tag}"
        );
        parent = Some(node.id);
    }
    spawned.nodes[&parent.expect("diplomacy path is not empty")]
}

fn on_diplomacy_activate(
    activate: On<Activate>,
    topics: Query<&DiplomacyTopicControl>,
    grants: Query<&DiplomacyGrantControl>,
    trade: Query<&DiplomacyTradeControl>,
    mut screens: Query<&mut DiplomacyScreen>,
) {
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    if let Ok(topic) = topics.get(activate.entity) {
        if screen.topic == topic.0 {
            return;
        }
        screen.topic = topic.0;
        screen.framed_nation = screen.source.nation();
        match topic.0 {
            DiplomacyTopic::Information => {}
            DiplomacyTopic::Grants => {
                screen.grant_row = 0;
                screen.recurring_grant = false;
            }
            DiplomacyTopic::Trade => screen.trade_row = 0,
        }
    } else if let Ok(grant) = grants.get(activate.entity) {
        screen.grant_row = grant.row;
        screen.recurring_grant = grant.recurring;
    } else if let Ok(trade) = trade.get(activate.entity) {
        screen.trade_row = trade.0;
    }
}

fn on_diplomacy_map_click(
    click: On<Pointer<Click>>,
    maps: Query<(&RelativeCursorPosition, &DiplomacyMapHit)>,
    modals: Query<(), With<ModalDialog>>,
    mut screens: Query<&mut DiplomacyScreen>,
    session: Option<ResMut<GameSession>>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok((cursor, _)) = maps.get(click.entity) else {
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
    let Some(mut session) = session else {
        return;
    };
    let Some(target) = session.0.world[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return;
    };
    let Ok(mut screen) = screens.single_mut() else {
        return;
    };
    if let Some(rejection) = apply_diplomacy_target(&mut screen, &mut session.0, target) {
        commands.trigger(OpenDiplomacyRejectionNotice {
            source: screen.source,
            rejection,
        });
    }
}

fn apply_diplomacy_target(
    screen: &mut DiplomacyScreen,
    state: &mut GameState,
    target: NationId,
) -> Option<PlayerDiplomacyRejection> {
    match screen.topic {
        DiplomacyTopic::Information => {
            screen.framed_nation = target;
            None
        }
        DiplomacyTopic::Grants => match state.toggle_player_diplomacy_grant(
            screen.source,
            target,
            DiplomacyGrant {
                amount: GRANT_AMOUNTS[screen.grant_row],
                recurring: screen.recurring_grant,
            },
        ) {
            PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
            PlayerDiplomacyOrderResult::Applied | PlayerDiplomacyOrderResult::SelectedNation => {
                None
            }
        },
        DiplomacyTopic::Trade => match state.toggle_player_trade_policy(
            screen.source,
            target,
            TRADE_POLICY_SCORES[screen.trade_row],
        ) {
            PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
            PlayerDiplomacyOrderResult::Applied | PlayerDiplomacyOrderResult::SelectedNation => {
                None
            }
        },
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

fn open_diplomacy_rejection_notice(request: On<OpenDiplomacyRejectionNotice>, mut ui: UiSpawner) {
    let spawned = ui.spawn_modal(diplomacy_notice_view_id());
    let notice_color = TextColor(ui.palette_color(0));
    ui.commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::Diplomacy));
    let title = spawned
        .require_unique(fourcc!("titl"))
        .expect("validated diplomacy notice title");
    let (title_font, title_layout, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail diplomacy notice title style");
    ui.commands.entity(title).insert((
        Text::new("Report from your\nForeign Minister\n\n"),
        title_font,
        title_layout,
        notice_color,
    ));
    let body = spawned
        .require_unique(fourcc!("info"))
        .expect("validated diplomacy notice body");
    let (body_font, body_layout, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy notice body style");
    ui.commands.entity(body).insert((
        Text::new(diplomacy_rejection_text(request.rejection)),
        body_font,
        body_layout,
        notice_color,
    ));
    let coat = spawned
        .require_unique(fourcc!("coat"))
        .expect("validated diplomacy notice coat");
    let coat_picture = PictureId::new(9500 + i16::from(request.source.get()));
    if let Ok(image) = ui.picture(coat_picture) {
        ui.commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = spawned
        .require_unique(fourcc!("okay"))
        .expect("validated diplomacy notice confirmation");
    ui.commands
        .entity(okay)
        .insert(DiplomacyNoticeClose(spawned.root))
        .remove::<InteractionDisabled>();
    let cancel = spawned
        .require_unique(fourcc!("cncl"))
        .expect("validated diplomacy notice cancel control");
    ui.commands.entity(cancel).insert(Visibility::Hidden);
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
    screens: Query<&DiplomacyScreen>,
    mut panels: Query<(&DiplomacyPanel, &mut Node)>,
    grant_controls: Query<(Entity, &DiplomacyGrantControl, Option<&Checked>)>,
    trade_controls: Query<(Entity, &DiplomacyTradeControl, Option<&Checked>)>,
    mut brackets: Query<(&DiplomacyTopicBracket, &mut ImageNode, &mut Visibility)>,
    mut selections: Query<&mut DiplomacyMapSelection>,
    mut treasury: Query<&mut Text, With<DiplomacyTreasury>>,
    mut grant_totals: Query<&mut Text, (With<DiplomacyGrantTotal>, Without<DiplomacyTreasury>)>,
) {
    let Ok(screen) = screens.single() else {
        return;
    };
    for (panel, mut node) in &mut panels {
        node.top = Val::Px(if panel.0 == screen.topic {
            PANEL_TOP
        } else {
            PANEL_OFFSCREEN_TOP
        });
    }
    for (entity, control, checked) in &grant_controls {
        set_checked(
            &mut commands,
            entity,
            checked.is_some(),
            screen.topic == DiplomacyTopic::Grants
                && control.row == screen.grant_row
                && control.recurring == screen.recurring_grant,
        );
    }
    for (entity, control, checked) in &trade_controls {
        set_checked(
            &mut commands,
            entity,
            checked.is_some(),
            screen.topic == DiplomacyTopic::Trade && control.0 == screen.trade_row,
        );
    }
    for (bracket, mut image, mut visibility) in &mut brackets {
        let visible = bracket.left == (screen.topic == DiplomacyTopic::Information);
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        image.image = match screen.topic {
            DiplomacyTopic::Information => bracket.pictures.information.clone(),
            DiplomacyTopic::Grants => bracket.pictures.grants.clone(),
            DiplomacyTopic::Trade => bracket.pictures.trade.clone(),
        };
    }
    for mut selection in &mut selections {
        if selection.0 != screen.framed_nation {
            selection.0 = screen.framed_nation;
        }
    }
    let major = session.0.nations.major(screen.source);
    for mut text in &mut treasury {
        text.0 = format_currency(major.common().treasury);
    }
    for mut text in &mut grant_totals {
        text.0 = format!(
            "Promised Grants: {}",
            format_currency(major.economy().grant_total_cost)
        );
    }
}

#[allow(clippy::type_complexity)]
fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<&DiplomacyScreen>,
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
    let Ok(screen) = screens.single() else {
        return;
    };
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
            .push_str(state.nations.display_name(major.0.nation()).unwrap_or(""));
    }

    for (label, mut text, mut node, mut visibility) in &mut labels {
        let Some(anchor) = representative_tile_for_nation(state, label.nation) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let Some(display_name) = state.nations.display_name(label.nation) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        if display_name.is_empty() {
            *visibility = Visibility::Hidden;
            continue;
        }
        let (row, column) = state.world.geometry().row_column(anchor);
        let is_major = MajorNationId::from_nation(label.nation).is_some();
        let offset = f32::from(if is_major == label.shadow { 1_u8 } else { 0 });
        node.left = Val::Px(f32::from(column) * 5.0 - 45.0 + offset);
        node.top = Val::Px(f32::from(row) * 5.0 - 6.0 + offset);
        text.0.clear();
        text.0.push_str(display_name);
        *visibility = Visibility::Visible;
    }

    let major = state.nations.major(screen.source);
    for (icon, mut image, mut node, mut visibility) in &mut icons {
        let (anchor, atlas_offset, top_offset) = match icon.kind {
            DiplomacyNationIconKind::Compatibility => {
                let level = state.diplomacy.mission_levels[screen.framed_nation][icon.nation];
                let atlas_offset = match (screen.topic, level) {
                    (DiplomacyTopic::Information, _) | (_, DiplomaticMissionLevel::None) => None,
                    (_, DiplomaticMissionLevel::TradeConsulate) => Some(0x170),
                    (_, DiplomaticMissionLevel::Embassy) => Some(0x180),
                };
                (state.nations.home_tile(icon.nation), atlas_offset, -8.0)
            }
            DiplomacyNationIconKind::Order => {
                let atlas_offset = match screen.topic {
                    DiplomacyTopic::Information => None,
                    DiplomacyTopic::Grants => major.economy().diplomacy_grants_by_nation
                        [icon.nation]
                        .and_then(diplomacy_grant_icon_offset),
                    DiplomacyTopic::Trade => {
                        let policy = major.common().trade_policy_by_nation[icon.nation];
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
        let (row, column) = state.world.geometry().row_column(anchor);
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
    mut assets: UiAssetResources,
    mut maps: Query<(
        Entity,
        &DiplomacyMapSelection,
        &mut DiplomacyMapPicture,
        Option<&mut ImageNode>,
    )>,
) {
    for (entity, selection, mut picture, image_node) in &mut maps {
        if !session.is_changed() && picture.rendered_selection == Some(selection.0) {
            continue;
        }
        let pixels =
            compose_owner_preview_indices(|tile| session.0.world[tile].owner_nation, selection.0);
        let image = preview_image_from_indices(&pixels, assets.default_dib_palette());
        let handle = if let Some(handle) = &picture.image {
            assets.replace_image(handle, image);
            handle.clone()
        } else {
            let handle = assets.add_image(image);
            picture.image = Some(handle.clone());
            handle
        };
        if let Some(mut image_node) = image_node {
            image_node.image = handle;
            image_node.rect = None;
        } else {
            commands.entity(entity).insert(ImageNode::new(handle));
        }
        picture.rendered_selection = Some(selection.0);
    }
}

fn diplomacy_information(
    state: &GameState,
    nation: NationId,
) -> (String, [String; 3], [String; 3]) {
    let name = state
        .nations
        .display_name(nation)
        .unwrap_or_default()
        .to_owned();
    let mut labels = ["Provinces:".to_owned(), String::new(), String::new()];
    let mut values = [
        state
            .nations
            .owned_region_count(nation)
            .unwrap_or_default()
            .to_string(),
        String::new(),
        String::new(),
    ];
    match state.nations.country_status(nation) {
        Some(CountryStatus::ColonyOf(master)) => {
            let master = state.nations.display_name(master).unwrap_or_default();
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
                    .and_then(|partner| state.nations.display_name(partner.nation()))
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
        .nations
        .home_tile(nation)
        .and_then(|tile| state.world[tile].province)
        .and_then(|province| state.provinces[province].region_class());
    let geometry = state.world.geometry();
    let mut column_sum = 0_u32;
    let mut row_sum = 0_u32;
    let mut tile_count = 0_u32;
    let mut west_count = 0_u32;
    let mut east_count = 0_u32;
    let mut fallback = None;

    for index in 0..TileId::COUNT {
        let tile = TileId::new(index);
        if state.world[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
            != Some(nation)
        {
            continue;
        }
        fallback = Some(tile);
        if let Some(home_region_class) = home_region_class
            && state.world[tile]
                .province
                .and_then(|province| state.provinces[province].region_class())
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
        return (state.nations.owned_region_count(nation).unwrap_or_default() > 0)
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

fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::camera::NormalizedRenderTarget;
    use bevy::picking::{
        backend::HitData,
        pointer::{Location, PointerId},
    };
    use std::time::Duration;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    #[derive(Clone, Copy, Resource)]
    struct TestDiplomacy {
        root: Entity,
        map: Entity,
        selected: Entity,
        return_to_map: Entity,
        query: Entity,
        grants_topic: Entity,
        recurring_three_thousand: Entity,
        trade_topic: Entity,
        trade_ten_percent: Entity,
    }

    fn fixture_session() -> GameSession {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME).unwrap();
        let state = save
            .game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 3_916_827_792,
                selected_nation: NationId::new(6),
            })
            .unwrap();
        GameSession(state)
    }

    fn enter_test_diplomacy(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        session: Res<GameSession>,
    ) {
        let view = catalog.view(&diplomacy_view_id()).unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_game_screen_nav(&mut commands, &catalog, &spawned);
        commands.entity(spawned.root).insert((
            GameScreenRoot(diplomacy_view_id()),
            DespawnOnExit(AppState::Diplomacy),
        ));
        let source = MajorNationId::from_nation(session.0.turn.active_nation).unwrap();
        let map = bind_diplomacy_screen(
            &mut commands,
            &catalog,
            &spawned,
            source,
            DiplomacyBracketPictures {
                information: Handle::default(),
                grants: Handle::default(),
                trade: Handle::default(),
            },
            DiplomacyTextStyles {
                title_font: TextFont::default(),
                title_layout: TextLayout::default(),
                row_font: TextFont::default(),
                row_layout: TextLayout::default(),
                map_font: TextFont::default(),
                map_layout: TextLayout::default(),
                key_font: TextFont::default(),
                key_layout: TextLayout::default(),
                foreground: Color::WHITE,
                shadow: Color::BLACK,
            },
            Handle::default(),
        );
        commands.insert_resource(TestDiplomacy {
            root: spawned.root,
            map,
            selected: spawned
                .require_under(&catalog, fourcc!("topB"), fourcc!("dipl"))
                .unwrap(),
            return_to_map: spawned.require_unique(fourcc!("end ")).unwrap(),
            query: spawned.require_unique(fourcc!("quer")).unwrap(),
            grants_topic: spawned.require_unique(fourcc!("grat")).unwrap(),
            recurring_three_thousand: spawned.require_unique(fourcc!("doc3")).unwrap(),
            trade_topic: spawned.require_unique(fourcc!("trat")).unwrap(),
            trade_ten_percent: spawned.require_unique(fourcc!("trab")).unwrap(),
        });
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    fn click_nation_two(app: &mut App, map: Entity) {
        let target = NationId::new(2);
        let (row, column) = {
            let session = app.world().resource::<GameSession>();
            let (tile_index, _) = session
                .0
                .world
                .iter()
                .enumerate()
                .find(|(index, tile)| {
                    let row = *index as u16 / STRATEGIC_MAP_WIDTH;
                    row & 1 != 0 && tile.owner_nation.and_then(TileOwnerTag::nation) == Some(target)
                })
                .expect("fixture nation 2 has territory on an odd map row");
            session
                .0
                .world
                .geometry()
                .row_column(TileId::new(tile_index as u16))
        };
        let x = f32::from(column * MAP_TILE_SCALE + MAP_ODD_ROW_OFFSET + 2);
        let y = f32::from(row * MAP_TILE_SCALE + 2);
        let normalized = Vec2::new((x + 0.5) / MAP_WIDTH - 0.5, (y + 0.5) / MAP_HEIGHT - 0.5);
        *app.world_mut()
            .get_mut::<RelativeCursorPosition>(map)
            .unwrap() = RelativeCursorPosition {
            cursor_over: true,
            normalized: Some(normalized),
        };
        app.world_mut().commands().trigger(Pointer::new(
            PointerId::Mouse,
            Location {
                target: NormalizedRenderTarget::None {
                    width: 640,
                    height: 480,
                },
                position: Vec2::new(MAP_LEFT + x + 0.5, MAP_TOP + y + 0.5),
            },
            Click {
                button: PointerButton::Primary,
                hit: HitData::new(Entity::PLACEHOLDER, 0.0, None, None),
                duration: Duration::ZERO,
                count: 1,
            },
            map,
        ));
        app.world_mut().flush();
        app.update();
    }

    fn treasury_text(app: &mut App) -> String {
        let mut query = app
            .world_mut()
            .query_filtered::<&Text, With<DiplomacyTreasury>>();
        query.single(app.world()).unwrap().0.clone()
    }

    fn grant_total_text(app: &mut App) -> String {
        let world = app.world_mut();
        let mut query = world.query_filtered::<&Text, With<DiplomacyGrantTotal>>();
        let texts = query
            .iter(world)
            .map(|text| text.0.clone())
            .collect::<Vec<_>>();
        assert_eq!(texts.len(), 2);
        assert_eq!(texts[0], texts[1]);
        texts[0].clone()
    }

    fn order_icon(app: &mut App, nation: NationId) -> (Visibility, Option<Rect>) {
        let world = app.world_mut();
        let mut query = world.query::<(&DiplomacyNationIcon, &Visibility, &ImageNode)>();
        query
            .iter(world)
            .find(|(icon, _, _)| {
                icon.nation == nation && icon.kind == DiplomacyNationIconKind::Order
            })
            .map(|(_, visibility, image)| (*visibility, image.rect))
            .unwrap()
    }

    #[test]
    fn player_orders_use_the_map_pointer_and_survive_state_reentry() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(fixture_session())
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .add_observer(on_diplomacy_activate)
            .add_observer(on_diplomacy_map_click)
            .add_systems(OnEnter(AppState::Diplomacy), enter_test_diplomacy)
            .add_systems(
                Update,
                (sync_diplomacy_controls, sync_diplomacy_information)
                    .chain()
                    .run_if(in_state(AppState::Diplomacy)),
            );

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::Diplomacy);
        app.update();
        app.update();

        let first = *app.world().resource::<TestDiplomacy>();
        assert!(app.world().get::<Checked>(first.selected).is_some());
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.selected)
                .is_some()
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.return_to_map)
                .is_none()
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.query)
                .is_some()
        );
        assert_eq!(treasury_text(&mut app), "$10,000");
        {
            let world = app.world_mut();
            let mut query = world.query::<(&DiplomacyMapKeyMajorName, &Text)>();
            let mut names: [Vec<String>; MajorNationId::COUNT as usize] =
                std::array::from_fn(|_| Vec::new());
            for (major, text) in query.iter(world) {
                names[usize::from(major.0.get())].push(text.0.clone());
            }
            for major in (0..MajorNationId::COUNT).map(MajorNationId::new) {
                assert_eq!(
                    names[usize::from(major.get())],
                    vec![
                        world
                            .resource::<GameSession>()
                            .0
                            .nations
                            .display_name(major.nation())
                            .unwrap()
                            .to_owned();
                        2
                    ]
                );
            }
        }

        click_nation_two(&mut app, first.map);
        assert_eq!(
            app.world().get::<DiplomacyMapSelection>(first.map),
            Some(&DiplomacyMapSelection(NationId::new(2)))
        );
        let target_name = app
            .world()
            .resource::<GameSession>()
            .0
            .nations
            .display_name(NationId::new(2))
            .unwrap()
            .to_owned();
        let displayed_names = {
            let world = app.world_mut();
            let mut query = world.query::<(&DiplomacyInfoText, &Text)>();
            query
                .iter(world)
                .filter_map(|(field, text)| {
                    matches!(field.0, DiplomacyInfoField::Name).then_some(text.0.clone())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(displayed_names, vec![target_name.clone(), target_name]);

        activate(&mut app, first.grants_topic);
        activate(&mut app, first.recurring_three_thousand);
        click_nation_two(&mut app, first.map);

        let source = MajorNationId::new(6);
        let target = NationId::new(2);
        let expected = DiplomacyGrant {
            amount: 3_000,
            recurring: true,
        };
        {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations.major(source);
            assert_eq!(
                major.economy().diplomacy_grants_by_nation[target],
                Some(expected)
            );
            assert_eq!(major.economy().grant_total_cost, 3_000);
            assert_eq!(major.common().treasury, 7_000);
        }
        assert_eq!(treasury_text(&mut app), "$7,000");
        assert_eq!(grant_total_text(&mut app), "Promised Grants: $3,000");
        assert_eq!(
            order_icon(&mut app, target),
            (
                Visibility::Visible,
                Some(Rect::new(288.0, 0.0, 304.0, 16.0))
            )
        );

        activate(&mut app, first.trade_topic);
        activate(&mut app, first.trade_ten_percent);
        click_nation_two(&mut app, first.map);
        {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations.major(source);
            assert_eq!(
                major.common().trade_policy_by_nation[target],
                TradePolicyScore::new(90)
            );
            assert_eq!(major.common().treasury, 7_000);
            assert_eq!(
                major.economy().diplomacy_grants_by_nation[target],
                Some(expected)
            );
        }
        assert_eq!(
            order_icon(&mut app, target),
            (Visibility::Visible, Some(Rect::new(96.0, 0.0, 112.0, 16.0)))
        );
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::StrategicMap);
        app.update();
        app.update();
        assert!(app.world().get_entity(first.root).is_err());

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::Diplomacy);
        app.update();
        app.update();
        let reopened = *app.world().resource::<TestDiplomacy>();
        assert_ne!(reopened.root, first.root);
        let session = app.world().resource::<GameSession>();
        assert_eq!(
            session
                .0
                .nations
                .major(source)
                .economy()
                .diplomacy_grants_by_nation[target],
            Some(expected)
        );
        assert_eq!(
            session
                .0
                .nations
                .major(source)
                .common()
                .trade_policy_by_nation[target],
            TradePolicyScore::new(90)
        );
        let topic = {
            let world = app.world_mut();
            let mut screens = world.query::<&DiplomacyScreen>();
            screens.single(world).unwrap().topic
        };
        assert_eq!(topic, DiplomacyTopic::Information);
    }
}
