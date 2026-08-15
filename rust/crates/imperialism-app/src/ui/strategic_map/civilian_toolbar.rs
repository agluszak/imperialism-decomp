//! Right-hand civilian command page (`uciv` / `TCivToolbar` + `TCivDescription`).

use super::super::format_currency;
use super::super::retail::{RetailTree, RetailUiAssets};
use super::civilian_orders::StrategicSelection;
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_core::*;
use imperialism_formats::*;

const PAGE_TAG: FourCc = fourcc!("uciv");
const PORTRAIT_TAG: FourCc = fourcc!("unit");
const LEGEND_TAG: FourCc = fourcc!("back");
const CIVILIAN_PAGE_VISIBLE: Vec2 = Vec2::new(0.0, 0x8f as f32);
const CIVILIAN_PAGE_PARKED: Vec2 = Vec2::new(-1000.0, -1000.0);
const PORTRAIT_PICTURE_BASE: i16 = 0x438;
const CIVILIAN_NAME_GROUP: i16 = 0x2718;
const CIVILIAN_LEGEND_GROUP: i16 = 0x272d;
const RESOURCE_ICON_ATLAS: i16 = 750;
const DEVELOPMENT_STRIP_ATLAS: i16 = 751;
const TERRAIN_ICON_ATLAS: i16 = 801;
const RESOURCE_ICON_SIZE: Vec2 = Vec2::new(20.0, 24.0);
const TERRAIN_ICON_SIZE: Vec2 = Vec2::new(20.0, 20.0);
const DEVELOPMENT_FRAME_SIZE: Vec2 = Vec2::new(38.0, 26.0);
const ENGINEER_BUILDING_ICON_SIZE: Vec2 = Vec2::new(27.0, 20.0);
const LEGEND_PANEL_WIDTH: f32 = 123.0;
const TRANSPARENT_INDEX: u8 = 0x10;
const NAME_PALETTE: u8 = 0x28;
const NAME_SHADOW_PALETTE: u8 = 0;
const LEGEND_PALETTE: u8 = 0x28;

/// `g_anTargetTileProfileByCivilianClassAndSlot`.
const TARGET_TILE_PROFILES: CivilianUnitTable<[Option<i16>; 5]> = CivilianUnitTable::from_array([
    [Some(8), Some(9), None, None, None],
    [Some(8), Some(9), Some(10), Some(11), Some(12)],
    [Some(6), Some(5), Some(2), None, None],
    [Some(13), None, None, None, None],
    [None, None, None, None, Some(0)],
    [Some(3), Some(7), None, None, None],
    [None, None, None, None, Some(0)],
    [None, None, None, None, Some(0)],
    [Some(10), Some(11), Some(12), None, None],
]);

const DEVELOPMENT_STRIP_BASE_X: CivilianUnitTable<Option<i16>> = CivilianUnitTable::from_array([
    Some(228),
    None,
    Some(0),
    Some(114),
    None,
    Some(798),
    Some(912),
    Some(1064),
    Some(684),
]);
const DEVELOPER_MAX_ROWS: CivilianUnitTable<i16> =
    CivilianUnitTable::from_array([2, 0, 3, 1, 0, 2, 0, 0, 3]);
const DEVELOPER_ROW_ICON_X: [i16; 12] =
    [0, 0, 0, 0x237, 0, 0, 0x21c, 0x24c, 0, 0x216, 0x237, 0x258];
/// Window origin of `back` while `uciv` is at the civilian Locate point (0, 0x8f).
const LEGEND_WINDOW_ORIGIN: IVec2 = IVec2::new(517, 182);

#[derive(Component)]
struct CivilianToolbarPage;

#[derive(Component)]
struct CivilianPortrait;

#[derive(Component)]
struct CivilianLegend;

#[derive(Component)]
struct CivilianLegendItem;

#[derive(Component)]
struct CivilianCommandButton;

#[derive(Component, Clone)]
struct LegendAtlases {
    resources: Handle<Image>,
    development: Handle<Image>,
    terrain: Handle<Image>,
}

pub(crate) fn register_civilian_toolbar(app: &mut App) {
    app.add_systems(
        Update,
        sync_civilian_toolbar.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_civilian_toolbar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let page = tree.find(root, PAGE_TAG);
    locate_node(commands, page, CIVILIAN_PAGE_PARKED);
    commands.entity(page).insert(CivilianToolbarPage);
    commands
        .entity(tree.child(page, PORTRAIT_TAG))
        .insert((CivilianPortrait, Visibility::Hidden));
    commands.entity(tree.child(page, LEGEND_TAG)).insert((
        CivilianLegend,
        LegendAtlases {
            resources: transparent_atlas(assets, RESOURCE_ICON_ATLAS),
            development: transparent_atlas(assets, DEVELOPMENT_STRIP_ATLAS),
            terrain: transparent_atlas(assets, TERRAIN_ICON_ATLAS),
        },
    ));
    for tag in [
        fourcc!("dfnd"),
        fourcc!("done"),
        fourcc!("garr"),
        fourcc!("latr"),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert((CivilianCommandButton, InteractionDisabled));
    }
}

#[allow(clippy::too_many_arguments)]
fn sync_civilian_toolbar(
    session: Res<GameSession>,
    selected: Query<Ref<StrategicSelection>>,
    mut commands: Commands,
    mut pages: Query<&mut Node, With<CivilianToolbarPage>>,
    portraits: Query<Entity, With<CivilianPortrait>>,
    legends: Query<(Entity, &LegendAtlases, Option<&Children>), With<CivilianLegend>>,
    buttons: Query<Entity, With<CivilianCommandButton>>,
    items: Query<Entity, With<CivilianLegendItem>>,
    mut assets: RetailUiAssets,
) {
    let Ok(selected) = selected.single() else {
        return;
    };
    if !session.is_changed() && !selected.is_changed() {
        return;
    }
    let Ok(mut page) = pages.single_mut() else {
        return;
    };
    let unit = selected.0.and_then(|id| {
        session
            .game
            .civilian_units()
            .iter()
            .find(|unit| unit.id() == id)
    });
    let position = if unit.is_some() {
        CIVILIAN_PAGE_VISIBLE
    } else {
        CIVILIAN_PAGE_PARKED
    };
    page.left = Val::Px(position.x);
    page.top = Val::Px(position.y);
    let command_enabled = unit.is_some();
    for button in &buttons {
        let mut entity = commands.entity(button);
        if command_enabled {
            entity.remove::<InteractionDisabled>();
        } else {
            entity.insert(InteractionDisabled);
        }
    }
    if let Ok(portrait) = portraits.single() {
        match unit {
            Some(unit) => {
                let picture = assets
                    .picture(PictureId::new(portrait_picture_id(unit.unit_type())))
                    .expect("retail civilian toolbar portrait must load");
                commands
                    .entity(portrait)
                    .insert((ImageNode::new(picture), Visibility::Visible));
            }
            None => {
                commands.entity(portrait).insert(Visibility::Hidden);
            }
        }
    }
    let Ok((legend, atlases, legend_children)) = legends.single() else {
        return;
    };
    despawn_legend_items(&mut commands, legend_children, &items);
    let Some(unit) = unit else {
        return;
    };
    spawn_civilian_legend(
        &mut commands,
        &mut assets,
        legend,
        &session.game,
        unit,
        atlases.clone(),
    );
}

fn portrait_picture_id(kind: CivilianUnitKind) -> i16 {
    PORTRAIT_PICTURE_BASE + i16::from(kind as u8)
}

fn civilian_legend_target_counts(state: &GameState, unit: &CivilianUnitState) -> [i16; 5] {
    let mut counts = [0; 5];
    let Some(tile) = unit.location().tile() else {
        return counts;
    };
    let Some(owner) = state.map()[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return counts;
    };
    let Some(common) = state.nation(owner) else {
        return counts;
    };
    let profiles = TARGET_TILE_PROFILES[unit.unit_type()];
    for &province in common.owned_regions() {
        for &linked in &state.map().provinces[province].linked_tiles {
            if state.map()[linked].recruit_search_visited != 0 {
                continue;
            }
            let profile = i16::from(state.map()[linked].gate);
            for (slot, expected) in profiles.iter().copied().enumerate() {
                if expected == Some(profile) {
                    counts[slot] += 1;
                }
            }
        }
    }
    counts
}

#[allow(clippy::too_many_arguments)]
fn spawn_civilian_legend(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    legend: Entity,
    state: &GameState,
    unit: &CivilianUnitState,
    atlases: LegendAtlases,
) {
    let kind = unit.unit_type();
    let name = assets
        .string(CIVILIAN_NAME_GROUP, i16::from(kind as u8) + 1)
        .expect("retail civilian class name must load");
    let (name_font, name_layout, name_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail civilian name text style");
    spawn_legend_text(
        commands,
        legend,
        name,
        0.0,
        0x46 as f32,
        LEGEND_PANEL_WIDTH,
        name_font,
        name_layout,
        name_line_height,
        assets.palette_color(NAME_PALETTE),
        Some(TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(NAME_SHADOW_PALETTE),
        }),
    );
    match kind {
        CivilianUnitKind::Prospector => {
            spawn_prospector_legend(commands, assets, legend, state, unit, atlases);
        }
        CivilianUnitKind::Engineer => {
            spawn_engineer_legend(commands, assets, legend, state, atlases);
        }
        CivilianUnitKind::Developer => {}
        _ => spawn_developer_legend(commands, assets, legend, state, unit, atlases),
    }
}

fn spawn_engineer_legend(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    legend: Entity,
    state: &GameState,
    atlases: LegendAtlases,
) {
    let (font, layout, line_height, _) = legend_text_style(assets);
    let color = assets.palette_color(LEGEND_PALETTE);
    spawn_legend_text(
        commands,
        legend,
        legend_string(assets, 6),
        12.0,
        96.0,
        100.0,
        font.clone(),
        layout,
        line_height,
        color,
        None,
    );
    let buildings = [
        (7, 2000, 347.0, 110.0, 120.0),
        (8, 3000, 374.0, 134.0, 144.0),
        (9, 5000, 320.0, 158.0, 168.0),
    ];
    for (label, cost, source_x, icon_y, text_y) in buildings {
        spawn_atlas_icon(
            commands,
            legend,
            atlases.terrain.clone(),
            Vec2::new(10.0, icon_y),
            ENGINEER_BUILDING_ICON_SIZE,
            Vec2::new(source_x, 0.0),
        );
        spawn_legend_text(
            commands,
            legend,
            legend_string(assets, label),
            40.0,
            text_y,
            44.0,
            font.clone(),
            layout,
            line_height,
            color,
            None,
        );
        spawn_legend_text(
            commands,
            legend,
            format_currency(cost),
            84.0,
            text_y,
            36.0,
            font.clone(),
            layout,
            line_height,
            color,
            None,
        );
    }
    spawn_legend_text(
        commands,
        legend,
        legend_string(assets, 10),
        0.0,
        212.0,
        LEGEND_PANEL_WIDTH,
        font,
        TextLayout::justify(Justify::Center),
        line_height,
        color,
        None,
    );
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("civilian toolbar requires an active major nation");
    let status = state.technology().research_status_by_nation[nation];
    let cannot_build = [
        status[Technology::IronRailroadBridge] != TechnologyResearchStatus::Researched,
        status[Technology::CompoundSteamEngine] != TechnologyResearchStatus::Researched,
        status[Technology::CompoundSteamEngine] != TechnologyResearchStatus::Researched,
        status[Technology::Dynamite] != TechnologyResearchStatus::Researched,
    ];
    let terrain_icons = [10_i16, 7, 8, 9];
    let mut icon_x = 10.0;
    let mut icon_y = 216.0;
    for (slot, blocked) in cannot_build.into_iter().enumerate() {
        if !blocked {
            continue;
        }
        spawn_atlas_icon(
            commands,
            legend,
            atlases.terrain.clone(),
            Vec2::new(icon_x, icon_y),
            TERRAIN_ICON_SIZE,
            Vec2::new(f32::from(terrain_icons[slot]) * 20.0, 0.0),
        );
        if icon_x < 94.0 {
            icon_x += 28.0;
        } else {
            icon_x = 10.0;
            icon_y += 22.0;
        }
    }
}

fn spawn_prospector_legend(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    legend: Entity,
    state: &GameState,
    unit: &CivilianUnitState,
    atlases: LegendAtlases,
) {
    let (font, layout, line_height, _) = legend_text_style(assets);
    let color = assets.palette_color(LEGEND_PALETTE);
    spawn_legend_text(
        commands,
        legend,
        legend_string(assets, 5),
        5.0,
        96.0,
        110.0,
        font.clone(),
        layout,
        line_height,
        color,
        None,
    );
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("civilian toolbar requires an active major nation");
    let streamlined_hulls_researched = state.technology().research_status_by_nation[nation]
        [Technology::StreamlinedHulls]
        == TechnologyResearchStatus::Researched;
    let counts = civilian_legend_target_counts(state, unit);
    let column_resources: [[i16; 4]; 5] = [
        [3, 4, -1, -1],
        [3, 4, 0x16, 0x15],
        [6, -1, -1, -1],
        [6, -1, -1, -1],
        [6, -1, -1, -1],
    ];
    let column_count = if streamlined_hulls_researched { 5 } else { 2 };
    let mut column_top = 0x68 as f32;
    for column in 0..column_count {
        let mut icon_top = column_top;
        if column == 1 {
            icon_top += 12.0;
        }
        let terrain = TARGET_TILE_PROFILES[CivilianUnitKind::Prospector][column]
            .expect("prospector legend columns have terrain profiles");
        spawn_atlas_icon(
            commands,
            legend,
            atlases.terrain.clone(),
            Vec2::new(12.0, icon_top),
            TERRAIN_ICON_SIZE,
            Vec2::new(f32::from(terrain) * 20.0, 0.0),
        );
        spawn_legend_text(
            commands,
            legend,
            counts[column].to_string(),
            34.0,
            icon_top + 20.0,
            24.0,
            font.clone(),
            layout,
            line_height,
            color,
            None,
        );
        let mut first_row_right = 0x3c as f32;
        let mut second_row_x = 0.0;
        for resource in column_resources[column] {
            if resource == -1 {
                first_row_right += 0x1e as f32;
                second_row_x += 0x20 as f32;
                continue;
            }
            let dest = if first_row_right < 0x78 as f32 {
                Vec2::new(first_row_right - 20.0, column_top - 4.0)
            } else {
                Vec2::new(second_row_x - 24.0, column_top + 24.0)
            };
            spawn_atlas_icon(
                commands,
                legend,
                atlases.resources.clone(),
                dest,
                RESOURCE_ICON_SIZE,
                Vec2::new(f32::from(resource) * 20.0, 0.0),
            );
            first_row_right += 0x1e as f32;
            second_row_x += 0x20 as f32;
        }
        column_top += 0x1c as f32;
        if column == 1 {
            column_top += 0x18 as f32;
        }
    }
}

fn spawn_developer_legend(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    legend: Entity,
    state: &GameState,
    unit: &CivilianUnitState,
    atlases: LegendAtlases,
) {
    let kind = unit.unit_type();
    let Some(strip_base) = DEVELOPMENT_STRIP_BASE_X[kind] else {
        return;
    };
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("civilian toolbar requires an active major nation");
    let levels = state.technology().city_capabilities_by_nation[nation]
        .university
        .requirement_levels;
    let (font, layout, line_height, _) = legend_text_style(assets);
    let color = assets.palette_color(LEGEND_PALETTE);
    spawn_legend_text(
        commands,
        legend,
        legend_string(assets, 1),
        0.0,
        0x6a as f32,
        LEGEND_PANEL_WIDTH,
        font.clone(),
        TextLayout::justify(Justify::Center),
        line_height,
        color,
        None,
    );
    let mut strip_level = 0_i16;
    for resource in CIVILIAN_RESOURCE_SPECIALTIES[kind] {
        let Some(resource) = resource else {
            continue;
        };
        let reached = i16::from(levels[resource]) - 1;
        if strip_level <= reached {
            strip_level = reached;
        }
    }
    spawn_atlas_icon(
        commands,
        legend,
        atlases.development.clone(),
        Vec2::new(
            LEGEND_PANEL_WIDTH / 2.0 - 11.0,
            0x12c as f32 - LEGEND_WINDOW_ORIGIN.y as f32,
        ),
        DEVELOPMENT_FRAME_SIZE,
        Vec2::new(f32::from(strip_base + strip_level.max(0) * 38), 0.0),
    );
    spawn_legend_text(
        commands,
        legend,
        legend_string(assets, 2),
        0.0,
        0xa2 as f32,
        LEGEND_PANEL_WIDTH,
        font.clone(),
        TextLayout::justify(Justify::Center),
        line_height,
        color,
        None,
    );
    let yield_anchors = [
        IVec2::new(540, 353),
        IVec2::new(588, 353),
        IVec2::new(540, 378),
        IVec2::new(588, 378),
    ];
    for (slot, resource) in CIVILIAN_RESOURCE_SPECIALTIES[kind].into_iter().enumerate() {
        let Some(resource) = resource else {
            continue;
        };
        let mut dest = yield_anchors[slot] - LEGEND_WINDOW_ORIGIN;
        if matches!(kind, CivilianUnitKind::Forester | CivilianUnitKind::Driller) {
            dest.x += 0x1b;
        }
        spawn_atlas_icon(
            commands,
            legend,
            atlases.resources.clone(),
            Vec2::new(dest.x as f32, dest.y as f32),
            RESOURCE_ICON_SIZE,
            Vec2::new(f32::from(resource as u8) * 20.0, 0.0),
        );
        spawn_legend_text(
            commands,
            legend,
            resource_development_yield(resource, levels[resource]).to_string(),
            dest.x as f32 + 24.0,
            dest.y as f32 + 20.0,
            24.0,
            font.clone(),
            layout,
            line_height,
            color,
            None,
        );
    }
    let mut row_limit = DEVELOPER_MAX_ROWS[kind];
    if kind == CivilianUnitKind::Farmer && levels[ResourceKind::Cotton] == 0 {
        row_limit -= 1;
    }
    let counts = civilian_legend_target_counts(state, unit);
    for row in 0..row_limit {
        let Some(terrain) = TARGET_TILE_PROFILES[kind][row as usize] else {
            continue;
        };
        let icon_x = DEVELOPER_ROW_ICON_X[row as usize + 3 * row_limit as usize]
            - LEGEND_WINDOW_ORIGIN.x as i16;
        spawn_atlas_icon(
            commands,
            legend,
            atlases.terrain.clone(),
            Vec2::new(
                f32::from(icon_x),
                0x1a6 as f32 - LEGEND_WINDOW_ORIGIN.y as f32,
            ),
            TERRAIN_ICON_SIZE,
            Vec2::new(f32::from(terrain) * 20.0, 0.0),
        );
        spawn_legend_text(
            commands,
            legend,
            counts[row as usize].to_string(),
            f32::from(icon_x) + 24.0,
            0x100 as f32,
            24.0,
            font.clone(),
            layout,
            line_height,
            color,
            None,
        );
    }
}

fn legend_string(assets: &RetailUiAssets, index: i16) -> String {
    assets
        .string(CIVILIAN_LEGEND_GROUP, index + 1)
        .expect("retail civilian legend string must load")
}

fn legend_text_style(
    assets: &mut RetailUiAssets,
) -> (TextFont, TextLayout, bevy::text::LineHeight, bool) {
    assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail civilian legend text style")
}

#[allow(clippy::too_many_arguments)]
fn spawn_legend_text(
    commands: &mut Commands,
    legend: Entity,
    value: String,
    left: f32,
    top: f32,
    width: f32,
    font: TextFont,
    layout: TextLayout,
    line_height: bevy::text::LineHeight,
    color: Color,
    shadow: Option<TextShadow>,
) {
    let mut entity = commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(left),
            top: Val::Px(top),
            width: Val::Px(width),
            height: Val::Px(16.0),
            ..default()
        },
        Text::new(value),
        font,
        layout,
        line_height,
        TextColor(color),
        Pickable::IGNORE,
        CivilianLegendItem,
        ChildOf(legend),
    ));
    if let Some(shadow) = shadow {
        entity.insert(shadow);
    }
}

fn spawn_atlas_icon(
    commands: &mut Commands,
    legend: Entity,
    atlas: Handle<Image>,
    dest: Vec2,
    size: Vec2,
    source: Vec2,
) {
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(dest.x),
            top: Val::Px(dest.y),
            width: Val::Px(size.x),
            height: Val::Px(size.y),
            ..default()
        },
        ImageNode {
            image: atlas,
            rect: Some(Rect::from_corners(source, source + size)),
            ..default()
        },
        Pickable::IGNORE,
        CivilianLegendItem,
        ChildOf(legend),
    ));
}

fn transparent_atlas(assets: &mut RetailUiAssets, picture_id: i16) -> Handle<Image> {
    assets
        .transparent_picture(PictureId::new(picture_id), TRANSPARENT_INDEX)
        .expect("retail civilian legend atlas must load")
}

fn despawn_legend_items(
    commands: &mut Commands,
    children: Option<&Children>,
    items: &Query<Entity, With<CivilianLegendItem>>,
) {
    let Some(children) = children else {
        return;
    };
    for child in children {
        if items.contains(*child) {
            commands.entity(*child).despawn();
        }
    }
}

fn locate_node(commands: &mut Commands, entity: Entity, position: Vec2) {
    commands.entity(entity).insert(Node {
        position_type: PositionType::Absolute,
        left: Val::Px(position.x),
        top: Val::Px(position.y),
        width: Val::Px(126.0),
        height: Val::Px(306.0),
        ..default()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_state() -> GameState {
        LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: NationId::new(6),
        })
    }

    #[test]
    fn legend_counts_owned_unvisited_profile_tiles() {
        let state = fixture_state();
        let nation = state.turn().active_nation;
        let unit = state
            .civilian_units()
            .iter()
            .find(|unit| {
                unit.owner_nation() == nation
                    && matches!(
                        unit.unit_type(),
                        CivilianUnitKind::Miner
                            | CivilianUnitKind::Prospector
                            | CivilianUnitKind::Farmer
                            | CivilianUnitKind::Forester
                            | CivilianUnitKind::Rancher
                            | CivilianUnitKind::Fisherman
                            | CivilianUnitKind::Driller
                    )
            })
            .unwrap_or_else(|| {
                panic!(
                    "civilians: {:?}",
                    state
                        .civilian_units()
                        .iter()
                        .map(|unit| (unit.owner_nation(), unit.nation(), unit.unit_type()))
                        .collect::<Vec<_>>()
                )
            });
        let counts = civilian_legend_target_counts(&state, unit);
        let profiles = TARGET_TILE_PROFILES[unit.unit_type()];
        for (slot, profile) in profiles.iter().copied().enumerate() {
            if profile.is_none() {
                assert_eq!(
                    counts[slot],
                    0,
                    "unused legend slot {slot} for {:?}",
                    unit.unit_type()
                );
            }
        }
        assert!(
            counts.iter().any(|&count| count > 0),
            "{:?} legend should count matching owned tiles, got {counts:?}",
            unit.unit_type()
        );
    }

    #[test]
    fn engineer_and_prospector_are_not_developer_legends() {
        assert_eq!(DEVELOPMENT_STRIP_BASE_X[CivilianUnitKind::Engineer], None);
        assert_eq!(DEVELOPMENT_STRIP_BASE_X[CivilianUnitKind::Prospector], None);
        assert!(DEVELOPMENT_STRIP_BASE_X[CivilianUnitKind::Miner].is_some());
        assert!(DEVELOPMENT_STRIP_BASE_X[CivilianUnitKind::Developer].is_some());
    }
}
