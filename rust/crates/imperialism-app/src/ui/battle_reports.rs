//! Post-combat `TBattleReportView` / `TBattleDetailBook`.

use super::generated;
use super::hover_help::get_string;
use super::retail::RetailTree;
use super::retail_raster::IndexedRasterExt;
use super::satellite_preview::nation_owner_palette;
use super::session::{BattleReportPresentation, GameSession, apply_turn_stop};
use super::window::{DismissWindow, ModalDefault, ModalWindow};
use crate::AppState;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{BattleReportSideText, BattleReportText, PictureId, fourcc};

const MAP_LEFT: f32 = 49.0;
const MAP_TOP: f32 = 45.0;
const MAP_WIDTH: f32 = 540.0;
const MAP_HEIGHT: f32 = 300.0;
const MARKER_ATLAS: i16 = 803;
const MARKER_CELL: f32 = 18.0;

#[derive(Component)]
struct BattleReportRoot {
    selected: usize,
}

#[derive(Component)]
struct BattleReportMap {
    marker_atlas: Handle<Image>,
}

#[derive(Component)]
struct BattleReportMarker {
    report: usize,
    sprite: i32,
}

#[derive(Component, Clone, Copy)]
enum BattleReportFlag {
    Friendly,
    Enemy,
}

#[derive(Component, Clone, Copy)]
enum BattleReportStep {
    Prev,
    Next,
}

#[derive(Component)]
enum BattleReportField {
    Result,
    Location,
    FriendlyAdmiral,
    EnemyAdmiral,
    FriendlyShips,
    EnemyShips,
}

#[derive(Component)]
struct DetailRoot;

pub(crate) struct BattleReportPlugin;

impl Plugin for BattleReportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::BattleReport),
            (spawn_battle_report, bind_battle_report).chain(),
        )
        .add_systems(
            Update,
            (
                project_battle_report,
                super::diplomacy_map::layout_diplomacy_map_label_entities,
                blink_selected_battle_report_marker,
                bind_detail,
                project_detail,
            )
                .run_if(in_state(AppState::BattleReport).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn spawn_battle_report(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_1351()).id();
    commands.entity(root).insert((
        BattleReportRoot { selected: 0 },
        DespawnOnExit(AppState::BattleReport),
    ));
}

fn bind_battle_report(
    mut commands: Commands,
    root: Single<Entity, Added<BattleReportRoot>>,
    tree: RetailTree,
    mut assets: super::RetailUiAssets,
    session: Res<GameSession>,
) {
    let main = tree.find(*root, fourcc!("main"));
    let marker_atlas = assets
        .keyed_picture(PictureId::new(MARKER_ATLAS), 0x10)
        .expect("retail battle-report marker atlas must load");
    let map_entity = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(MAP_LEFT),
                top: px(MAP_TOP),
                width: px(MAP_WIDTH),
                height: px(MAP_HEIGHT),
                overflow: Overflow::clip(),
                ..default()
            },
            ImageNode::default(),
            RelativeCursorPosition::default(),
            BattleReportMap { marker_atlas },
            ChildOf(main),
        ))
        .observe(on_battle_report_map_click)
        .id();
    let mut seeds = [None; NationId::COUNT as usize];
    for nation in NationId::all() {
        let Some(name) = session.game.nations().display_name(nation) else {
            continue;
        };
        let Some(anchor) = session.game.ocean_overlay_anchor_for_nation(nation) else {
            continue;
        };
        let (row, column) = session.game.map().geometry().row_column(anchor);
        seeds[usize::from(nation.get())] =
            Some(super::diplomacy_map::DiplomacyLabelSeed { name, column, row });
    }
    super::diplomacy_map::spawn_diplomacy_map_labels(
        &mut commands,
        &mut assets,
        map_entity,
        &seeds,
    );
    commands
        .entity(tree.find(*root, fourcc!("okay")))
        .insert((ActivateOnPress, ModalDefault, DismissWindow))
        .observe(on_battle_report_close);
    commands
        .entity(tree.find(*root, fourcc!("info")))
        .insert(ActivateOnPress)
        .observe(on_battle_report_detail);
    commands
        .entity(tree.find(*root, fourcc!("prev")))
        .insert((BattleReportStep::Prev, ActivateOnPress))
        .observe(on_battle_report_step);
    commands
        .entity(tree.find(*root, fourcc!("next")))
        .insert((BattleReportStep::Next, ActivateOnPress))
        .observe(on_battle_report_step);
    for (tag, field) in [
        (fourcc!("resu"), BattleReportField::Result),
        (fourcc!("loca"), BattleReportField::Location),
        (fourcc!("fadm"), BattleReportField::FriendlyAdmiral),
        (fourcc!("eadm"), BattleReportField::EnemyAdmiral),
        (fourcc!("fshp"), BattleReportField::FriendlyShips),
        (fourcc!("eshp"), BattleReportField::EnemyShips),
    ] {
        commands.entity(tree.find(*root, tag)).insert(field);
    }
    commands
        .entity(tree.find(*root, fourcc!("fflg")))
        .insert(BattleReportFlag::Friendly);
    commands
        .entity(tree.find(*root, fourcc!("eflg")))
        .insert(BattleReportFlag::Enemy);
}

fn project_battle_report(
    mut commands: Commands,
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    roots: Query<Ref<BattleReportRoot>>,
    added: Query<(), Added<BattleReportField>>,
    mut fields: Query<(&BattleReportField, &mut Text)>,
    mut flags: Query<(&BattleReportFlag, &mut ImageNode), Without<BattleReportMap>>,
    map: Single<(Entity, Option<&ImageNode>, &BattleReportMap)>,
    markers: Query<Entity, With<BattleReportMarker>>,
    mut assets: super::RetailUiAssets,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    if super::projection_idle(&session, !added.is_empty())
        && !root.is_changed()
        && !reports.is_changed()
    {
        return;
    }
    let reports_game = session.game.battle_reports();
    let (map_entity, map_image, map_data) = map.into_inner();
    let state = &session.game;
    let owner_at = |tile: TileId| {
        state.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
    };
    let (picture, _) =
        super::diplomacy_map::compose_diplomacy_map(owner_at, nation_owner_palette, None);
    let image = picture.to_keyed_image(assets.default_dib_palette(), 0x10);
    if let Some(image_node) = map_image {
        assets.replace_image(&image_node.image, image);
    } else {
        commands
            .entity(map_entity)
            .insert(ImageNode::new(assets.add_image(image)));
    }
    for marker in &markers {
        commands.entity(marker).despawn();
    }
    let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
    let geometry = state.map().geometry();
    for (index, report) in reports_game.iter().enumerate() {
        let Some(tile) = battle_report_tile(state, report) else {
            continue;
        };
        let tile = battle_report_marker_tile(geometry, tile, &mut crowd);
        let (row, column) = state.map().geometry().row_column(tile);
        let point = super::diplomacy_map::diplomacy_tile_pixel(row, column) - IVec2::splat(9);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(point.x),
                top: px(point.y),
                width: px(MARKER_CELL),
                height: px(MARKER_CELL),
                ..default()
            },
            ImageNode {
                image: map_data.marker_atlas.clone(),
                rect: Some(marker_rect(battle_report_marker_sprite(state, report))),
                ..default()
            },
            BattleReportMarker {
                report: index,
                sprite: battle_report_marker_sprite(state, report),
            },
            ChildOf(map_entity),
            ZIndex(1),
        ));
    }
    let Some(report) = reports_game.get(root.selected) else {
        for (_, mut text) in &mut fields {
            text.0.clear();
        }
        return;
    };
    let report_text = battle_report_text(&session, &reports.0, root.selected);
    let participant = report.displayed_side;
    let other = other_side(participant);
    let location = match report.location {
        BattleReportLocation::Province(id) => session.game.map().provinces[id].name.clone(),
        BattleReportLocation::Zone(id) => format!("zone {}", id.get()),
    };
    for (field, mut text) in &mut fields {
        text.0 = match field {
            BattleReportField::Result => battle_report_result_text(&assets, state, report),
            BattleReportField::Location => location.clone(),
            BattleReportField::FriendlyAdmiral => report_text[participant].name.clone(),
            BattleReportField::EnemyAdmiral => report_text[other].name.clone(),
            BattleReportField::FriendlyShips => report_text[participant].overlay.clone(),
            BattleReportField::EnemyShips => report_text[other].overlay.clone(),
        };
    }
    for (flag, mut image) in &mut flags {
        let side = match flag {
            BattleReportFlag::Friendly => participant,
            BattleReportFlag::Enemy => other,
        };
        image.image = assets
            .picture(PictureId::new(
                0x1130 + i16::from(report.sides[side].nation.get()),
            ))
            .expect("retail battle-report flag picture must load");
    }
}

/// `TBattleReportView::DoPostCreate` marker placement: spiral outward from the
/// report's map cell on a 60×108 crowding grid until a free hex is found, then
/// mark a radius-3 neighborhood around it as crowded. The steps replicate retail
/// `TMapMgr::StepHexRowColByDirectionWithWrapRules`, which wraps columns around
/// the map edges when the map is bounded.
fn battle_report_marker_tile(geometry: MapGeometry, origin: TileId, crowd: &mut [u8]) -> TileId {
    let cell = i32::from(origin.get());
    let (mut row, mut column) = (cell / 108, cell % 108);
    let mut ring_leg = 1;
    let mut leg_step = 0;
    let mut radius = 0;
    let mut found_cell = cell;
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, ring_leg);
    while radius < 10 {
        if let Some(probe) = crowd_probe(row, column)
            && crowd[probe as usize] == 0
        {
            found_cell = probe;
            break;
        }
        leg_step += 1;
        if leg_step >= radius {
            leg_step = 0;
            ring_leg += 1;
            if ring_leg >= 6 {
                ring_leg = 0;
                radius += 1;
                step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
            }
        }
        step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, ring_leg);
    }
    (row, column) = (found_cell / 108, found_cell % 108);
    let mut ring = 0;
    let mut mark_leg = 1;
    let mut mark_step = 0;
    let mut mark_leg_len = found_cell % 108;
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
    step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, mark_leg);
    while ring < 3 {
        if let Some(probe) = crowd_probe(row, column) {
            crowd[probe as usize] += 1;
        }
        mark_step += 1;
        if mark_step >= mark_leg_len {
            mark_step = 0;
            mark_leg += 1;
            if mark_leg >= 6 {
                mark_leg = 0;
                mark_leg_len += 1;
                ring += 1;
                step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, 4);
            }
        }
        step_hex_row_col_by_wrap_rules(geometry, &mut row, &mut column, mark_leg);
    }
    crowd[found_cell as usize] += 1;
    TileId::new(u16::try_from(found_cell).expect("battle-report marker tile fits the map"))
}

fn crowd_probe(row: i32, column: i32) -> Option<i32> {
    ((0..STRATEGIC_MAP_HEIGHT as i32).contains(&row)
        && (0..STRATEGIC_MAP_WIDTH as i32).contains(&column))
    .then_some(row * STRATEGIC_MAP_WIDTH as i32 + column)
}

/// Retail `TMapMgr::StepHexRowColByDirectionWithWrapRules` integer row/column
/// stepping, including its out-of-bounds column wrap quirk.
fn step_hex_row_col_by_wrap_rules(
    geometry: MapGeometry,
    row: &mut i32,
    column: &mut i32,
    direction: i32,
) {
    if direction == 4 || (direction > 2 && *row & 1 == 0) {
        let next = *column - 1;
        *column = next;
        if next < 0 && !geometry.wraps_horizontally() {
            *column = STRATEGIC_MAP_WIDTH as i32 - 1;
        }
    } else if direction == 1 || (direction < 3 && *row & 1 != 0) {
        let next = *column + 1;
        *column = next;
        if next >= STRATEGIC_MAP_WIDTH as i32 && !geometry.wraps_horizontally() {
            *column = 0;
        }
    }
    if direction == 5 || direction == 0 {
        *row -= 1;
    } else if direction == 3 || direction == 2 {
        *row += 1;
    }
}

fn battle_report_result_text(
    assets: &super::RetailUiAssets,
    state: &GameState,
    report: &BattleReport,
) -> String {
    let (group, index) = battle_report_result_string_index(state, report);
    get_string(assets, group, index)
}

/// `RefreshMapContextSelectionPanelAndInfoLabels`: the `resu` string group and
/// (0-based, pre-`GetString` increment) index recovered from the report kind,
/// the winner/active-nation relation, and land-battle site ownership.
fn battle_report_result_string_index(state: &GameState, report: &BattleReport) -> (i16, i16) {
    let active = state.turn().active_nation;
    let winner = report.participant.unwrap_or(report.displayed_side);
    let relation = if report.sides[winner].nation == active {
        1
    } else if report.sides[other_side(winner)].nation == active {
        -1
    } else {
        0
    };
    match report.kind {
        BattleReportKind::MerchantInterception => (0x273c, relation + 4),
        BattleReportKind::SeaBattle => (0x273c, relation + 7),
        BattleReportKind::PreemptedLandBattle => (0x273d, relation + 39),
        BattleReportKind::UncontestedTakeover => (0x273d, relation + 42),
        BattleReportKind::LandBattle => {
            let report_sides_are_same = report.displayed_side == winner;
            let report_participant_is_active = report.sides[winner].nation == active;
            let active_nation_is_other_report_side = relation != 0 && !report_participant_is_active;
            let displayed_participant_is_active =
                report.sides[report.displayed_side].nation == active;
            let mut other_nation = report.sides[BattleReportSideSlot::Left].nation;
            if other_nation == active {
                other_nation = report.sides[BattleReportSideSlot::Right].nation;
            }
            let BattleReportLocation::Province(province) = report.location else {
                unreachable!("land battle reports store a province");
            };
            let active_nation_owns_battle_site = state.capitol_province(active) == Some(province);
            let other_nation_owns_battle_site =
                state.capitol_province(other_nation) == Some(province);
            let index = if active_nation_owns_battle_site && displayed_participant_is_active {
                47
            } else if active_nation_owns_battle_site && active_nation_is_other_report_side {
                48
            } else if report_participant_is_active
                && report_sides_are_same
                && other_nation_owns_battle_site
            {
                47
            } else if report_participant_is_active && report_sides_are_same {
                3
            } else if report_participant_is_active {
                6
            } else if active_nation_is_other_report_side && report_sides_are_same {
                4
            } else if active_nation_is_other_report_side {
                1
            } else if report_sides_are_same {
                2
            } else {
                5
            };
            (0x273d, index)
        }
    }
}

fn blink_selected_battle_report_marker(
    time: Res<Time>,
    roots: Query<&BattleReportRoot>,
    mut markers: Query<(&BattleReportMarker, &mut ImageNode)>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    // TBattleReportView flips the selected sprite column every 15 idle ticks.
    let phase = i32::from((time.elapsed().as_millis() / 250) & 1 == 0);
    for (marker, mut image) in &mut markers {
        image.rect = Some(marker_rect(
            marker.sprite + i32::from(marker.report == root.selected) * phase,
        ));
    }
}

fn battle_report_tile(state: &GameState, report: &BattleReport) -> Option<TileId> {
    match report.location {
        BattleReportLocation::Province(province) => state.map().provinces[province].city_tile(),
        BattleReportLocation::Zone(zone) => state
            .ocean()
            .zones
            .get(usize::from(zone.get()))
            .and_then(|zone| zone.zone().active_tile.or(zone.zone().target_tile)),
    }
}

fn battle_report_marker_sprite(state: &GameState, report: &BattleReport) -> i32 {
    let active = state.turn().active_nation;
    let participant = report.participant.unwrap_or(BattleReportSideSlot::Left);
    let other = other_side(participant);
    let base = if report.sides[participant].nation == active {
        0
    } else if report.sides[other].nation == active {
        4
    } else {
        8
    };
    base + i32::from(report.kind == BattleReportKind::MerchantInterception) * 2
}

fn other_side(side: BattleReportSideSlot) -> BattleReportSideSlot {
    match side {
        BattleReportSideSlot::Left => BattleReportSideSlot::Right,
        BattleReportSideSlot::Right => BattleReportSideSlot::Left,
    }
}

fn marker_rect(sprite: i32) -> Rect {
    Rect::from_corners(
        Vec2::new(sprite as f32 * MARKER_CELL, 0.0),
        Vec2::new((sprite + 1) as f32 * MARKER_CELL, MARKER_CELL),
    )
}

fn on_battle_report_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<BattleReportMap>>,
    markers: Query<(&BattleReportMarker, &Node)>,
    mut roots: Query<&mut BattleReportRoot>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    let Some(point) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let point = Vec2::new((point.x + 0.5) * MAP_WIDTH, (point.y + 0.5) * MAP_HEIGHT);
    let Some(report) = markers.iter().find_map(|(marker, node)| {
        let (Val::Px(left), Val::Px(top)) = (node.left, node.top) else {
            return None;
        };
        Rect::from_corners(
            Vec2::new(left, top),
            Vec2::new(left + MARKER_CELL, top + MARKER_CELL),
        )
        .contains(point)
        .then_some(marker.report)
    }) else {
        return;
    };
    if let Ok(mut root) = roots.single_mut() {
        root.selected = report;
    }
}

fn on_battle_report_close(
    _activate: On<Activate>,
    mut session: ResMut<GameSession>,
    mut reports: ResMut<BattleReportPresentation>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    reports.0.clear();
    apply_turn_stop(session.game.close_post_combat_reports(), &mut next_state);
}

fn on_battle_report_detail(
    _activate: On<Activate>,
    mut commands: Commands,
    session: Res<GameSession>,
    details: Query<(), With<DetailRoot>>,
) {
    if details.is_empty() && !session.game.battle_reports().is_empty() {
        spawn_detail(&mut commands);
    }
}

fn on_battle_report_step(
    activate: On<Activate>,
    step: Query<&BattleReportStep>,
    session: Res<GameSession>,
    mut roots: Query<&mut BattleReportRoot>,
) {
    let Ok(step) = step.get(activate.entity) else {
        return;
    };
    let count = session.game.battle_reports().len();
    if count == 0 {
        return;
    }
    let Ok(mut root) = roots.single_mut() else {
        return;
    };
    root.selected = match *step {
        BattleReportStep::Prev => (root.selected + count - 1) % count,
        BattleReportStep::Next => (root.selected + 1) % count,
    };
}

fn spawn_detail(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::diplo_1352()).id();
    commands.entity(root).insert((
        DetailRoot,
        ModalWindow,
        DespawnOnExit(AppState::BattleReport),
    ));
}

fn bind_detail(mut commands: Commands, root: Single<Entity, Added<DetailRoot>>, tree: RetailTree) {
    commands.entity(tree.find(*root, fourcc!("okay"))).insert((
        ActivateOnPress,
        ModalDefault,
        DismissWindow,
    ));
}

fn project_detail(
    session: Res<GameSession>,
    reports: Res<BattleReportPresentation>,
    selected: Single<&BattleReportRoot>,
    added: Query<(), Added<DetailRoot>>,
    tree: RetailTree,
    root: Query<Entity, With<DetailRoot>>,
    mut texts: Query<&mut Text>,
) {
    if added.is_empty() {
        return;
    }
    let Ok(root) = root.single() else {
        return;
    };
    let Some(_) = session.game.battle_reports().get(selected.selected) else {
        return;
    };
    let report_text = battle_report_text(&session, &reports.0, selected.selected);
    let left = tree.find(root, fourcc!("natL"));
    let right = tree.find(root, fourcc!("natR"));
    if let Ok(mut text) = texts.get_mut(left) {
        text.0 = report_text[BattleReportSideSlot::Left].name.clone();
    }
    if let Ok(mut text) = texts.get_mut(right) {
        text.0 = report_text[BattleReportSideSlot::Right].name.clone();
    }
}

pub(crate) fn battle_report_texts_for_save(
    session: &GameSession,
    captured: &[BattleReportText],
) -> Vec<BattleReportText> {
    session
        .game
        .battle_reports()
        .iter()
        .enumerate()
        .map(|(index, _)| battle_report_text(session, captured, index))
        .collect()
}

fn battle_report_text(
    session: &GameSession,
    captured: &[BattleReportText],
    index: usize,
) -> BattleReportText {
    if let Some(text) = captured.get(index) {
        return text.clone();
    }
    let report = &session.game.battle_reports()[index];
    BattleReportText::from_array([
        generated_battle_report_side_text(&session.game, report, BattleReportSideSlot::Left),
        generated_battle_report_side_text(&session.game, report, BattleReportSideSlot::Right),
    ])
}

fn generated_battle_report_side_text(
    state: &GameState,
    report: &BattleReport,
    slot: BattleReportSideSlot,
) -> BattleReportSideText {
    let side = &report.sides[slot];
    let nation_name = state
        .nation(side.nation)
        .map(|nation| nation.display_name.as_str())
        .unwrap_or("");
    let role = match (report.kind.is_land(), slot) {
        (true, BattleReportSideSlot::Left) => "Units Attacking",
        (true, BattleReportSideSlot::Right) => "Defensive Muster",
        (false, _) => "",
    };
    let name = if role.is_empty() {
        nation_name.to_owned()
    } else {
        format!("{nation_name}: {role}")
    };
    let mut overlay = String::new();
    for kind_index in 0..MilitaryUnitKind::LENGTH {
        let kind = MilitaryUnitKind::from_index(kind_index as u8).expect("military kind index");
        let matching = side
            .children
            .iter()
            .filter(|row| row.kind == BattleReportUnitKind::Military(kind))
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        if !overlay.is_empty() {
            overlay.push_str(", ");
        }
        let unit_name = match kind {
            MilitaryUnitKind::Minutemen => "Minutemen",
            MilitaryUnitKind::Skirmishers => "Skirmishers",
            MilitaryUnitKind::Regulars => "Regulars",
            MilitaryUnitKind::Grenadiers => "Grenadiers",
            MilitaryUnitKind::Hussars => "Hussars",
            MilitaryUnitKind::Cuirassiers => "Cuirassiers",
            MilitaryUnitKind::LightArtillery => "Light Artillery",
            MilitaryUnitKind::Artillery => "Artillery",
            _ => &matching[0].name,
        };
        overlay.push_str(&format!("{} {unit_name}", matching.len()));
        let inactive = matching
            .iter()
            .filter(|row| row.stock_or_required <= 0)
            .count();
        if inactive != 0 {
            overlay.push_str(&format!(" ({inactive} Inactive)"));
        }
    }
    BattleReportSideText { name, overlay }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game;

    #[test]
    fn battle_report_marker_spiral_matches_retail_placement_order() {
        let geometry = MapGeometry::new(MapTopology::Bounded);
        let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1000)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1109)
        );
        let mut crowd = vec![0u8; STRATEGIC_TILE_COUNT];
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1000), &mut crowd),
            TileId::new(1000)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(1001), &mut crowd),
            TileId::new(1110)
        );
        assert_eq!(
            battle_report_marker_tile(geometry, TileId::new(999), &mut crowd),
            TileId::new(996)
        );
    }

    #[test]
    fn battle_report_result_string_index_follows_retail_decision_tree() {
        let state = beginning_of_game();
        let active = state.turn().active_nation;
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(21)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273d, 47)
        );
        // The enemy's capitol, won by that enemy while the active nation is the
        // displayed other side.
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Right),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(80)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273d, 1)
        );
        // Sea-battle strings key off the winner/active relation alone.
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::SeaBattle,
            location: BattleReportLocation::Zone(OceanZoneId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: active,
                    children: Vec::new(),
                },
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                },
            ]),
        };
        assert_eq!(
            battle_report_result_string_index(&state, &report),
            (0x273c, 8)
        );
    }

    #[test]
    fn generated_land_report_text_preserves_retail_caption_and_summary_order() {
        let state = beginning_of_game();
        let nation = state.turn().active_nation;
        let report = BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation,
                    children: vec![
                        BattleReportUnit {
                            kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                            stock_or_required: 100,
                            name: "1st Regulars".to_owned(),
                            strength_bucket: 1,
                            detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                        },
                        BattleReportUnit {
                            kind: BattleReportUnitKind::Military(MilitaryUnitKind::Regulars),
                            stock_or_required: 0,
                            name: "2nd Regulars".to_owned(),
                            strength_bucket: 1,
                            detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
                        },
                    ],
                },
                BattleReportSide {
                    nation: NationId::new(1),
                    children: Vec::new(),
                },
            ]),
        };

        let text = generated_battle_report_side_text(&state, &report, BattleReportSideSlot::Left);

        assert_eq!(
            text.name,
            format!(
                "{}: Units Attacking",
                state.nation(nation).unwrap().display_name
            )
        );
        assert_eq!(text.overlay, "2 Regulars (1 Inactive)");
    }
}
