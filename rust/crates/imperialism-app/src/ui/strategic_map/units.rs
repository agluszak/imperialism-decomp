//! Read-only projection of authoritative units onto the strategic map.
//!
//! Retail `TMapDialog::DrawOneTile` blits civilians, army-count badges, and ocean
//! action frames into the tile cache. This module keeps those sprites as disposable
//! Bevy entities over the composed terrain bitmap.

use super::super::GameSession;
use super::RetailUiAssets;
use super::{TILE_SIZE, VIEWPORT_HEIGHT, VIEWPORT_WIDTH, for_each_visible_strategic_tile};
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use enum_map::Enum;
use imperialism_core::*;
use imperialism_formats::*;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

const UNIT_TRANSPARENT_INDEX: u8 = 0x10;
const FOREIGN_CIVILIAN_FRAME_INDEX: u8 = 0x13;
const STRATEGIC_NAVAL_FRAME_COUNT: i16 = 18;
const CIVILIAN_IDLE_PICTURE_BASE: i16 = 400;
const CIVILIAN_WORKING_PICTURE_BASE: i16 = 418;
const ARMY_COUNT_PICTURE_IDS: [i16; 4] = [570, 572, 574, 576];
const OWNER_FLAG_PICTURE_ID: i16 = 580;
const FLEET_ATLAS_PICTURE_BASE: i16 = 1_380;
const CIVILIAN_SPRITE_CLASS: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([2, 3, 1, 6, 0, 7, 5, 4, 8]);
const CIVILIAN_ANIMATION_PICTURE_IDS: CivilianUnitTable<i16> = CivilianUnitTable::from_array([
    14_000, 14_005, 14_011, 14_015, 14_021, 14_026, 14_030, 14_035, 14_040,
]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CivilianPose {
    Idle,
    Working,
    Animated,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum StrategicUnitIdentity {
    Civilian(CivilianUnitId),
    Army(ProvinceId),
    Naval(TileId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum StrategicUnitSprite {
    Civilian {
        kind: CivilianUnitKind,
        pose: CivilianPose,
        owner_badge: Option<u8>,
        framed: bool,
    },
    Army {
        bucket: u8,
        owner_slot: u8,
    },
    Naval {
        frame: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct VisibleStrategicUnit {
    identity: StrategicUnitIdentity,
    screen_x: i32,
    screen_y: i32,
    sprite: StrategicUnitSprite,
    z: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StrategicUnitProjectKey {
    view_origin: TileId,
    active_nation: NationId,
    fleet_atlas: i16,
    visible: u64,
}

#[derive(Component)]
pub(crate) struct StrategicUnitLayer {
    projected: Option<StrategicUnitProjectKey>,
}

#[derive(Component)]
pub(crate) struct StrategicMapUnit;

#[derive(Component)]
pub(crate) struct StrategicUnitSprites {
    civilians: HashMap<(CivilianUnitKind, CivilianPose), IndexedPicture>,
    army_counts: [IndexedPicture; 4],
    owner_flags: IndexedPicture,
    fleet_frames: Vec<IndexedPicture>,
    fleet_atlas_id: i16,
    composed: HashMap<StrategicUnitSprite, Handle<Image>>,
}

pub(super) fn bind_strategic_units(
    commands: &mut Commands,
    map: Entity,
    assets: &mut RetailUiAssets,
    state: &GameState,
) {
    let mut sprites = load_strategic_unit_sprites(assets, state);
    let layer = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(0.0),
                width: Val::Px(VIEWPORT_WIDTH as f32),
                height: Val::Px(VIEWPORT_HEIGHT as f32),
                overflow: Overflow::clip(),
                ..default()
            },
            Pickable::IGNORE,
            ChildOf(map),
        ))
        .id();
    project_strategic_units_onto(commands, layer, &mut sprites, assets, state);
    commands.entity(layer).insert((
        StrategicUnitLayer {
            projected: Some(strategic_unit_project_key(state)),
        },
        sprites,
    ));
}

pub(crate) fn sync_strategic_units(
    mut commands: Commands,
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    mut layers: Query<(
        Entity,
        &mut StrategicUnitLayer,
        &mut StrategicUnitSprites,
        Option<&Children>,
    )>,
    units: Query<Entity, With<StrategicMapUnit>>,
) {
    if !session.is_changed() {
        return;
    }
    let state = &session.game;
    for (layer, mut projection, mut sprites, children) in &mut layers {
        let fleet_id = fleet_atlas_picture_id(state).get();
        if sprites.fleet_atlas_id != fleet_id {
            sprites.fleet_frames = load_fleet_frames(&assets, state);
            sprites.fleet_atlas_id = fleet_id;
            sprites.composed.clear();
        }
        let key = strategic_unit_project_key(state);
        if projection.projected == Some(key) {
            continue;
        }
        despawn_projected_units(&mut commands, children, &units);
        project_strategic_units_onto(&mut commands, layer, &mut sprites, &mut assets, state);
        projection.projected = Some(key);
    }
}

fn despawn_projected_units(
    commands: &mut Commands,
    children: Option<&Children>,
    units: &Query<Entity, With<StrategicMapUnit>>,
) {
    let Some(children) = children else {
        return;
    };
    for child in children {
        if units.contains(*child) {
            commands.entity(*child).despawn();
        }
    }
}

fn project_strategic_units_onto(
    commands: &mut Commands,
    layer: Entity,
    sprites: &mut StrategicUnitSprites,
    assets: &mut RetailUiAssets,
    state: &GameState,
) {
    let palette = *assets.default_dib_palette();
    for unit in visible_strategic_units(state) {
        let Some(image) = unit_sprite_image(sprites, assets, &palette, unit.sprite) else {
            continue;
        };
        let (width, height) = (TILE_SIZE, TILE_SIZE);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(unit.screen_x as f32),
                top: Val::Px(unit.screen_y as f32),
                width: Val::Px(width as f32),
                height: Val::Px(height as f32),
                ..default()
            },
            ImageNode::new(image),
            ZIndex(unit.z),
            Pickable::IGNORE,
            StrategicMapUnit,
            ChildOf(layer),
        ));
    }
}

fn load_strategic_unit_sprites(assets: &RetailUiAssets, state: &GameState) -> StrategicUnitSprites {
    let mut civilians = HashMap::new();
    for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
        for pose in [
            CivilianPose::Idle,
            CivilianPose::Working,
            CivilianPose::Animated,
        ] {
            if let Some(picture) = load_civilian_picture(assets, kind, pose) {
                civilians.insert((kind, pose), picture);
            }
        }
    }
    let army_counts = ARMY_COUNT_PICTURE_IDS.map(|id| load_required_picture(assets, id));
    let owner_flags = load_required_picture(assets, OWNER_FLAG_PICTURE_ID);
    let fleet_atlas_id = fleet_atlas_picture_id(state).get();
    let fleet_frames = load_fleet_frames(assets, state);
    StrategicUnitSprites {
        civilians,
        army_counts,
        owner_flags,
        fleet_frames,
        fleet_atlas_id,
        composed: HashMap::new(),
    }
}

fn load_civilian_picture(
    assets: &RetailUiAssets,
    kind: CivilianUnitKind,
    pose: CivilianPose,
) -> Option<IndexedPicture> {
    let picture_id = civilian_picture_id(kind, pose);
    if let Ok(picture) = assets.indexed_picture(PictureId::new(picture_id)) {
        return Some(first_tile_frame(picture));
    }
    if pose == CivilianPose::Animated {
        return None;
    }
    assets
        .indexed_picture(PictureId::new(civilian_picture_id(
            kind,
            CivilianPose::Animated,
        )))
        .ok()
        .map(first_tile_frame)
}

fn civilian_picture_id(kind: CivilianUnitKind, pose: CivilianPose) -> i16 {
    match pose {
        CivilianPose::Idle => CIVILIAN_IDLE_PICTURE_BASE + i16::from(civilian_sprite_class(kind)),
        CivilianPose::Working => {
            CIVILIAN_WORKING_PICTURE_BASE + i16::from(civilian_sprite_class(kind))
        }
        CivilianPose::Animated => CIVILIAN_ANIMATION_PICTURE_IDS[kind],
    }
}

fn load_fleet_frames(assets: &RetailUiAssets, state: &GameState) -> Vec<IndexedPicture> {
    let atlas = load_required_picture(assets, fleet_atlas_picture_id(state).get());
    (0..STRATEGIC_NAVAL_FRAME_COUNT as u32)
        .filter_map(|frame| {
            let x = frame * TILE_SIZE as u32;
            (x + TILE_SIZE as u32 <= atlas.width)
                .then(|| crop_indexed(&atlas, x, 0, TILE_SIZE as u32, TILE_SIZE as u32))
        })
        .collect()
}

fn load_required_picture(assets: &RetailUiAssets, id: i16) -> IndexedPicture {
    let picture_id = PictureId::new(id);
    assets.indexed_picture(picture_id).unwrap_or_else(|error| {
        panic!("retail strategic unit picture {picture_id} must load: {error}")
    })
}

fn first_tile_frame(picture: IndexedPicture) -> IndexedPicture {
    let width = picture.width.min(TILE_SIZE as u32);
    let height = picture.height.min(TILE_SIZE as u32);
    if picture.width == width && picture.height == height {
        picture
    } else {
        crop_indexed(&picture, 0, 0, width, height)
    }
}

fn crop_indexed(
    source: &IndexedPicture,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
) -> IndexedPicture {
    let mut pixels = Vec::with_capacity((width * height) as usize);
    for row in 0..height {
        let start = ((y + row) * source.width + x) as usize;
        pixels.extend_from_slice(&source.pixels[start..start + width as usize]);
    }
    IndexedPicture {
        width,
        height,
        pixels,
    }
}

fn unit_sprite_image(
    sprites: &mut StrategicUnitSprites,
    assets: &mut RetailUiAssets,
    palette: &DibPalette,
    sprite: StrategicUnitSprite,
) -> Option<Handle<Image>> {
    if let Some(handle) = sprites.composed.get(&sprite) {
        return Some(handle.clone());
    }
    let picture = compose_unit_sprite(sprites, sprite)?;
    let handle = assets.add_image(indexed_rgba_image(
        &picture,
        palette,
        UNIT_TRANSPARENT_INDEX,
    ));
    sprites.composed.insert(sprite, handle.clone());
    Some(handle)
}

fn compose_unit_sprite(
    sprites: &StrategicUnitSprites,
    sprite: StrategicUnitSprite,
) -> Option<IndexedPicture> {
    match sprite {
        StrategicUnitSprite::Civilian {
            kind,
            pose,
            owner_badge,
            framed,
        } => {
            let mut picture = sprites.civilians.get(&(kind, pose))?.clone();
            if let Some(slot) = owner_badge {
                blit_indexed(
                    &sprites.owner_flags,
                    i32::from(slot) * 9,
                    0,
                    9,
                    6,
                    &mut picture,
                    28,
                    TILE_SIZE - 8,
                );
            }
            if framed {
                draw_unit_frame(&mut picture, FOREIGN_CIVILIAN_FRAME_INDEX);
            }
            Some(picture)
        }
        StrategicUnitSprite::Army { bucket, owner_slot } => {
            let count = sprites.army_counts.get(usize::from(bucket))?;
            let mut picture = transparent_tile();
            blit_indexed(
                count,
                0,
                0,
                count.width as i32,
                count.height as i32,
                &mut picture,
                0,
                TILE_SIZE - 0x26,
            );
            blit_indexed(
                &sprites.owner_flags,
                i32::from(owner_slot) * 9,
                0,
                9,
                6,
                &mut picture,
                7,
                TILE_SIZE - 8,
            );
            Some(picture)
        }
        StrategicUnitSprite::Naval { frame } => {
            sprites.fleet_frames.get(usize::from(frame)).cloned()
        }
    }
}

fn transparent_tile() -> IndexedPicture {
    IndexedPicture {
        width: TILE_SIZE as u32,
        height: TILE_SIZE as u32,
        pixels: vec![UNIT_TRANSPARENT_INDEX; (TILE_SIZE * TILE_SIZE) as usize],
    }
}

#[allow(clippy::too_many_arguments)]
fn blit_indexed(
    source: &IndexedPicture,
    src_x: i32,
    src_y: i32,
    width: i32,
    height: i32,
    destination: &mut IndexedPicture,
    dest_x: i32,
    dest_y: i32,
) {
    let dest_width = destination.width as i32;
    let dest_height = destination.height as i32;
    for row in 0..height {
        let destination_y = dest_y + row;
        let source_row = src_y + row;
        if !(0..dest_height).contains(&destination_y)
            || !(0..source.height as i32).contains(&source_row)
        {
            continue;
        }
        for column in 0..width {
            let destination_x = dest_x + column;
            let source_column = src_x + column;
            if !(0..dest_width).contains(&destination_x)
                || !(0..source.width as i32).contains(&source_column)
            {
                continue;
            }
            let pixel =
                source.pixels[source_row as usize * source.width as usize + source_column as usize];
            if pixel == UNIT_TRANSPARENT_INDEX {
                continue;
            }
            destination.pixels
                [destination_y as usize * destination.width as usize + destination_x as usize] =
                pixel;
        }
    }
}

fn draw_unit_frame(picture: &mut IndexedPicture, color: u8) {
    let width = picture.width as i32;
    let height = picture.height as i32;
    for x in 0..width {
        put_index(picture, x, 0, color);
        put_index(picture, x, height - 1, color);
    }
    for y in 0..height {
        put_index(picture, 0, y, color);
        put_index(picture, width - 1, y, color);
    }
}

fn put_index(picture: &mut IndexedPicture, x: i32, y: i32, color: u8) {
    if (0..picture.width as i32).contains(&x) && (0..picture.height as i32).contains(&y) {
        picture.pixels[y as usize * picture.width as usize + x as usize] = color;
    }
}

fn indexed_rgba_image(picture: &IndexedPicture, palette: &DibPalette, transparent: u8) -> Image {
    let mut rgba = Vec::with_capacity(picture.pixels.len() * 4);
    for &palette_index in &picture.pixels {
        let alpha = if palette_index == transparent {
            0
        } else {
            0xff
        };
        palette[palette_index].write_rgba(alpha, &mut rgba);
    }
    let mut image = Image::new(
        Extent3d {
            width: picture.width,
            height: picture.height,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        rgba,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    image
}

fn strategic_unit_project_key(state: &GameState) -> StrategicUnitProjectKey {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for unit in visible_strategic_units(state) {
        unit.hash(&mut hasher);
    }
    StrategicUnitProjectKey {
        view_origin: state.map_view_origin(),
        active_nation: state.turn().active_nation,
        fleet_atlas: fleet_atlas_picture_id(state).get(),
        visible: hasher.finish(),
    }
}

fn fleet_atlas_picture_id(state: &GameState) -> PictureId {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("strategic map requires an active major nation");
    let status = &state.technology().research_status_by_nation[nation];
    let mut variant = 0_i16;
    if status[Technology::AdvancedIronWorking] == TechnologyResearchStatus::Researched {
        variant = 1;
    }
    if status[Technology::MarineEngineering] == TechnologyResearchStatus::Researched {
        variant = 2;
    }
    PictureId::new(FLEET_ATLAS_PICTURE_BASE + i16::from(nation.get()) + variant * 7)
}

fn visible_strategic_units(state: &GameState) -> Vec<VisibleStrategicUnit> {
    let mut units = Vec::new();
    for_each_visible_strategic_tile(state, |tile, screen_x, screen_y| {
        if let Some(unit) = army_badge_on_tile(state, tile) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 1,
            });
        }
        if let Some(unit) = naval_marker_on_tile(state, tile) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 1,
            });
        }
        if let Some(unit) = civilian_on_tile(state, tile) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 2,
            });
        }
    });
    units
}

#[derive(Clone, Copy)]
struct ProjectedUnit {
    identity: StrategicUnitIdentity,
    sprite: StrategicUnitSprite,
}

fn civilian_on_tile(state: &GameState, tile: TileId) -> Option<ProjectedUnit> {
    if state.map()[tile].terrain == TerrainKind::Water {
        return None;
    }
    if !civilian_tile_is_visible(state.map()[tile].owner_nation, state.turn().active_nation) {
        return None;
    }
    let unit = stacked_civilian_on_tile(state.civilian_units(), tile, state.turn().active_nation)?;
    Some(ProjectedUnit {
        identity: StrategicUnitIdentity::Civilian(unit.id()),
        sprite: civilian_sprite(unit, state.turn().active_nation),
    })
}

fn army_badge_on_tile(state: &GameState, tile: TileId) -> Option<ProjectedUnit> {
    let tile_state = state.map()[tile];
    if tile_state.flags.bits() & 3 == 0 || tile_state.gate == 0 {
        return None;
    }
    let province = tile_state.province?;
    let mut present = false;
    let mut displayed = 0_u16;
    for unit in state.military_units() {
        if unit.stationed_province() != Some(province) {
            continue;
        }
        present = true;
        if !garrison_filler(unit.unit_type()) {
            displayed += 1;
        }
    }
    if !present {
        return None;
    }
    Some(ProjectedUnit {
        identity: StrategicUnitIdentity::Army(province),
        sprite: StrategicUnitSprite::Army {
            bucket: army_count_bucket(displayed),
            owner_slot: owner_flag_slot(tile_state.owner_nation),
        },
    })
}

fn naval_marker_on_tile(state: &GameState, tile: TileId) -> Option<ProjectedUnit> {
    if state.map()[tile].terrain != TerrainKind::Water {
        return None;
    }
    let frame = naval_action_frame(state.map()[tile].action)?;
    Some(ProjectedUnit {
        identity: StrategicUnitIdentity::Naval(tile),
        sprite: StrategicUnitSprite::Naval { frame },
    })
}

fn stacked_civilian_on_tile(
    units: &[CivilianUnitState],
    tile: TileId,
    active: NationId,
) -> Option<&CivilianUnitState> {
    let mut first = None;
    let mut owned = None;
    for unit in units {
        if unit.location().tile() != Some(tile) {
            continue;
        }
        if first.is_none() {
            first = Some(unit);
        }
        if owned.is_none() && unit.owner_nation() == active {
            owned = Some(unit);
        }
    }
    let selected = owned.or(first)?;
    (!selected.registered()).then_some(selected)
}

fn civilian_sprite(unit: &CivilianUnitState, active: NationId) -> StrategicUnitSprite {
    let foreign = unit.owner_nation() != active;
    StrategicUnitSprite::Civilian {
        kind: unit.unit_type(),
        pose: civilian_pose(unit.order(), foreign),
        owner_badge: foreign
            .then(|| owner_flag_slot(Some(TileOwnerTag::from_nation(unit.owner_nation())))),
        framed: foreign,
    }
}

fn civilian_pose(order: &CivilianWorkOrder, foreign: bool) -> CivilianPose {
    if civilian_uses_work_animation(order) && !foreign {
        CivilianPose::Animated
    } else if civilian_is_idle_selection(order) {
        CivilianPose::Idle
    } else {
        CivilianPose::Working
    }
}

fn civilian_is_idle_selection(order: &CivilianWorkOrder) -> bool {
    matches!(order, CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep)
}

fn civilian_uses_work_animation(order: &CivilianWorkOrder) -> bool {
    !matches!(
        order,
        CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep | CivilianWorkOrder::Redeploy { .. }
    )
}

fn civilian_sprite_class(kind: CivilianUnitKind) -> u8 {
    CIVILIAN_SPRITE_CLASS[kind]
}

fn civilian_tile_is_visible(owner: Option<TileOwnerTag>, active: NationId) -> bool {
    match owner {
        Some(owner) if owner.get() >= MajorNationId::COUNT => true,
        Some(owner) => owner.nation() == Some(active),
        None => false,
    }
}

fn garrison_filler(kind: MilitaryUnitKind) -> bool {
    matches!(
        kind,
        MilitaryUnitKind::Minutemen | MilitaryUnitKind::Militia | MilitaryUnitKind::Conscripts
    )
}

fn army_count_bucket(displayed: u16) -> u8 {
    match displayed {
        0 => 0,
        1..=5 => 1,
        6..=10 => 2,
        _ => 3,
    }
}

fn owner_flag_slot(owner: Option<TileOwnerTag>) -> u8 {
    match owner {
        Some(owner) if owner.get() < MajorNationId::COUNT => owner.get(),
        _ => MajorNationId::COUNT,
    }
}

fn naval_action_frame(action: Option<TileAction>) -> Option<u16> {
    let frame = action?.retail();
    (0..STRATEGIC_NAVAL_FRAME_COUNT)
        .contains(&frame)
        .then_some(frame as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_state() -> GameState {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
        save.game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: NationId::new(6),
        })
    }

    fn civilian(
        id: i32,
        kind: CivilianUnitKind,
        owner: NationId,
        tile: TileId,
        order: CivilianWorkOrder,
        registered: bool,
    ) -> CivilianUnitState {
        CivilianUnitState::new(
            CivilianUnitId::from_serialized(id),
            owner,
            kind,
            CivilianLocation::OnMap(tile),
            order,
            owner,
            0,
            registered,
        )
        .expect("test civilian is internally consistent")
    }

    #[test]
    fn idle_and_sleeping_civilians_use_the_idle_atlas_class() {
        assert_eq!(
            civilian_pose(&CivilianWorkOrder::Idle, false),
            CivilianPose::Idle
        );
        assert_eq!(
            civilian_pose(&CivilianWorkOrder::Sleep, false),
            CivilianPose::Idle
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Redeploy {
                    destination: TileId::new(1),
                    turns: TurnsRemaining::try_new(1).unwrap(),
                },
                false
            ),
            CivilianPose::Working
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Prospect {
                    turns: TurnsRemaining::try_new(1).unwrap(),
                },
                false
            ),
            CivilianPose::Animated
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Prospect {
                    turns: TurnsRemaining::try_new(1).unwrap(),
                },
                true
            ),
            CivilianPose::Working
        );
    }

    #[test]
    fn civilian_sprite_classes_match_the_retail_order_type_table() {
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Engineer), 0);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Farmer), 1);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Miner), 2);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Prospector), 3);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Developer), 4);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Fisherman), 5);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Forester), 6);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Rancher), 7);
        assert_eq!(civilian_sprite_class(CivilianUnitKind::Driller), 8);
    }

    #[test]
    fn stacking_prefers_the_active_nations_unregistered_civilian() {
        let tile = TileId::new(10);
        let active = NationId::new(6);
        let foreign = NationId::new(0);
        let units = [
            civilian(
                1,
                CivilianUnitKind::Miner,
                foreign,
                tile,
                CivilianWorkOrder::Idle,
                false,
            ),
            civilian(
                2,
                CivilianUnitKind::Engineer,
                active,
                tile,
                CivilianWorkOrder::Idle,
                false,
            ),
        ];
        let selected = stacked_civilian_on_tile(&units, tile, active).unwrap();
        assert_eq!(selected.id(), CivilianUnitId::from_serialized(2));
        assert_eq!(selected.unit_type(), CivilianUnitKind::Engineer);
    }

    #[test]
    fn registered_civilians_are_not_drawn_as_field_units() {
        let tile = TileId::new(10);
        let active = NationId::new(6);
        let units = [civilian(
            1,
            CivilianUnitKind::Miner,
            active,
            tile,
            CivilianWorkOrder::Idle,
            true,
        )];
        assert!(stacked_civilian_on_tile(&units, tile, active).is_none());
    }

    #[test]
    fn civilians_are_hidden_on_foreign_great_power_land() {
        let active = NationId::new(6);
        assert!(civilian_tile_is_visible(
            Some(TileOwnerTag::from_nation(active)),
            active
        ));
        assert!(!civilian_tile_is_visible(
            Some(TileOwnerTag::from_nation(NationId::new(0))),
            active
        ));
        assert!(civilian_tile_is_visible(Some(TileOwnerTag::new(8)), active));
        assert!(!civilian_tile_is_visible(None, active));
    }

    #[test]
    fn army_count_buckets_match_retail_thresholds() {
        assert_eq!(army_count_bucket(0), 0);
        assert_eq!(army_count_bucket(1), 1);
        assert_eq!(army_count_bucket(5), 1);
        assert_eq!(army_count_bucket(6), 2);
        assert_eq!(army_count_bucket(10), 2);
        assert_eq!(army_count_bucket(11), 3);
        assert!(garrison_filler(MilitaryUnitKind::Minutemen));
        assert!(garrison_filler(MilitaryUnitKind::Militia));
        assert!(garrison_filler(MilitaryUnitKind::Conscripts));
        assert!(!garrison_filler(MilitaryUnitKind::Regulars));
    }

    #[test]
    fn owner_flag_slots_collapse_minor_nations() {
        assert_eq!(
            owner_flag_slot(Some(TileOwnerTag::from_nation(NationId::new(3)))),
            3
        );
        assert_eq!(owner_flag_slot(Some(TileOwnerTag::new(8))), 7);
        assert_eq!(owner_flag_slot(None), 7);
    }

    #[test]
    fn naval_frames_are_the_non_negative_strategic_atlas_slots() {
        assert_eq!(naval_action_frame(TileAction::try_from_retail(2)), Some(2));
        assert_eq!(naval_action_frame(TileAction::try_from_retail(3)), Some(3));
        assert_eq!(
            naval_action_frame(TileAction::try_from_retail(17)),
            Some(17)
        );
        assert_eq!(naval_action_frame(TileAction::try_from_retail(18)), None);
        assert_eq!(naval_action_frame(TileAction::try_from_retail(-14)), None);
        assert_eq!(naval_action_frame(None), None);
    }

    #[test]
    fn viewport_iterator_matches_tile_screen_origins_and_clips_offscreen_rows() {
        let state = fixture_state();
        let mut seen = Vec::new();
        for_each_visible_strategic_tile(&state, |tile, x, y| {
            seen.push((tile, x, y));
            assert_eq!(
                super::super::strategic_tile_screen_origin(&state, tile),
                (x, y)
            );
            assert!(x < VIEWPORT_WIDTH as i32);
            assert!(x + TILE_SIZE > 0);
        });
        assert!(!seen.is_empty());
        let (origin_row, _) = state.map().geometry().row_column(state.map_view_origin());
        let outside = state
            .map()
            .geometry()
            .tile(origin_row.saturating_add(8), 0)
            .or_else(|| state.map().geometry().tile(origin_row.saturating_sub(1), 0));
        if let Some(outside) = outside {
            assert!(seen.iter().all(|(tile, _, _)| *tile != outside));
        }
    }

    #[test]
    fn beginning_of_game_projects_civilians_armies_and_fleets() {
        let mut state = fixture_state();
        state.center_map_on_first_idle_civilian();
        assert!(
            state
                .first_idle_civilian_tile(state.turn().active_nation)
                .is_some(),
            "opening save has an idle civilian"
        );
        assert!(
            visible_strategic_units(&state)
                .iter()
                .any(|unit| matches!(unit.identity, StrategicUnitIdentity::Civilian(_))),
            "opening save should show field civilians"
        );

        let army_tile = state
            .military_units()
            .iter()
            .find_map(|unit| {
                unit.stationed_province()
                    .and_then(|province| state.map().provinces[province].city_tile())
            })
            .expect("opening save has a stationed army");
        state.center_map_on(army_tile);
        assert!(
            visible_strategic_units(&state)
                .iter()
                .any(|unit| matches!(unit.identity, StrategicUnitIdentity::Army(_))),
            "opening save should show capital army badges"
        );

        let naval_tile = TileId::all()
            .find(|&tile| {
                state.map()[tile].terrain == TerrainKind::Water
                    && naval_action_frame(state.map()[tile].action).is_some()
            })
            .expect("opening save has an ocean action marker");
        state.center_map_on(naval_tile);
        assert!(
            visible_strategic_units(&state)
                .iter()
                .any(|unit| matches!(unit.identity, StrategicUnitIdentity::Naval(_))),
            "opening save should show ocean action fleet markers"
        );
    }
}
