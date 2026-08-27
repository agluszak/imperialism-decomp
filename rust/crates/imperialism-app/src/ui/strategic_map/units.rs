//! Read-only projection of authoritative units onto the strategic map.
//!
//! Retail `TMapDialog::DrawOneTile` blits civilians, army-count badges, and ocean
//! action frames into the tile cache. This module keeps those sprites as disposable
//! Bevy entities over the composed terrain bitmap.

use super::super::GameSession;
use super::RetailUiAssets;
use super::StrategicMapSession;
use super::map_projection::DetailedMapProjection;
use super::{TILE_SIZE, VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use crate::ui::retail_raster::{IndexedRasterExt, indexed_picture};
use bevy::prelude::*;
use enum_map::Enum;
use imperialism_core::*;
use imperialism_formats::*;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;

const UNIT_TRANSPARENT_INDEX: u8 = 0x10;
const FOREIGN_CIVILIAN_FRAME_INDEX: u8 = 0x13;
const STRATEGIC_NAVAL_FRAME_COUNT: i16 = 18;
const OCEAN_ATLAS_FRAME_COUNT: i16 = 19;
const CIVILIAN_IDLE_PICTURE_BASE: PictureId = PictureId::new(400);
const CIVILIAN_WORKING_PICTURE_BASE: PictureId = PictureId::new(418);
const ARMY_COUNT_PICTURE_IDS: [PictureId; 4] = [
    PictureId::new(570),
    PictureId::new(572),
    PictureId::new(574),
    PictureId::new(576),
];
const SELECTED_ARMY_COUNT_PICTURE_IDS: [PictureId; 4] = [
    PictureId::new(571),
    PictureId::new(573),
    PictureId::new(575),
    PictureId::new(577),
];
const OWNER_FLAG_PICTURE_ID: PictureId = PictureId::new(580);
const FORT_PICTURE_IDS: [PictureId; 3] = [
    PictureId::new(560),
    PictureId::new(561),
    PictureId::new(562),
];
const ORDER_MARKER_PICTURE_ID: PictureId = PictureId::new(806);
const FLEET_ATLAS_PICTURE_BASE: PictureId = PictureId::new(1_380);
const CIVILIAN_SPRITE_CLASS: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([2, 3, 1, 6, 0, 7, 5, 4, 8]);
const CIVILIAN_ANIMATION_PICTURE_IDS: CivilianUnitTable<PictureId> =
    CivilianUnitTable::from_array([
        PictureId::new(14_000),
        PictureId::new(14_005),
        PictureId::new(14_011),
        PictureId::new(14_015),
        PictureId::new(14_021),
        PictureId::new(14_026),
        PictureId::new(14_030),
        PictureId::new(14_035),
        PictureId::new(14_040),
    ]);
const CIVILIAN_ANIMATION_FRAME_COUNTS: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([5, 4, 2, 4, 3, 2, 3, 3, 2]);
const CIVILIAN_ANIMATION_LOGICAL_COUNTS: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([9, 7, 2, 5, 6, 2, 5, 9, 5]);
const CIVILIAN_ANIMATION_TICKS_PER_FRAME: CivilianUnitTable<u8> =
    CivilianUnitTable::from_array([5, 15, 10, 7, 15, 15, 7, 10, 10]);
const STRATEGIC_SELECTION_PULSE_TICKS: u32 = 30;
const RETAIL_UI_TICK_MILLIS: u64 = 16;
const CIVILIAN_ANIMATION_FRAME_MAP: CivilianUnitTable<[u8; 12]> = CivilianUnitTable::from_array([
    [0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 2, 3, 1, 1, 1, 1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 1, 2, 0, 0, 0, 0],
    [0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CivilianPose {
    Idle,
    Selected,
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
        frame: u8,
        owner_badge: Option<u8>,
        framed: bool,
    },
    Army {
        bucket: u8,
        owner_slot: u8,
        fort_level: u8,
        order_marker: u8,
        selected: bool,
    },
    Naval {
        frame: u16,
        selected: bool,
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
    fleet_atlas: PictureId,
    visible: u64,
}

#[derive(Component)]
pub(crate) struct StrategicUnitLayer {
    projected: Option<StrategicUnitProjectKey>,
}

#[derive(Component)]
pub(crate) struct StrategicMapUnit;

#[derive(Component)]
pub(crate) struct CivilianWorkAnimation {
    kind: CivilianUnitKind,
    logical_frame: u8,
    timer: Timer,
}

#[derive(Component)]
pub(crate) struct StrategicSelectionAnimation {
    normal: StrategicUnitSprite,
    alternate: StrategicUnitSprite,
}

pub(crate) struct StrategicSelectionPulse {
    timer: Timer,
    phase: bool,
}

impl Default for StrategicSelectionPulse {
    fn default() -> Self {
        Self {
            timer: Timer::new(
                Duration::from_millis(
                    u64::from(STRATEGIC_SELECTION_PULSE_TICKS) * RETAIL_UI_TICK_MILLIS,
                ),
                TimerMode::Repeating,
            ),
            phase: false,
        }
    }
}

impl StrategicSelectionPulse {
    fn tick(&mut self, delta: Duration) -> Option<bool> {
        self.timer.tick(delta);
        self.timer.just_finished().then(|| {
            let rendered_phase = self.phase;
            self.phase = !self.phase;
            rendered_phase
        })
    }
}

#[derive(Component)]
pub(crate) struct StrategicUnitSprites {
    civilians: HashMap<(CivilianUnitKind, CivilianPose), Vec<IndexedPicture>>,
    army_counts: [IndexedPicture; 4],
    selected_army_counts: [IndexedPicture; 4],
    owner_flags: IndexedPicture,
    forts: [IndexedPicture; 3],
    order_markers: IndexedPicture,
    fleet_frames: Vec<IndexedPicture>,
    fleet_atlas_id: PictureId,
    composed: HashMap<StrategicUnitSprite, Handle<Image>>,
}

pub(super) fn bind_strategic_units(
    commands: &mut Commands,
    map: Entity,
    assets: &mut RetailUiAssets,
    state: &GameState,
    view_origin: TileId,
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
    project_strategic_units_onto(
        commands,
        layer,
        &mut sprites,
        assets,
        state,
        view_origin,
        None,
        None,
        None,
    );
    commands.entity(layer).insert((
        StrategicUnitLayer {
            projected: Some(strategic_unit_project_key(
                state,
                view_origin,
                None,
                None,
                None,
            )),
        },
        sprites,
    ));
}

pub(crate) fn sync_strategic_units(
    mut commands: Commands,
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    mut assets: RetailUiAssets,
    mut layers: Query<(
        Entity,
        &mut StrategicUnitLayer,
        &mut StrategicUnitSprites,
        Option<&Children>,
    )>,
    units: Query<Entity, With<StrategicMapUnit>>,
) {
    let state = &session.game;
    let origin = map.view.detailed_origin(state);
    for (layer, mut projection, mut sprites, children) in &mut layers {
        let selected_civilian = map.selection.civilian();
        let selected_army = map.selection.army();
        let selected_navy = map.selection.navy_zone();
        let fleet_id = fleet_atlas_picture_id(state);
        if sprites.fleet_atlas_id != fleet_id {
            sprites.fleet_frames = load_fleet_frames(&assets, state);
            sprites.fleet_atlas_id = fleet_id;
            sprites.composed.clear();
        }
        let key = strategic_unit_project_key(
            state,
            origin,
            selected_civilian,
            selected_army,
            selected_navy,
        );
        if projection.projected == Some(key) {
            continue;
        }
        despawn_projected_units(&mut commands, children, &units);
        project_strategic_units_onto(
            &mut commands,
            layer,
            &mut sprites,
            &mut assets,
            state,
            origin,
            selected_civilian,
            selected_army,
            selected_navy,
        );
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
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    selected_army: Option<ProvinceId>,
    selected_navy: Option<OceanZoneId>,
) {
    let palette = *assets.default_dib_palette();
    for unit in visible_strategic_units(
        state,
        view_origin,
        selected_civilian,
        selected_army,
        selected_navy,
    ) {
        let selection = match unit.sprite {
            StrategicUnitSprite::Civilian {
                kind,
                pose: CivilianPose::Selected,
                ..
            } => Some((
                civilian_selection_sprite(kind, false),
                civilian_selection_sprite(kind, true),
            )),
            StrategicUnitSprite::Army { selected: true, .. } => Some((
                army_selection_sprite(unit.sprite, false),
                army_selection_sprite(unit.sprite, true),
            )),
            StrategicUnitSprite::Naval { selected: true, .. } => Some((
                naval_selection_sprite(unit.sprite, false),
                naval_selection_sprite(unit.sprite, true),
            )),
            _ => None,
        };
        let rendered_sprite = selection.map(|(normal, _)| normal).unwrap_or(unit.sprite);
        let Some(image) = unit_sprite_image(sprites, assets, &palette, rendered_sprite) else {
            continue;
        };
        let framed = matches!(
            unit.sprite,
            StrategicUnitSprite::Civilian { framed: true, .. }
        );
        let frame_margin = i32::from(framed);
        let width = TILE_SIZE + frame_margin * 2;
        let height = TILE_SIZE + frame_margin * 2;
        let mut entity = commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px((unit.screen_x - frame_margin) as f32),
                top: Val::Px((unit.screen_y - frame_margin) as f32),
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
        if let StrategicUnitSprite::Civilian {
            kind,
            pose: CivilianPose::Animated,
            ..
        } = unit.sprite
        {
            entity.insert(CivilianWorkAnimation {
                kind,
                logical_frame: 0,
                timer: Timer::from_seconds(
                    f32::from(CIVILIAN_ANIMATION_TICKS_PER_FRAME[kind]) * 0.016,
                    TimerMode::Repeating,
                ),
            });
        }
        if let Some((normal, alternate)) = selection {
            entity.insert(StrategicSelectionAnimation { normal, alternate });
        }
    }
}

pub(crate) fn animate_strategic_selection(
    time: Res<Time>,
    mut pulse: Local<StrategicSelectionPulse>,
    mut assets: RetailUiAssets,
    mut layers: Query<(&mut StrategicUnitSprites, &Children)>,
    mut units: Query<(&StrategicSelectionAnimation, &mut ImageNode)>,
) {
    if units.is_empty() {
        return;
    }
    let Some(outlined) = pulse.tick(time.delta()) else {
        return;
    };
    let palette = *assets.default_dib_palette();
    for (mut sprites, children) in &mut layers {
        for child in children {
            let Ok((selection, mut image)) = units.get_mut(*child) else {
                continue;
            };
            let sprite = if outlined {
                selection.alternate
            } else {
                selection.normal
            };
            if let Some(handle) = unit_sprite_image(&mut sprites, &mut assets, &palette, sprite) {
                image.image = handle;
            }
        }
    }
}

pub(crate) fn animate_civilian_work(
    time: Res<Time>,
    mut session: ResMut<GameSession>,
    mut assets: RetailUiAssets,
    mut layers: Query<(&mut StrategicUnitSprites, &Children)>,
    mut units: Query<(&mut CivilianWorkAnimation, &mut ImageNode)>,
) {
    let palette = *assets.default_dib_palette();
    for (mut sprites, children) in &mut layers {
        for child in children {
            let Ok((mut animation, mut image)) = units.get_mut(*child) else {
                continue;
            };
            animation.timer.tick(time.delta());
            if !animation.timer.just_finished() {
                continue;
            }
            let kind = animation.kind;
            let next = animation.logical_frame + 1;
            animation.logical_frame = if kind == CivilianUnitKind::Rancher {
                if next == 2
                    || (next == 1 && session.game.next_civilian_animation_rand() % 100 <= 49)
                {
                    0
                } else {
                    next
                }
            } else if next == CIVILIAN_ANIMATION_LOGICAL_COUNTS[kind] {
                0
            } else {
                next
            };
            let frame = CIVILIAN_ANIMATION_FRAME_MAP[kind][usize::from(animation.logical_frame)];
            let sprite = StrategicUnitSprite::Civilian {
                kind,
                pose: CivilianPose::Animated,
                frame,
                owner_badge: None,
                framed: false,
            };
            if let Some(handle) = unit_sprite_image(&mut sprites, &mut assets, &palette, sprite) {
                image.image = handle;
            }
        }
    }
}

fn load_strategic_unit_sprites(assets: &RetailUiAssets, state: &GameState) -> StrategicUnitSprites {
    let mut civilians = HashMap::new();
    for kind in (0..CivilianUnitKind::LENGTH).map(CivilianUnitKind::from_usize) {
        for pose in [
            CivilianPose::Idle,
            CivilianPose::Selected,
            CivilianPose::Working,
            CivilianPose::Animated,
        ] {
            if let Some(pictures) = load_civilian_pictures(assets, kind, pose) {
                civilians.insert((kind, pose), pictures);
            }
        }
    }
    let army_counts = ARMY_COUNT_PICTURE_IDS.map(|id| load_required_picture(assets, id));
    let selected_army_counts =
        SELECTED_ARMY_COUNT_PICTURE_IDS.map(|id| load_required_picture(assets, id));
    let owner_flags = load_required_picture(assets, OWNER_FLAG_PICTURE_ID);
    let forts = FORT_PICTURE_IDS.map(|id| load_required_picture(assets, id));
    let order_markers = load_required_picture(assets, ORDER_MARKER_PICTURE_ID);
    let fleet_atlas_id = fleet_atlas_picture_id(state);
    let fleet_frames = load_fleet_frames(assets, state);
    StrategicUnitSprites {
        civilians,
        army_counts,
        selected_army_counts,
        owner_flags,
        forts,
        order_markers,
        fleet_frames,
        fleet_atlas_id,
        composed: HashMap::new(),
    }
}

fn load_civilian_pictures(
    assets: &RetailUiAssets,
    kind: CivilianUnitKind,
    pose: CivilianPose,
) -> Option<Vec<IndexedPicture>> {
    let picture_id = civilian_picture_id(kind, pose);
    if pose == CivilianPose::Animated {
        return (0..CIVILIAN_ANIMATION_FRAME_COUNTS[kind])
            .map(|frame| {
                assets
                    .indexed_picture(picture_id.offset(i16::from(frame)))
                    .ok()
                    .map(first_tile_frame)
            })
            .collect();
    }
    if let Ok(picture) = assets.indexed_picture(picture_id) {
        return Some(vec![first_tile_frame(picture)]);
    }
    assets
        .indexed_picture(civilian_picture_id(kind, CivilianPose::Animated))
        .ok()
        .map(|picture| vec![first_tile_frame(picture)])
}

fn civilian_picture_id(kind: CivilianUnitKind, pose: CivilianPose) -> PictureId {
    match pose {
        CivilianPose::Idle => {
            CIVILIAN_IDLE_PICTURE_BASE.offset(i16::from(civilian_sprite_class(kind)))
        }
        CivilianPose::Selected => {
            CIVILIAN_IDLE_PICTURE_BASE.offset(9 + i16::from(civilian_sprite_class(kind)))
        }
        CivilianPose::Working => {
            CIVILIAN_WORKING_PICTURE_BASE.offset(i16::from(civilian_sprite_class(kind)))
        }
        CivilianPose::Animated => CIVILIAN_ANIMATION_PICTURE_IDS[kind],
    }
}

fn load_fleet_frames(assets: &RetailUiAssets, state: &GameState) -> Vec<IndexedPicture> {
    let atlas = load_required_picture(assets, fleet_atlas_picture_id(state));
    (0..OCEAN_ATLAS_FRAME_COUNT as u32)
        .filter_map(|frame| {
            let x = frame * TILE_SIZE as u32;
            (x + TILE_SIZE as u32 <= atlas.width)
                .then(|| atlas.crop(IRect::new(x as i32, 0, x as i32 + TILE_SIZE, TILE_SIZE)))
        })
        .collect()
}

fn load_required_picture(assets: &RetailUiAssets, picture_id: PictureId) -> IndexedPicture {
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
        picture.crop(IRect::new(0, 0, width as i32, height as i32))
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
    let handle = assets.add_image(picture.to_keyed_image(palette, UNIT_TRANSPARENT_INDEX));
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
            frame,
            owner_badge,
            framed,
        } => {
            let mut picture = sprites
                .civilians
                .get(&(kind, pose))?
                .get(usize::from(frame))?
                .clone();
            if let Some(slot) = owner_badge {
                let source_x = i32::from(slot) * 9;
                picture.blit_keyed(
                    &sprites.owner_flags,
                    IRect::new(source_x, 0, source_x + 9, 6),
                    IVec2::new(28, 2),
                    UNIT_TRANSPARENT_INDEX,
                );
            }
            if framed {
                let mut framed = indexed_picture(
                    picture.width as i32 + 2,
                    picture.height as i32 + 2,
                    UNIT_TRANSPARENT_INDEX,
                );
                framed.blit_keyed_at(&picture, IVec2::ONE, UNIT_TRANSPARENT_INDEX);
                framed.frame_rect(
                    IRect::new(0, 0, framed.width as i32, framed.height as i32),
                    FOREIGN_CIVILIAN_FRAME_INDEX,
                );
                picture = framed;
            }
            Some(picture)
        }
        StrategicUnitSprite::Army {
            bucket,
            owner_slot,
            fort_level,
            order_marker,
            selected,
        } => {
            let counts = if selected {
                &sprites.selected_army_counts
            } else {
                &sprites.army_counts
            };
            let count = counts.get(usize::from(bucket))?;
            let mut picture = indexed_picture(TILE_SIZE, TILE_SIZE, UNIT_TRANSPARENT_INDEX);
            picture.blit_keyed_at(count, IVec2::ZERO, UNIT_TRANSPARENT_INDEX);
            let source_x = i32::from(owner_slot) * 9;
            picture.blit_keyed(
                &sprites.owner_flags,
                IRect::new(source_x, 0, source_x + 9, 6),
                IVec2::new(7, 2),
                UNIT_TRANSPARENT_INDEX,
            );
            if fort_level > 0 {
                picture.blit_keyed_at(
                    sprites.forts.get(usize::from(fort_level - 1))?,
                    IVec2::ZERO,
                    UNIT_TRANSPARENT_INDEX,
                );
            }
            if order_marker > 0 {
                let source_x = (i32::from(order_marker) - 1) * TILE_SIZE;
                picture.blit_keyed(
                    &sprites.order_markers,
                    IRect::new(source_x, 0, source_x + TILE_SIZE, TILE_SIZE),
                    IVec2::ZERO,
                    UNIT_TRANSPARENT_INDEX,
                );
            }
            Some(picture)
        }
        StrategicUnitSprite::Naval { frame, .. } => {
            sprites.fleet_frames.get(usize::from(frame)).cloned()
        }
    }
}

fn strategic_unit_project_key(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    selected_army: Option<ProvinceId>,
    selected_navy: Option<OceanZoneId>,
) -> StrategicUnitProjectKey {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for unit in visible_strategic_units(
        state,
        view_origin,
        selected_civilian,
        selected_army,
        selected_navy,
    ) {
        unit.hash(&mut hasher);
    }
    StrategicUnitProjectKey {
        view_origin,
        active_nation: state.turn().active_nation,
        fleet_atlas: fleet_atlas_picture_id(state),
        visible: hasher.finish(),
    }
}

fn fleet_atlas_picture_id(state: &GameState) -> PictureId {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("strategic map requires an active major nation");
    let status = &state.technology().research_status_by_nation[nation];
    let variant = fleet_atlas_variant(
        status[Technology::AdvancedIronWorking],
        status[Technology::MarineEngineering],
    );
    FLEET_ATLAS_PICTURE_BASE.offset(i16::from(nation.get()) + variant * 7)
}

fn fleet_atlas_variant(
    advanced_iron_working: TechnologyResearchStatus,
    marine_engineering: TechnologyResearchStatus,
) -> i16 {
    if marine_engineering != TechnologyResearchStatus::NotStarted {
        2
    } else if advanced_iron_working != TechnologyResearchStatus::NotStarted {
        1
    } else {
        0
    }
}

fn visible_strategic_units(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    selected_army: Option<ProvinceId>,
    selected_navy: Option<OceanZoneId>,
) -> Vec<VisibleStrategicUnit> {
    let mut units = Vec::new();
    let selected_navy_tile = selected_navy.and_then(|zone| {
        state
            .ocean()
            .zones
            .get(usize::from(zone.get()))?
            .zone()
            .active_tile
    });
    let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
    for projected in projection.visible_tiles() {
        let tile = projected.tile;
        let screen_x = projected.origin.x;
        let screen_y = projected.origin.y;
        if let Some(unit) = army_badge_on_tile(state, tile, selected_army) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 1,
            });
        }
        if let Some(unit) = naval_marker_on_tile(state, tile, selected_navy_tile) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 1,
            });
        }
        if let Some(unit) = civilian_on_tile(state, tile, selected_civilian) {
            units.push(VisibleStrategicUnit {
                identity: unit.identity,
                screen_x,
                screen_y,
                sprite: unit.sprite,
                z: 2,
            });
        }
    }
    units
}

#[derive(Clone, Copy)]
struct ProjectedUnit {
    identity: StrategicUnitIdentity,
    sprite: StrategicUnitSprite,
}

fn civilian_on_tile(
    state: &GameState,
    tile: TileId,
    selected: Option<CivilianUnitId>,
) -> Option<ProjectedUnit> {
    if state.map()[tile].terrain == TerrainKind::Water {
        return None;
    }
    if !civilian_tile_is_visible(state.map()[tile].owner_nation, state.turn().active_nation) {
        return None;
    }
    let (id, unit) = chained_civilian_on_tile(state, tile, state.turn().active_nation)?;
    Some(ProjectedUnit {
        identity: StrategicUnitIdentity::Civilian(id),
        sprite: civilian_sprite(unit, state.turn().active_nation, selected == Some(id)),
    })
}

fn army_badge_on_tile(
    state: &GameState,
    tile: TileId,
    selected: Option<ProvinceId>,
) -> Option<ProjectedUnit> {
    let tile_state = state.map()[tile];
    if tile_state.flags.bits() & 3 == 0 || tile_state.gate == 0 {
        return None;
    }
    let province = tile_state.province?;
    let mut present = false;
    let mut displayed = 0_u16;
    for (_, unit) in state.military_units() {
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
            fort_level: state.map().provinces[province].fort_level().retail() as u8,
            order_marker: u8::try_from(tile_state.per_tile_visited).unwrap_or(0),
            selected: selected == Some(province),
        },
    })
}

fn army_selection_sprite(sprite: StrategicUnitSprite, selected: bool) -> StrategicUnitSprite {
    let StrategicUnitSprite::Army {
        bucket,
        owner_slot,
        fort_level,
        order_marker,
        ..
    } = sprite
    else {
        unreachable!("army selection animation requires an army sprite")
    };
    StrategicUnitSprite::Army {
        bucket,
        owner_slot,
        fort_level,
        order_marker,
        selected,
    }
}

fn naval_selection_sprite(sprite: StrategicUnitSprite, alternate: bool) -> StrategicUnitSprite {
    let StrategicUnitSprite::Naval { frame, .. } = sprite else {
        unreachable!("navy selection animation requires a naval sprite")
    };
    StrategicUnitSprite::Naval {
        frame: frame + u16::from(alternate),
        selected: alternate,
    }
}

fn naval_marker_on_tile(
    state: &GameState,
    tile: TileId,
    selected: Option<TileId>,
) -> Option<ProjectedUnit> {
    if state.map()[tile].terrain != TerrainKind::Water {
        return None;
    }
    let frame = naval_action_frame(state.map()[tile].action)?;
    Some(ProjectedUnit {
        identity: StrategicUnitIdentity::Naval(tile),
        sprite: StrategicUnitSprite::Naval {
            frame,
            selected: selected == Some(tile),
        },
    })
}

fn chained_civilian_on_tile(
    state: &GameState,
    tile: TileId,
    active: NationId,
) -> Option<(CivilianUnitId, &CivilianUnitState)> {
    let selected = state
        .civilian_on_tile_for_nation(tile, active)
        .or_else(|| {
            let id = state.civilian_chain_head_on_tile(tile)?;
            Some((id, state.civilian_unit(id)?))
        })?;
    (!selected.1.registered()).then_some(selected)
}

fn civilian_sprite(
    unit: &CivilianUnitState,
    active: NationId,
    selected: bool,
) -> StrategicUnitSprite {
    let foreign = unit.owner_nation() != active;
    StrategicUnitSprite::Civilian {
        kind: unit.unit_type(),
        pose: civilian_pose(unit.order(), foreign, selected),
        frame: 0,
        owner_badge: foreign
            .then(|| owner_flag_slot(Some(TileOwnerTag::from_nation(unit.owner_nation())))),
        framed: foreign,
    }
}

fn civilian_selection_sprite(kind: CivilianUnitKind, outlined: bool) -> StrategicUnitSprite {
    StrategicUnitSprite::Civilian {
        kind,
        pose: if outlined {
            CivilianPose::Selected
        } else {
            CivilianPose::Idle
        },
        frame: 0,
        owner_badge: None,
        framed: false,
    }
}

fn civilian_pose(order: &CivilianWorkOrder, foreign: bool, selected: bool) -> CivilianPose {
    if selected && civilian_is_idle_selection(order) && !foreign {
        CivilianPose::Selected
    } else if civilian_uses_work_animation(order) && !foreign {
        CivilianPose::Animated
    } else if civilian_is_idle_selection(order) {
        CivilianPose::Idle
    } else {
        CivilianPose::Working
    }
}

fn civilian_is_idle_selection(order: &CivilianWorkOrder) -> bool {
    matches!(
        order,
        CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep | CivilianWorkOrder::Later
    )
}

fn civilian_uses_work_animation(order: &CivilianWorkOrder) -> bool {
    !matches!(
        order,
        CivilianWorkOrder::Idle
            | CivilianWorkOrder::Sleep
            | CivilianWorkOrder::Later
            | CivilianWorkOrder::Done
            | CivilianWorkOrder::Redeploy { .. }
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
    use crate::ui::test_support::{
        beginning_map_view_origin, beginning_of_game_parts_with, beginning_of_game_with,
        strategic_map_beginning_context,
    };

    fn fixture_state() -> GameState {
        beginning_of_game_with(strategic_map_beginning_context())
    }

    fn civilian(
        id: i32,
        kind: CivilianUnitKind,
        owner: NationId,
        tile: TileId,
        order: CivilianWorkOrder,
        registered: bool,
    ) -> (CivilianUnitId, CivilianUnitState) {
        let id = CivilianUnitId::from_serialized(id);
        let state = CivilianUnitState::new(
            owner,
            kind,
            CivilianLocation::OnMap(tile),
            order,
            owner,
            0,
            registered,
        )
        .expect("test civilian is internally consistent");
        (id, state)
    }

    #[test]
    fn idle_and_sleeping_civilians_use_the_idle_atlas_class() {
        assert_eq!(
            civilian_pose(&CivilianWorkOrder::Idle, false, false),
            CivilianPose::Idle
        );
        assert_eq!(
            civilian_pose(&CivilianWorkOrder::Sleep, false, false),
            CivilianPose::Idle
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Redeploy {
                    source: TileId::new(1),
                    turns: 1,
                },
                false,
                false,
            ),
            CivilianPose::Working
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Prospect {
                    source: TileId::new(1),
                    turns: 1,
                },
                false,
                false,
            ),
            CivilianPose::Animated
        );
        assert_eq!(
            civilian_pose(
                &CivilianWorkOrder::Prospect {
                    source: TileId::new(1),
                    turns: 1,
                },
                true,
                false,
            ),
            CivilianPose::Working
        );
    }

    #[test]
    fn selected_idle_civilian_uses_the_white_outline_atlas_group() {
        assert_eq!(
            civilian_pose(&CivilianWorkOrder::Idle, false, true),
            CivilianPose::Selected
        );
        assert_eq!(
            civilian_picture_id(CivilianUnitKind::Engineer, CivilianPose::Selected),
            PictureId::new(409)
        );
    }

    #[test]
    fn selected_civilian_projection_uses_the_white_outline_sprite() {
        let state = fixture_state();
        let active = state.turn().active_nation;
        let (selected, tile) = state
            .civilian_units()
            .find_map(|(id, unit)| {
                (unit.owner_nation() == active
                    && civilian_is_idle_selection(unit.order())
                    && !unit.registered())
                .then(|| unit.location().tile().map(|tile| (id, tile)))
                .flatten()
            })
            .expect("opening save has an idle field civilian");
        let view_origin = state.map().viewport_origin_centered_on(tile);

        let projected = visible_strategic_units(&state, view_origin, Some(selected), None, None)
            .into_iter()
            .find(|unit| unit.identity == StrategicUnitIdentity::Civilian(selected))
            .expect("selected civilian is visible");
        assert!(matches!(
            projected.sprite,
            StrategicUnitSprite::Civilian {
                pose: CivilianPose::Selected,
                ..
            }
        ));
    }

    #[test]
    fn selected_civilian_pulse_matches_the_retail_thirty_tick_phase_flip() {
        let mut pulse = StrategicSelectionPulse::default();
        assert_eq!(pulse.tick(Duration::from_millis(479)), None);
        assert_eq!(pulse.tick(Duration::from_millis(1)), Some(false));
        assert_eq!(pulse.tick(Duration::from_millis(480)), Some(true));
        assert_eq!(
            civilian_selection_sprite(CivilianUnitKind::Engineer, false),
            StrategicUnitSprite::Civilian {
                kind: CivilianUnitKind::Engineer,
                pose: CivilianPose::Idle,
                frame: 0,
                owner_badge: None,
                framed: false,
            }
        );
        assert_eq!(
            civilian_selection_sprite(CivilianUnitKind::Engineer, true),
            StrategicUnitSprite::Civilian {
                kind: CivilianUnitKind::Engineer,
                pose: CivilianPose::Selected,
                frame: 0,
                owner_badge: None,
                framed: false,
            }
        );
    }

    #[test]
    fn selected_army_projection_uses_the_alternate_count_phase() {
        let state = fixture_state();
        let (province, tile) = state
            .military_units()
            .find_map(|(_, unit)| {
                unit.stationed_province().and_then(|province| {
                    state.map().provinces[province]
                        .city_tile()
                        .map(|tile| (province, tile))
                })
            })
            .expect("opening save has a stationed army");
        let view_origin = state.map().viewport_origin_centered_on(tile);

        let projected = visible_strategic_units(&state, view_origin, None, Some(province), None)
            .into_iter()
            .find(|unit| unit.identity == StrategicUnitIdentity::Army(province))
            .expect("selected army is visible");
        assert!(matches!(
            projected.sprite,
            StrategicUnitSprite::Army { selected: true, .. }
        ));
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
    fn loader_stack_prefers_the_active_nation_below_a_foreign_head() {
        let tile = TileId::new(10);
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let active = parts.turn.active_nation;
        let foreign = NationId::new((active.get() + 1) % MajorNationId::COUNT);
        let active_unit = civilian(
            1,
            CivilianUnitKind::Engineer,
            active,
            tile,
            CivilianWorkOrder::Idle,
            false,
        );
        let foreign_head = civilian(
            2,
            CivilianUnitKind::Miner,
            foreign,
            tile,
            CivilianWorkOrder::Idle,
            false,
        );
        parts.civilian_units.clear();
        parts.civilian_units.insert(active_unit.0, active_unit.1);
        parts.civilian_units.insert(foreign_head.0, foreign_head.1);
        let state = GameState::from_parts(parts);

        assert_eq!(
            state.civilian_chain_head_on_tile(tile),
            Some(foreign_head.0)
        );
        let (id, selected) = chained_civilian_on_tile(&state, tile, active).unwrap();
        assert_eq!(id, active_unit.0);
        assert_eq!(selected.unit_type(), CivilianUnitKind::Engineer);
    }

    #[test]
    fn registered_civilians_are_not_drawn_as_field_units() {
        let tile = TileId::new(10);
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let active = parts.turn.active_nation;
        let unit = civilian(
            1,
            CivilianUnitKind::Miner,
            active,
            tile,
            CivilianWorkOrder::Idle,
            true,
        );
        parts.civilian_units.clear();
        parts.civilian_units.insert(unit.0, unit.1);
        let state = GameState::from_parts(parts);
        assert!(chained_civilian_on_tile(&state, tile, active).is_none());
    }

    #[test]
    fn stacking_falls_back_to_the_foreign_chain_head() {
        let tile = TileId::new(10);
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let active = parts.turn.active_nation;
        let foreign = NationId::new((active.get() + 1) % MajorNationId::COUNT);
        let unit = civilian(
            1,
            CivilianUnitKind::Miner,
            foreign,
            tile,
            CivilianWorkOrder::Idle,
            false,
        );
        parts.civilian_units.clear();
        parts.civilian_units.insert(unit.0, unit.1);
        let state = GameState::from_parts(parts);

        assert_eq!(
            chained_civilian_on_tile(&state, tile, active).unwrap().0,
            unit.0
        );
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
    fn army_badge_uses_the_displayed_top_down_coordinates() {
        let count = IndexedPicture {
            width: 18,
            height: 38,
            pixels: vec![2; 18 * 38],
        };
        let flags = IndexedPicture {
            width: 9 * 8,
            height: 6,
            pixels: vec![3; 9 * 8 * 6],
        };
        let sprites = StrategicUnitSprites {
            civilians: HashMap::new(),
            army_counts: std::array::from_fn(|_| count.clone()),
            selected_army_counts: std::array::from_fn(|_| count.clone()),
            owner_flags: flags,
            forts: std::array::from_fn(|_| indexed_picture(TILE_SIZE, TILE_SIZE, 0x10)),
            order_markers: indexed_picture(TILE_SIZE, TILE_SIZE, 0x10),
            fleet_frames: Vec::new(),
            fleet_atlas_id: PictureId::new(0),
            composed: HashMap::new(),
        };

        let picture = compose_unit_sprite(
            &sprites,
            StrategicUnitSprite::Army {
                bucket: 0,
                owner_slot: 0,
                fort_level: 0,
                order_marker: 0,
                selected: false,
            },
        )
        .unwrap();
        assert_eq!(picture.pixels[0], 2);
        assert_eq!(picture.pixels[2 * TILE_SIZE as usize + 7], 3);
        assert_eq!(
            picture.pixels[56 * TILE_SIZE as usize + 7],
            UNIT_TRANSPARENT_INDEX
        );
    }

    #[test]
    fn fort_and_order_marker_reapply_above_the_army_badge_in_retail_order() {
        let count = IndexedPicture {
            width: 18,
            height: 38,
            pixels: vec![2; 18 * 38],
        };
        let mut fort = indexed_picture(TILE_SIZE, TILE_SIZE, UNIT_TRANSPARENT_INDEX);
        fort.pixels[0] = 4;
        let mut marker = indexed_picture(TILE_SIZE, TILE_SIZE, UNIT_TRANSPARENT_INDEX);
        marker.pixels[0] = 5;
        let sprites = StrategicUnitSprites {
            civilians: HashMap::new(),
            army_counts: std::array::from_fn(|_| count.clone()),
            selected_army_counts: std::array::from_fn(|_| count.clone()),
            owner_flags: indexed_picture(9, 6, UNIT_TRANSPARENT_INDEX),
            forts: std::array::from_fn(|_| fort.clone()),
            order_markers: marker,
            fleet_frames: Vec::new(),
            fleet_atlas_id: PictureId::new(0),
            composed: HashMap::new(),
        };

        let fort_only = compose_unit_sprite(
            &sprites,
            StrategicUnitSprite::Army {
                bucket: 0,
                owner_slot: 0,
                fort_level: 1,
                order_marker: 0,
                selected: false,
            },
        )
        .unwrap();
        let marked = compose_unit_sprite(
            &sprites,
            StrategicUnitSprite::Army {
                bucket: 0,
                owner_slot: 0,
                fort_level: 1,
                order_marker: 1,
                selected: false,
            },
        )
        .unwrap();

        assert_eq!(fort_only.pixels[0], 4);
        assert_eq!(marked.pixels[0], 5);
        assert_eq!(marked.pixels[1], 2);
    }

    #[test]
    fn selected_army_uses_paired_count_art_below_retail_foregrounds() {
        let normal = IndexedPicture {
            width: 18,
            height: 38,
            pixels: vec![2; 18 * 38],
        };
        let selected = IndexedPicture {
            width: 18,
            height: 38,
            pixels: vec![6; 18 * 38],
        };
        let mut fort = indexed_picture(TILE_SIZE, TILE_SIZE, UNIT_TRANSPARENT_INDEX);
        fort.pixels[1] = 4;
        let mut marker = indexed_picture(TILE_SIZE, TILE_SIZE, UNIT_TRANSPARENT_INDEX);
        marker.pixels[0] = 5;
        let sprites = StrategicUnitSprites {
            civilians: HashMap::new(),
            army_counts: std::array::from_fn(|_| normal.clone()),
            selected_army_counts: std::array::from_fn(|_| selected.clone()),
            owner_flags: indexed_picture(9, 6, UNIT_TRANSPARENT_INDEX),
            forts: std::array::from_fn(|_| fort.clone()),
            order_markers: marker,
            fleet_frames: Vec::new(),
            fleet_atlas_id: PictureId::new(0),
            composed: HashMap::new(),
        };
        let sprite = StrategicUnitSprite::Army {
            bucket: 0,
            owner_slot: 0,
            fort_level: 1,
            order_marker: 1,
            selected: true,
        };

        let picture = compose_unit_sprite(&sprites, sprite).unwrap();

        assert_eq!(picture.pixels[0], 5);
        assert_eq!(picture.pixels[1], 4);
        assert_eq!(picture.pixels[2], 6);
        assert!(matches!(
            army_selection_sprite(sprite, false),
            StrategicUnitSprite::Army {
                selected: false,
                ..
            }
        ));
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
    fn foreign_civilian_frame_surrounds_instead_of_overwriting_the_tile_sprite() {
        let civilian = IndexedPicture {
            width: TILE_SIZE as u32,
            height: TILE_SIZE as u32,
            pixels: vec![5; (TILE_SIZE * TILE_SIZE) as usize],
        };
        let mut civilians = HashMap::new();
        civilians.insert(
            (CivilianUnitKind::Engineer, CivilianPose::Idle),
            vec![civilian],
        );
        let sprites = StrategicUnitSprites {
            civilians,
            army_counts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            selected_army_counts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            owner_flags: indexed_picture(1, 1, 0),
            forts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            order_markers: indexed_picture(1, 1, 0),
            fleet_frames: Vec::new(),
            fleet_atlas_id: PictureId::new(0),
            composed: HashMap::new(),
        };

        let picture = compose_unit_sprite(
            &sprites,
            StrategicUnitSprite::Civilian {
                kind: CivilianUnitKind::Engineer,
                pose: CivilianPose::Idle,
                frame: 0,
                owner_badge: None,
                framed: true,
            },
        )
        .unwrap();

        assert_eq!((picture.width, picture.height), (66, 66));
        assert_eq!(picture.pixels[0], FOREIGN_CIVILIAN_FRAME_INDEX);
        assert_eq!(picture.pixels[66 + 1], 5);
        assert_eq!(picture.pixels[64 * 66 + 64], 5);
        assert_eq!(picture.pixels[65 * 66 + 65], FOREIGN_CIVILIAN_FRAME_INDEX);
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
    fn selected_navy_uses_the_zone_active_tile_and_adjacent_atlas_frame() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let (zone, tile) = parts
            .ocean
            .zones
            .iter()
            .enumerate()
            .find_map(|(ordinal, zone)| {
                let tile = zone.zone().active_tile?;
                Some((
                    OceanZoneId::new(u16::try_from(ordinal).expect("zone ordinal fits")),
                    tile,
                ))
            })
            .expect("opening save has an active navy-zone tile");
        parts.map[tile].action = TileAction::try_from_retail(17);
        let state = GameState::from_parts(parts);
        let view_origin = state.map().viewport_origin_centered_on(tile);

        let projected = visible_strategic_units(&state, view_origin, None, None, Some(zone))
            .into_iter()
            .find(|unit| unit.identity == StrategicUnitIdentity::Naval(tile))
            .expect("selected navy-zone marker is visible");
        assert_eq!(
            projected.sprite,
            StrategicUnitSprite::Naval {
                frame: 17,
                selected: true,
            }
        );
        assert_eq!(
            naval_selection_sprite(projected.sprite, true),
            StrategicUnitSprite::Naval {
                frame: 18,
                selected: true,
            }
        );
    }

    #[test]
    fn selected_navy_can_render_the_nineteenth_ocean_atlas_frame() {
        let sprites = StrategicUnitSprites {
            civilians: HashMap::new(),
            army_counts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            selected_army_counts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            owner_flags: indexed_picture(1, 1, 0),
            forts: std::array::from_fn(|_| indexed_picture(1, 1, 0)),
            order_markers: indexed_picture(1, 1, 0),
            fleet_frames: (0..OCEAN_ATLAS_FRAME_COUNT)
                .map(|frame| indexed_picture(1, 1, frame as u8))
                .collect(),
            fleet_atlas_id: PictureId::new(0),
            composed: HashMap::new(),
        };
        let selected = naval_selection_sprite(
            StrategicUnitSprite::Naval {
                frame: 17,
                selected: true,
            },
            true,
        );

        assert_eq!(
            compose_unit_sprite(&sprites, selected).unwrap().pixels,
            [18]
        );
    }

    #[test]
    fn pending_ship_technologies_select_the_retail_fleet_atlas_variants() {
        use TechnologyResearchStatus::{NotStarted, Pending, Researched};

        assert_eq!(fleet_atlas_variant(NotStarted, NotStarted), 0);
        assert_eq!(fleet_atlas_variant(Pending, NotStarted), 1);
        assert_eq!(fleet_atlas_variant(Researched, NotStarted), 1);
        assert_eq!(fleet_atlas_variant(NotStarted, Pending), 2);
        assert_eq!(fleet_atlas_variant(Pending, Pending), 2);
        assert_eq!(fleet_atlas_variant(Researched, Researched), 2);
    }

    #[test]
    fn viewport_iterator_matches_tile_screen_origins_and_clips_offscreen_rows() {
        let state = fixture_state();
        let view_origin = beginning_map_view_origin();
        let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
        let seen = projection.visible_tiles().collect::<Vec<_>>();
        for projected in &seen {
            assert_eq!(
                projection.tile_origin(projected.tile),
                Some(projected.origin)
            );
            assert!(projected.origin.x < VIEWPORT_WIDTH as i32);
            assert!(projected.origin.x + TILE_SIZE > 0);
        }
        assert!(!seen.is_empty());
        let (origin_row, _) = state.map().geometry().row_column(view_origin);
        let outside = state
            .map()
            .geometry()
            .tile(origin_row.saturating_add(8), 0)
            .or_else(|| state.map().geometry().tile(origin_row.saturating_sub(1), 0));
        if let Some(outside) = outside {
            assert!(seen.iter().all(|projected| projected.tile != outside));
        }
    }

    #[test]
    fn beginning_of_game_projects_civilians_armies_and_fleets() {
        let state = fixture_state();
        assert!(
            state
                .first_idle_civilian_tile(state.turn().active_nation)
                .is_some(),
            "opening save has an idle civilian"
        );
        let civilian_tile = state
            .first_idle_civilian_tile(state.turn().active_nation)
            .unwrap();
        let civilian_origin = state.map().viewport_origin_centered_on(civilian_tile);
        assert!(
            visible_strategic_units(&state, civilian_origin, None, None, None)
                .iter()
                .any(|unit| matches!(unit.identity, StrategicUnitIdentity::Civilian(_))),
            "opening save should show field civilians"
        );

        let army_tile = state
            .military_units()
            .find_map(|(_, unit)| {
                unit.stationed_province()
                    .and_then(|province| state.map().provinces[province].city_tile())
            })
            .expect("opening save has a stationed army");
        let army_origin = state.map().viewport_origin_centered_on(army_tile);
        assert!(
            visible_strategic_units(&state, army_origin, None, None, None)
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
        let naval_origin = state.map().viewport_origin_centered_on(naval_tile);
        assert!(
            visible_strategic_units(&state, naval_origin, None, None, None)
                .iter()
                .any(|unit| matches!(unit.identity, StrategicUnitIdentity::Naval(_))),
            "opening save should show ocean action fleet markers"
        );
    }
}
