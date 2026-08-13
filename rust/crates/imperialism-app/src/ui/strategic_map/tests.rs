use super::borders::{
    CITY_BORDER_PALETTE, MAJOR_NATION_BORDER_PALETTES, MINOR_NATION_BORDER_PALETTE, draw_border,
};
use super::overlays::{
    IMPROVEMENT_PICTURE_IDS, RESOURCE_ICON_HEIGHT, RESOURCE_ICON_WIDTH, RESOURCE_OVERLAY_HEIGHT,
    RESOURCE_OVERLAY_WIDTH, city_marker_offset, transport_marker_offset,
};
use super::terrain::{
    BASE_WATER_OFFSETS, coast_corner_variant, compose_strategic_base_tile, frame_for_offset,
    uses_river_mouth_coast_frame,
};
use super::*;
use imperialism_core::{
    MapTopology, STRATEGIC_TILE_COUNT, TerrainKind, TileOwnerTag, TileRendering, TileState,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};

const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

fn solid_frame(index: u8) -> IndexedPicture {
    IndexedPicture {
        width: TILE_SIZE as u32,
        height: TILE_SIZE as u32,
        pixels: vec![index; (TILE_SIZE * TILE_SIZE) as usize],
    }
}

fn synthetic_terrain_pictures() -> Vec<IndexedPicture> {
    (0..51).map(|index| solid_frame(index as u8)).collect()
}

fn synthetic_river_masks() -> Vec<IndexedPicture> {
    (0..RIVER_MASK_PICTURE_COUNT)
        .map(|index| IndexedPicture {
            width: TILE_SIZE as u32,
            height: TILE_SIZE as u32,
            // Non-transparent river ink uses a distinct high index.
            pixels: vec![0x80 | index as u8; (TILE_SIZE * TILE_SIZE) as usize],
        })
        .collect()
}

fn synthetic_improvement_pictures() -> Vec<IndexedPicture> {
    (0..IMPROVEMENT_PICTURE_IDS.len())
        .map(|index| solid_frame(0x90 + index as u8))
        .collect()
}

fn synthetic_resource_icons() -> IndexedPicture {
    let width = (ResourceKind::LENGTH as i32 * RESOURCE_ICON_WIDTH) as u32;
    IndexedPicture {
        width,
        height: RESOURCE_ICON_HEIGHT as u32,
        pixels: (0..width as usize * RESOURCE_ICON_HEIGHT as usize)
            .map(|index| 0xa0 + (index as u8 % ResourceKind::LENGTH as u8))
            .collect(),
    }
}

fn synthetic_resource_overlays() -> IndexedPicture {
    let width = 24 * RESOURCE_OVERLAY_WIDTH as u32;
    IndexedPicture {
        width,
        height: RESOURCE_OVERLAY_HEIGHT as u32,
        pixels: vec![0xb0; width as usize * RESOURCE_OVERLAY_HEIGHT as usize],
    }
}

fn synthetic_sprites() -> (
    Vec<IndexedPicture>,
    Vec<IndexedPicture>,
    Vec<IndexedPicture>,
    IndexedPicture,
    IndexedPicture,
) {
    (
        synthetic_terrain_pictures(),
        synthetic_river_masks(),
        synthetic_improvement_pictures(),
        synthetic_resource_icons(),
        synthetic_resource_overlays(),
    )
}

fn sprites_from<'a>(
    terrain: &'a [IndexedPicture],
    rivers: &'a [IndexedPicture],
    improvements: &'a [IndexedPicture],
    icons: &'a IndexedPicture,
    overlays: &'a IndexedPicture,
) -> StrategicMapSprites<'a> {
    StrategicMapSprites {
        terrain,
        river_masks: rivers,
        improvements,
        resource_icons: icons,
        resource_overlays: overlays,
    }
}

fn fixture_state() -> GameState {
    let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
    save.game_state(LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
        selected_nation: imperialism_core::NationId::new(6),
    })
}

#[test]
fn coast_corner_variant_matches_the_adjacent_bit_rule() {
    assert_eq!(coast_corner_variant(0x05, 1), 0);
    // Corner 0 needs bits 5 and 0 both set for the joined-corner variant.
    assert_eq!(coast_corner_variant(0b0010_0001, 0), 1);
    assert_eq!(coast_corner_variant(0b0000_0001, 0), 2);
    assert_eq!(coast_corner_variant(0b0010_0000, 0), 3);
}

#[test]
fn river_mouth_coast_frames_follow_corner_and_sprite_pairs() {
    assert!(uses_river_mouth_coast_frame(1, Some(0x33)));
    assert!(uses_river_mouth_coast_frame(4, Some(0x39)));
    assert!(!uses_river_mouth_coast_frame(1, Some(0x35)));
    assert!(!uses_river_mouth_coast_frame(0, Some(0x33)));
}

#[test]
fn water_coast_corners_pull_distinct_frame_inks() {
    let terrain = synthetic_terrain_pictures();
    let rivers = synthetic_river_masks();
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    state.map_mut()[origin].terrain = TerrainKind::Water;
    state.map_mut()[origin].rendering = TileRendering::from_retail(0, 0, 0, 0b0000_0011).unwrap();

    let pixels = compose_strategic_base_tile(&state, origin, &terrain, &rivers);
    let base_ink = frame_for_offset(BASE_WATER_OFFSETS[0]) as u8;
    assert!(pixels.contains(&base_ink));
    assert!(pixels.iter().any(|&pixel| pixel >= 22));
}

#[test]
fn river_masks_replace_opaque_destination_indexes() {
    let terrain = synthetic_terrain_pictures();
    let rivers = synthetic_river_masks();
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    state.map_mut()[origin].terrain = TerrainKind::Plains;
    state.map_mut()[origin].gate = 0;
    state.map_mut()[origin].rendering = TileRendering::from_retail(0, 0x0b, 0, 0).unwrap();

    let pixels = compose_strategic_base_tile(&state, origin, &terrain, &rivers);
    assert!(pixels.iter().all(|&pixel| pixel == 0x80));
}

#[test]
fn bounded_seam_tiles_use_the_dedicated_seam_frame() {
    let terrain = synthetic_terrain_pictures();
    let rivers = synthetic_river_masks();
    let mut state = fixture_state();
    // Force bounded topology and a center column past 54 so column 0 is a seam.
    let tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
    let mut world = MapMgr::new(MapTopology::Bounded, tiles);
    let origin = world.geometry().tile(10, 51).unwrap();
    world.view_origin = origin;
    let seam = world.geometry().tile(10, 0).unwrap();
    *state.map_mut() = world;

    let pixels = compose_strategic_base_tile(&state, seam, &terrain, &rivers);
    assert!(
        pixels
            .iter()
            .all(|&pixel| pixel == frame_for_offset(0xc80) as u8)
    );
}

#[test]
fn city_site_selection_draws_black_frame_and_neighbor_outline() {
    let mut state = fixture_state();
    let nation = MajorNationId::new(6);
    let owner = TileOwnerTag::from_nation(nation.nation());
    let origin = state.map().view_origin;
    state.map_mut()[origin].owner_nation = Some(owner);
    state.map_mut()[origin].terrain = TerrainKind::Plains;
    let neighbors = state.map().geometry().neighbors(origin);
    for neighbor in neighbors.into_iter().flatten() {
        state.map_mut()[neighbor].owner_nation = Some(owner);
        state.map_mut()[neighbor].terrain = TerrainKind::Plains;
    }

    let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
    let mut indices = compose_strategic_map_indices(
        &state,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    let before = indices.clone();
    draw_city_site_selection(&state, nation, origin, &mut indices);
    assert_ne!(indices, before);
    let (x, y) = strategic_tile_screen_origin(&state, origin);
    let top_left = (y * VIEWPORT_WIDTH as i32 + x) as usize;
    assert_eq!(indices[top_left], 0);
}

#[test]
fn city_marker_offsets_follow_former_owner_and_development_stage() {
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    state.map_mut()[origin].flags = TileFlags::from_bits_retain(1);
    state.map_mut()[origin].former_owner_nation = Some(TileOwnerTag::from_nation(NationId::new(6)));
    assert_eq!(city_marker_offset(&state, origin), Some(0x6c0));

    state.map_mut()[origin].flags = TileFlags::from_bits_retain(2);
    state.map_mut()[origin].province = Some(ProvinceId::new(0));
    assert_eq!(city_marker_offset(&state, origin), Some(0x700));

    state.map_mut()[origin].former_owner_nation = Some(TileOwnerTag::new(8));
    state.map_mut()[origin].flags = TileFlags::from_bits_retain(1);
    assert_eq!(city_marker_offset(&state, origin), Some(0x9c0));
    state.map_mut()[origin].flags = TileFlags::from_bits_retain(2);
    assert_eq!(city_marker_offset(&state, origin), Some(0x980));
}

#[test]
fn transport_marker_offsets_encode_port_depot_and_link_state() {
    assert_eq!(transport_marker_offset(0x10, true), Some(0x7c0));
    assert_eq!(transport_marker_offset(0x10, false), Some(0x800));
    assert_eq!(transport_marker_offset(0x14, true), Some(0x840));
    assert_eq!(transport_marker_offset(0x14, false), Some(0xa40));
    assert_eq!(transport_marker_offset(4, true), Some(0x880));
    assert_eq!(transport_marker_offset(4, false), Some(0xa00));
    assert_eq!(transport_marker_offset(0, true), None);
}

#[test]
fn completed_rails_use_the_later_mask_family_than_pending_rails() {
    let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    state.map_mut()[origin].terrain = TerrainKind::Plains;
    state.map_mut()[origin].gate = 0;
    state.map_mut()[origin].rendering = TileRendering::default();
    state.map_mut()[origin].transport_links = TileTransportLinks::EAST;
    state.map_mut()[origin].pending_rail_links = TileTransportLinks::empty();
    state.map_mut()[origin].flags = TileFlags::empty();
    state.map_mut()[origin].edge_resources = [None, None];

    let completed = compose_strategic_tile(
        &state,
        origin,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(completed.contains(&(0x80 | 0x19)));

    state.map_mut()[origin].transport_links = TileTransportLinks::empty();
    state.map_mut()[origin].pending_rail_links = TileTransportLinks::EAST;
    let pending = compose_strategic_tile(
        &state,
        origin,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(pending.contains(&(0x80 | 0x1f)));
}

#[test]
fn prospectable_resources_use_extractive_overlay_or_undeveloped_icon() {
    let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
    state.map_mut()[origin].terrain = TerrainKind::Hills;
    state.map_mut()[origin].gate = 2;
    state.map_mut()[origin].flags = TileFlags::empty();
    state.map_mut()[origin].edge_resources = [Some(ResourceKind::Coal), None];
    state.map_mut()[origin].development.extractive = DevelopmentLevel::ZERO;
    state.map_mut()[origin].development.surface = DevelopmentLevel::ZERO;
    state.map_mut()[origin]
        .development
        .resource_visible_to_majors[nation] = true;

    let undeveloped = compose_strategic_tile(
        &state,
        origin,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(
        undeveloped
            .iter()
            .any(|&pixel| (0xa0..0xb0).contains(&pixel))
    );

    state.map_mut()[origin].development.extractive = DevelopmentLevel::new(1);
    let developed = compose_strategic_tile(
        &state,
        origin,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(developed.contains(&0xb0));
}

#[test]
fn city_tiles_blit_the_capital_improvement_ink() {
    let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
    let mut state = fixture_state();
    let origin = state.map().view_origin;
    state.map_mut()[origin].terrain = TerrainKind::Plains;
    state.map_mut()[origin].gate = 1;
    state.map_mut()[origin].flags = TileFlags::from_bits_retain(1);
    state.map_mut()[origin].former_owner_nation = Some(TileOwnerTag::from_nation(NationId::new(6)));
    state.map_mut()[origin].edge_resources = [None, None];

    let pixels = compose_strategic_tile(
        &state,
        origin,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(pixels.contains(&0x90));
}

#[test]
fn nation_borders_use_the_owner_palette() {
    let mut pixels = vec![1_u8; (TILE_SIZE * TILE_SIZE) as usize];
    draw_border(
        &mut pixels,
        0,
        MAJOR_NATION_BORDER_PALETTES[6],
        MINOR_NATION_BORDER_PALETTE,
    );
    assert!(pixels.contains(&MAJOR_NATION_BORDER_PALETTES[6]));
    assert!(pixels.contains(&MINOR_NATION_BORDER_PALETTE));
}

#[test]
fn beginning_of_game_viewport_paints_settlements_borders_and_resources() {
    let mut state = fixture_state();
    if let Some(tile) = state.first_idle_civilian_tile(state.turn().active_nation) {
        state.center_map_on(tile);
    }

    let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
    let indices = compose_strategic_map_indices(
        &state,
        sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
    );
    assert!(
        (0x90..=0x93)
            .chain(0x9c..=0x9d)
            .any(|ink| indices.contains(&ink)),
        "town and capital markers should copy atlas66c improvement ink"
    );
    assert!(
        indices.contains(&0x98),
        "the opening capital fort should copy atlas66c fort ink"
    );
    assert!(
        indices.contains(&CITY_BORDER_PALETTE)
            || MAJOR_NATION_BORDER_PALETTES
                .iter()
                .any(|palette| indices.contains(palette)),
        "ownership borders should copy nation or city palette ink"
    );
    assert!(
        indices.iter().any(|&pixel| (0xa0..0xb1).contains(&pixel)),
        "visible resource indicators should copy picture 750/751 ink"
    );
}
