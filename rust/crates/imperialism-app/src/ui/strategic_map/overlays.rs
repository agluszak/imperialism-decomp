use bevy::prelude::{IRect, IVec2};
use imperialism_core::*;
use imperialism_formats::*;

use crate::ui::retail_raster::IndexedRasterExt;

use super::{RIVER_MASK_TRANSPARENT_INDEX, StrategicMapSprites, TILE_SIZE};

pub(super) const RESOURCE_ICON_WIDTH: i32 = 0x14;
pub(super) const RESOURCE_ICON_HEIGHT: i32 = 0x18;
pub(super) const RESOURCE_OVERLAY_WIDTH: i32 = 0x26;
pub(super) const RESOURCE_OVERLAY_HEIGHT: i32 = 0x1a;
const RESOURCE_OVERLAY_SOURCE_X: [i16; 28] = [
    0, 798, 114, 228, 342, -114, 684, -114, -114, -114, -114, -114, -114, -114, -114, -114, -114,
    0, 0, -114, 798, 570, 456, 0, 0, 0, 0, 0,
];
const IMPROVEMENT_ATLAS_BASE_OFFSET: u16 = 0x6c0;
pub(super) const IMPROVEMENT_PICTURE_IDS: [i16; 15] = [
    550, 551, 552, 553, 554, 555, 556, 557, 560, 561, 562, 10_104, 10_105, 578, 579,
];
pub(super) fn compose_strategic_railways(
    tile_state: &TileState,
    river_masks: &[IndexedPicture],
    surface: &mut IndexedPicture,
) {
    if tile_state.transport_links.is_empty() && tile_state.pending_rail_links.is_empty() {
        return;
    }
    const COMPLETED_MASK: HexDirectionTable<usize> =
        HexDirectionTable::from_array([0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d]);
    const PENDING_MASK: HexDirectionTable<usize> =
        HexDirectionTable::from_array([0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23]);
    for direction in HexDirection::ALL {
        let direction_bit = direction.bit();
        let mask = if tile_state.transport_links.bits() & direction_bit != 0 {
            COMPLETED_MASK[direction]
        } else if tile_state.pending_rail_links.bits() & direction_bit != 0 {
            PENDING_MASK[direction]
        } else {
            continue;
        };
        surface.blit_keyed_at(
            &river_masks[mask],
            IVec2::ZERO,
            RIVER_MASK_TRANSPARENT_INDEX,
        );
    }
}

pub(super) fn compose_strategic_improvements(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
    surface: &mut IndexedPicture,
) {
    let tile_state = state.map()[tile];
    let flags = tile_state.flags.bits();
    let city_or_town = flags & 3 != 0 && tile_state.gate != 0;

    if city_or_town && let Some(offset) = city_marker_offset(state, tile) {
        blit_improvement_sprite(sprites.improvements, offset, surface);
    }

    if flags & 0x14 != 0
        && flags & 1 == 0
        && let Some(offset) = transport_marker_offset(flags, town_transport_linked(state, tile))
    {
        blit_improvement_sprite(sprites.improvements, offset, surface);
    }

    if !city_or_town {
        compose_strategic_resource_indicators(state, tile, sprites, surface);
    } else if let Some(offset) = fort_marker_offset(state, tile) {
        blit_improvement_sprite(sprites.improvements, offset, surface);
    }
}

pub(super) fn city_marker_offset(state: &GameState, tile: TileId) -> Option<u16> {
    let tile_state = state.map()[tile];
    let flags = tile_state.flags.bits();
    let minor_sprites = tile_state
        .former_owner_nation
        .is_some_and(|owner| owner.get() >= MajorNationId::COUNT);
    if !minor_sprites {
        if flags & 1 != 0 {
            return Some(0x6c0);
        }
        if flags & 2 != 0 {
            let stage = tile_state
                .province
                .map(|province| state.map().provinces[province].development_stage())
                .unwrap_or(ProvinceDevelopmentStage::None);
            return match stage {
                ProvinceDevelopmentStage::None => Some(0x700),
                ProvinceDevelopmentStage::Village => Some(0x740),
                ProvinceDevelopmentStage::Town => Some(0x780),
            };
        }
        return None;
    }
    if flags & 1 != 0 {
        Some(0x9c0)
    } else if flags & 2 != 0 {
        Some(0x980)
    } else {
        None
    }
}

pub(super) fn transport_marker_offset(flags: u16, linked: bool) -> Option<u16> {
    if flags & 4 != 0 {
        if flags & 0x10 != 0 {
            Some(if linked { 0x840 } else { 0xa40 })
        } else {
            Some(if linked { 0x880 } else { 0xa00 })
        }
    } else if flags & 0x10 != 0 {
        Some(if linked { 0x7c0 } else { 0x800 })
    } else {
        None
    }
}

fn fort_marker_offset(state: &GameState, tile: TileId) -> Option<u16> {
    let fort_level = state.map()[tile]
        .province
        .map(|province| state.map().provinces[province].fort_level())
        .unwrap_or(FortLevel::None);
    let picture = match fort_level {
        FortLevel::None => return None,
        FortLevel::One => 0x23,
        FortLevel::Two => 0x24,
        FortLevel::Three => 0x25,
    };
    Some(picture << 6)
}

pub(super) fn town_transport_linked(state: &GameState, tile: TileId) -> bool {
    let Some(owner) = state.map()[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return true;
    };
    let Some(major) = MajorNationId::from_nation(owner) else {
        return true;
    };
    state
        .nations()
        .major(major)
        .towns
        .get(&tile)
        .map(|town| town.transport_linked)
        .unwrap_or(true)
}

fn blit_improvement_sprite(pictures: &[IndexedPicture], offset: u16, surface: &mut IndexedPicture) {
    let index = usize::from((offset - IMPROVEMENT_ATLAS_BASE_OFFSET) / TILE_SIZE as u16);
    surface.blit_keyed_at(&pictures[index], IVec2::ZERO, RIVER_MASK_TRANSPARENT_INDEX);
}

fn compose_strategic_resource_indicators(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
    surface: &mut IndexedPicture,
) {
    let tile_state = state.map()[tile];
    let surface_level = tile_state.development.surface.get();
    let extractive = tile_state.development.extractive.get();
    let first = tile_state.edge_resources[0];
    let second = tile_state.edge_resources[1];

    if let Some(resource) = first.filter(resource_is_prospectable) {
        if extractive != 0 {
            blit_resource_overlay(
                sprites.resource_overlays,
                resource,
                extractive,
                2,
                2,
                surface,
            );
        } else if resource_visible_to_active_nation(state, tile) {
            blit_resource_icon(sprites.resource_icons, resource, 0, 0, surface);
        }
    } else if surface_level != 0
        && let Some(resource) = first
    {
        blit_resource_overlay(
            sprites.resource_overlays,
            resource,
            surface_level,
            0x1b,
            2,
            surface,
        );
    }

    if let Some(resource) = second.filter(resource_is_prospectable) {
        if extractive != 0 {
            blit_resource_overlay(
                sprites.resource_overlays,
                resource,
                extractive,
                2,
                0x1c,
                surface,
            );
        } else if resource_visible_to_active_nation(state, tile) {
            blit_resource_icon(sprites.resource_icons, resource, 0, 0x1c, surface);
        }
    }

    if second == Some(ResourceKind::Livestock)
        && matches!(first, Some(ResourceKind::Coal | ResourceKind::Iron))
        && surface_level != 0
    {
        blit_resource_overlay(
            sprites.resource_overlays,
            ResourceKind::Livestock,
            surface_level,
            0x1b,
            0x1c,
            surface,
        );
    }
}

fn resource_is_prospectable(resource: &ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Oil
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn resource_visible_to_active_nation(state: &GameState, tile: TileId) -> bool {
    MajorNationId::from_nation(state.turn().active_nation)
        .is_some_and(|nation| state.map()[tile].development.resource_visible_to_majors[nation])
}

fn blit_resource_icon(
    atlas: &IndexedPicture,
    resource: ResourceKind,
    dest_x: i32,
    dest_y: i32,
    surface: &mut IndexedPicture,
) {
    let source_x = i32::from(resource.retail()) * RESOURCE_ICON_WIDTH;
    surface.blit_keyed(
        atlas,
        IRect::new(
            source_x,
            0,
            source_x + RESOURCE_ICON_WIDTH,
            RESOURCE_ICON_HEIGHT,
        ),
        IVec2::new(dest_x, dest_y),
        RIVER_MASK_TRANSPARENT_INDEX,
    );
}

fn blit_resource_overlay(
    atlas: &IndexedPicture,
    resource: ResourceKind,
    level: u8,
    dest_x: i32,
    dest_y: i32,
    surface: &mut IndexedPicture,
) {
    if level == 0 {
        return;
    }
    let source_base = RESOURCE_OVERLAY_SOURCE_X[usize::from(resource.retail())];
    if source_base < 0 {
        return;
    }
    let source_x =
        i32::from(source_base) - RESOURCE_OVERLAY_WIDTH + i32::from(level) * RESOURCE_OVERLAY_WIDTH;
    surface.blit_keyed(
        atlas,
        IRect::new(
            source_x,
            0,
            source_x + RESOURCE_OVERLAY_WIDTH,
            RESOURCE_OVERLAY_HEIGHT,
        ),
        IVec2::new(dest_x, dest_y),
        RIVER_MASK_TRANSPARENT_INDEX,
    );
}
