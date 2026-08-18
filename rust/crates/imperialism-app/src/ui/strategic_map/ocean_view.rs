//! `TOceanDialog` (`DOOG`) alternate strategic view.

use super::map_interaction::OceanView;
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::retail::RetailTree;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::text::LineHeight;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const LAND_POS: Vec2 = Vec2::new(5.0, 0x1b as f32);
const OCEAN_TILE: i32 = 16;
const OCEAN_FILL: u8 = 0x1a;
const BOUNDED_MAP_BLANK: u8 = 0x16;
const OWNER_PALETTE: [u8; 24] = [
    0xf3, 0x2a, 0x25, 0x1d, 0xf6, 0x8c, 0xbd, 0x0a, 0x0b, 0x0d, 0x29, 0xde, 0xdf, 0xfa, 0x2c, 0x31,
    0x33, 0x41, 0x48, 0xd0, 0xcd, 0xce, 0xcf, OCEAN_FILL,
];
const BORDER_PALETTE: [u8; 24] = [
    0x15, 0x2d, 0x1e, 0x1c, 0x30, 0xae, 0xca, 0x7d, 0x7d, 0x7d, 0x7d, 0xe2, 0xe2, 0xe2, 0xe2, 0x51,
    0x51, 0x51, 0x51, 0xf0, 0xf0, 0xf0, 0xf0, 0xc6,
];
const VERTICAL_OFFSETS: [[i32; 16]; 3] = [
    [5, 6, 7, 11, 5, 6, 7, 8, 10, 11, 12, 13, 2, 3, 4, 5],
    [2, 3, 9, 13, 2, 11, 12, 13, 2, 3, 4, 5, 10, 11, 12, 13],
    [4, 8, 10, 12, 3, 4, 9, 10, 6, 7, 8, 9, 6, 7, 8, 9],
];
const DIAGONAL_OFFSETS: [[i32; 8]; 3] = [
    [4, 5, 2, 2, 5, 5, 5, 5],
    [3, 3, 3, 4, 4, 4, 3, 4],
    [2, 2, 5, 5, 2, 3, 2, 2],
];

#[derive(Component)]
pub(crate) struct LandMapFrame;

#[derive(Component)]
pub(crate) struct OceanMapCanvas;

#[derive(Component)]
struct OceanMapLabel;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (sync_ocean_view_frames, sync_ocean_canvas, sync_ocean_labels)
            .chain()
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_ocean_view(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> Entity {
    let land = tree.find(root, fourcc!("DLOG"));
    commands.entity(land).insert(LandMapFrame);
    let ocean = tree.find(root, fourcc!("DOOG"));
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(empty_ocean_image(&palette));
    commands.entity(ocean).insert((
        OceanMapCanvas,
        ImageNode::new(image),
        Visibility::Hidden,
        RelativeCursorPosition::default(),
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(LAND_POS.x),
            top: Val::Px(LAND_POS.y),
            width: Val::Px(VIEWPORT_WIDTH as f32),
            height: Val::Px(VIEWPORT_HEIGHT as f32),
            ..default()
        },
    ));
    ocean
}

fn sync_ocean_view_frames(
    interactions: Query<&super::map_interaction::StrategicInteraction>,
    mut land: Query<&mut Visibility, (With<LandMapFrame>, Without<OceanMapCanvas>)>,
    mut sea: Query<&mut Visibility, (With<OceanMapCanvas>, Without<LandMapFrame>)>,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    let (land_visibility, sea_visibility) = if interaction.ocean.active {
        (Visibility::Hidden, Visibility::Visible)
    } else {
        (Visibility::Visible, Visibility::Hidden)
    };
    if let Ok(mut visibility) = land.single_mut() {
        *visibility = land_visibility;
    }
    if let Ok(mut visibility) = sea.single_mut() {
        *visibility = sea_visibility;
    }
}

fn sync_ocean_canvas(
    session: Res<GameSession>,
    interactions: Query<Ref<super::map_interaction::StrategicInteraction>>,
    retail: Res<crate::RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    canvases: Query<(&ImageNode, &RelativeCursorPosition), With<OceanMapCanvas>>,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    if !interaction.ocean.active && !session.is_changed() && !interaction.is_changed() {
        return;
    }
    if !interaction.ocean.active {
        return;
    }
    let palette = retail.assets().default_dib_palette();
    for (node, cursor) in &canvases {
        let hovered = ocean_tile_at_cursor(&session.game, cursor, &interaction.ocean);
        let image = compose_ocean_map(
            &session.game,
            &interaction,
            hovered,
            retail.assets(),
            palette,
        );
        if let Some(mut existing) = images.get_mut(&node.image) {
            *existing = image;
        }
    }
}

fn sync_ocean_labels(
    mut commands: Commands,
    session: Res<GameSession>,
    interactions: Query<Ref<super::map_interaction::StrategicInteraction>>,
    canvases: Query<Entity, With<OceanMapCanvas>>,
    labels: Query<Entity, With<OceanMapLabel>>,
    mut assets: RetailUiAssets,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    if !session.is_changed() && !interaction.is_changed() && !labels.is_empty() {
        return;
    }
    for label in &labels {
        commands.entity(label).despawn();
    }
    if !interaction.ocean.active {
        return;
    }
    let Ok(canvas) = canvases.single() else {
        return;
    };
    let (zone_font, zone_layout, zone_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 2,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail ocean-zone text style");
    let (nation_font, nation_layout, nation_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 1,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail ocean-nation text style");
    let palette = assets.default_dib_palette();

    commands.entity(canvas).with_children(|parent| {
        for zone in session.game.ocean().zones.iter().rev() {
            let Some(tile) = zone.zone().target_tile else {
                continue;
            };
            let Some((x, y)) =
                ocean_label_position(session.game.map().geometry(), tile, &interaction.ocean)
            else {
                continue;
            };
            let color = if matches!(zone, ZoneKind::PortZone(_)) {
                palette_color(palette, 0)
            } else {
                palette_color(palette, 0x13)
            };
            spawn_ocean_label(
                parent,
                &zone.zone().display_name,
                x,
                y + 2.0,
                color,
                &zone_font,
                &zone_layout,
                zone_line_height,
            );
        }

        for slot in 0..NationId::COUNT {
            let nation = NationId::new(slot);
            let Some(name) = session.game.nations().display_name(nation) else {
                continue;
            };
            let Some(tile) = session.game.ocean_overlay_anchor_for_nation(nation) else {
                break;
            };
            let Some((x, y)) =
                ocean_label_position(session.game.map().geometry(), tile, &interaction.ocean)
            else {
                continue;
            };
            spawn_ocean_label(
                parent,
                name,
                x + 1.0,
                y - 13.0,
                palette_color(palette, 0x13),
                &nation_font,
                &nation_layout,
                nation_line_height,
            );
            spawn_ocean_label(
                parent,
                name,
                x,
                y - 14.0,
                palette_color(palette, 0),
                &nation_font,
                &nation_layout,
                nation_line_height,
            );
        }
    });
}

fn spawn_ocean_label(
    parent: &mut ChildSpawnerCommands,
    text: &str,
    center_x: f32,
    top: f32,
    color: Color,
    font: &TextFont,
    layout: &TextLayout,
    line_height: LineHeight,
) {
    parent.spawn((
        OceanMapLabel,
        Pickable::IGNORE,
        Text::new(text),
        font.clone(),
        *layout,
        line_height,
        TextColor(color),
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(center_x - 150.0),
            top: Val::Px(top),
            width: Val::Px(300.0),
            ..default()
        },
    ));
}

fn ocean_label_position(
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanView,
) -> Option<(f32, f32)> {
    let (row, column) = geometry.row_column(tile);
    let y = (i32::from(row) - ocean.origin_row) * 16 + 8;
    let x = (i32::from(column) - ocean.origin_column).rem_euclid(108) * 16 + i32::from(row & 1) * 8;
    ((0..=VIEWPORT_WIDTH as i32).contains(&x) && (0..=VIEWPORT_HEIGHT as i32).contains(&y))
        .then_some((x as f32, y as f32))
}

fn palette_color(palette: &DibPalette, index: u8) -> Color {
    let [red, green, blue] = palette[index].to_array();
    Color::srgb_u8(red, green, blue)
}

pub(crate) fn ocean_tile_at_cursor(
    state: &GameState,
    cursor: &RelativeCursorPosition,
    ocean: &OceanView,
) -> Option<TileId> {
    cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .and_then(|position| {
            ocean_tile_at_position(state, position, ocean.origin_column, ocean.origin_row)
        })
}

fn ocean_tile_at_position(
    state: &GameState,
    normalized: Vec2,
    origin_column: i32,
    origin_row: i32,
) -> Option<TileId> {
    let x = ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32;
    let y = ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32;
    if !(0..VIEWPORT_WIDTH as i32).contains(&x) || !(0..VIEWPORT_HEIGHT as i32).contains(&y) {
        return None;
    }
    let row = origin_row + y / OCEAN_TILE;
    if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
        return None;
    }
    let mut adjusted = x;
    if row & 1 == 0 {
        adjusted += 8;
    }
    let column = origin_column + adjusted / OCEAN_TILE;
    let column = if state.map().geometry().wraps_horizontally() {
        column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    } else if (0..i32::from(STRATEGIC_MAP_WIDTH)).contains(&column) {
        column
    } else {
        return None;
    };
    state.map().geometry().tile(row as u16, column as u16)
}

fn compose_ocean_map(
    state: &GameState,
    interaction: &super::map_interaction::StrategicInteraction,
    hovered: Option<TileId>,
    assets: &RetailAssets,
    palette: &DibPalette,
) -> Image {
    let ocean = &interaction.ocean;
    let mut indices = compose_ocean_indices(state, ocean);
    compose_ocean_improvements(&mut indices, state, ocean, assets);
    compose_ocean_unit_badges(&mut indices, state, ocean, assets);
    compose_ocean_routes(&mut indices, state, ocean);
    compose_ocean_selection(&mut indices, state, interaction, hovered);
    indexed_image(&indices, palette)
}

fn compose_ocean_indices(state: &GameState, ocean: &OceanView) -> Vec<u8> {
    let mut indices = vec![OCEAN_FILL; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
    let geometry = state.map().geometry();
    let bounded = !geometry.wraps_horizontally();
    let blank_wrapped_left = bounded && (ocean.origin_column < 2 || ocean.origin_column > 100);
    let blank_wrapped_right = bounded && ocean.origin_column <= 100 && ocean.origin_column > 70;
    for row_delta in 0..28 {
        let row = ocean.origin_row + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            continue;
        }
        for column_delta in 0..=32 {
            let screen_x = column_delta * OCEAN_TILE - if row & 1 == 0 { 8 } else { 0 };
            let screen_y = row_delta * OCEAN_TILE;
            let unwrapped_column = ocean.origin_column + column_delta;
            let column = if unwrapped_column >= i32::from(STRATEGIC_MAP_WIDTH) {
                if blank_wrapped_right {
                    fill_ocean_cell(&mut indices, screen_x, screen_y, BOUNDED_MAP_BLANK);
                    continue;
                }
                unwrapped_column - i32::from(STRATEGIC_MAP_WIDTH)
            } else if blank_wrapped_left && unwrapped_column > 60 {
                fill_ocean_cell(&mut indices, screen_x, screen_y, BOUNDED_MAP_BLANK);
                continue;
            } else {
                unwrapped_column
            };
            let Some(tile) = geometry.tile(row as u16, column as u16) else {
                continue;
            };
            let tile_state = state.map()[tile];
            let owner = ocean_owner(tile_state.owner_nation);
            let water = tile_state.terrain == TerrainKind::Water;
            if !water {
                fill_ocean_cell(&mut indices, screen_x, screen_y, OWNER_PALETTE[owner]);
            }
            if screen_x >= 0 {
                draw_ocean_borders(
                    state,
                    tile,
                    screen_x,
                    screen_y,
                    owner,
                    tile_state.province,
                    water,
                    &mut indices,
                );
            }
        }
    }
    indices
}

fn ocean_owner(owner: Option<TileOwnerTag>) -> usize {
    owner.map_or(23, |owner| usize::from(owner.get().min(23)))
}

fn compose_ocean_improvements(
    indices: &mut [u8],
    state: &GameState,
    ocean: &OceanView,
    assets: &RetailAssets,
) {
    let base_a = ocean_picture(assets, 1422);
    let base_b = ocean_picture(assets, 1423);
    let visited = ocean_picture(assets, 807);
    let active = MajorNationId::from_nation(state.turn().active_nation).map(|nation| {
        let status = &state.technology().research_status_by_nation[nation];
        let variant = if status[Technology::MarineEngineering]
            == TechnologyResearchStatus::Researched
        {
            2
        } else if status[Technology::AdvancedIronWorking] == TechnologyResearchStatus::Researched {
            1
        } else {
            0
        };
        ocean_picture(assets, 1401 + i16::from(nation.get()) + variant as i16 * 7)
    });
    let geometry = state.map().geometry();
    let bounded = !geometry.wraps_horizontally();
    let blank_wrapped_left = bounded && (ocean.origin_column < 2 || ocean.origin_column > 100);
    let blank_wrapped_right = bounded && ocean.origin_column <= 100 && ocean.origin_column > 70;

    for row_delta in 0..28 {
        let row = ocean.origin_row + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            continue;
        }
        for column_delta in 0..=32 {
            let unwrapped_column = ocean.origin_column + column_delta;
            let column = if unwrapped_column >= i32::from(STRATEGIC_MAP_WIDTH) {
                if blank_wrapped_right {
                    continue;
                }
                unwrapped_column - i32::from(STRATEGIC_MAP_WIDTH)
            } else if blank_wrapped_left && unwrapped_column > 60 {
                continue;
            } else {
                unwrapped_column
            };
            let Some(tile) = geometry.tile(row as u16, column as u16) else {
                continue;
            };
            let tile_state = state.map()[tile];
            let flags = tile_state.flags.bits();
            if tile_state.action.is_none()
                && tile_state.per_tile_visited <= 0
                && (flags & 3 == 0 || tile_state.gate == 0)
                && flags & 4 == 0
            {
                continue;
            }
            let (picture, source_x) =
                if tile_state.action.is_some_and(|action| action.retail() >= 2) {
                    let Some(active) = active.as_ref() else {
                        continue;
                    };
                    (active, i32::from(tile_state.action.unwrap().retail()) * 16)
                } else if tile_state.per_tile_visited > 0 {
                    (&visited, i32::from(tile_state.per_tile_visited - 1) * 16)
                } else {
                    let source_x = ocean_improvement_source_x(&tile_state);
                    if source_x < 1024 {
                        (&base_a, source_x)
                    } else {
                        (&base_b, source_x - 1024)
                    }
                };
            let screen_x = column_delta * OCEAN_TILE - if row & 1 == 0 { 8 } else { 0 };
            let screen_y = row_delta * OCEAN_TILE;
            blit_ocean_sprite(indices, picture, source_x, screen_x, screen_y);
        }
    }
}

fn ocean_picture(assets: &RetailAssets, id: i16) -> IndexedPicture {
    assets
        .indexed_picture(PictureId::new(id))
        .unwrap_or_else(|error| panic!("retail ocean picture {id} must load: {error}"))
}

fn ocean_improvement_source_x(tile: &TileState) -> i32 {
    let owner = tile.owner_nation.map(TileOwnerTag::get).unwrap_or(23);
    if tile.flags.contains(TileFlags::BASE_TRANSPORT) {
        return if owner < 7 {
            i32::from(owner + 0x16) * 16
        } else {
            0x1d * 16
        };
    }
    if tile.flags.contains(TileFlags::CITY_MARKER) {
        return if owner < 7 {
            i32::from(owner * 2 + 0x40) * 16
        } else {
            0x4e * 16
        };
    }
    if tile.flags.contains(TileFlags::PORT) {
        return if owner < 7 {
            i32::from(owner + 0x26) * 16
        } else {
            0x2d * 16
        };
    }
    0
}

fn blit_ocean_sprite(
    indices: &mut [u8],
    picture: &IndexedPicture,
    source_x: i32,
    destination_x: i32,
    destination_y: i32,
) {
    for y in 0..16 {
        for x in 0..16 {
            let source = source_x + x;
            if source < 0 || source >= picture.width as i32 || y >= picture.height as i32 {
                continue;
            }
            let color = picture.pixels[y as usize * picture.width as usize + source as usize];
            if color != 0x10 {
                put_ocean_pixel(indices, destination_x + x, destination_y + y, color);
            }
        }
    }
}

fn compose_ocean_routes(indices: &mut [u8], state: &GameState, ocean: &OceanView) {
    let viewport_column_x2 = ocean.origin_column * 2 + 1;
    for route in &state.ocean().routes {
        let mut start_x = (route.start_column - viewport_column_x2 + 216).rem_euclid(216);
        let mut end_x = (route.end_column - viewport_column_x2 + 216).rem_euclid(216);
        if (start_x - end_x).abs() > 108 {
            if start_x > 108 {
                start_x -= 216;
            } else if end_x > 108 {
                end_x -= 216;
            }
        }
        draw_ocean_line(
            indices,
            start_x * 8,
            (route.start_row - ocean.origin_row) * 16,
            end_x * 8,
            (route.end_row - ocean.origin_row) * 16,
            BORDER_PALETTE[23],
        );
    }
}

fn compose_ocean_unit_badges(
    indices: &mut [u8],
    state: &GameState,
    ocean: &OceanView,
    assets: &RetailAssets,
) {
    let base_a = ocean_picture(assets, 1422);
    let base_b = ocean_picture(assets, 1423);
    for (_, civilian) in state.civilian_units() {
        let Some(tile) = civilian.location().tile() else {
            continue;
        };
        let Some((x, y)) = ocean_tile_screen_origin(state.map().geometry(), tile, ocean) else {
            continue;
        };
        fill_ocean_cell(
            indices,
            x,
            y,
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        blit_ocean_sprite(indices, &base_a, 0xe0, x, y);
    }

    let mut drawn_provinces = Vec::new();
    for (_, unit) in state.military_units() {
        let Some(province) = unit.stationed_province() else {
            continue;
        };
        if drawn_provinces.contains(&province) {
            continue;
        }
        drawn_provinces.push(province);
        let Some(tile) = state.map().provinces[province].city_tile() else {
            continue;
        };
        let Some((x, y)) = ocean_tile_screen_origin(state.map().geometry(), tile, ocean) else {
            continue;
        };
        fill_ocean_cell(
            indices,
            x,
            y,
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        let source_x = ocean_improvement_source_x(&state.map()[tile]);
        if source_x < 1024 {
            blit_ocean_sprite(indices, &base_a, source_x, x, y);
        } else {
            blit_ocean_sprite(indices, &base_b, source_x - 1024, x, y);
        }
    }
}

fn ocean_tile_screen_origin(
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanView,
) -> Option<(i32, i32)> {
    let (row, column) = geometry.row_column(tile);
    let x = (i32::from(column) - ocean.origin_column).rem_euclid(108) * 16
        - if row & 1 == 0 { 8 } else { 0 };
    let y = (i32::from(row) - ocean.origin_row) * 16;
    (x < VIEWPORT_WIDTH as i32 && x + 16 > 0 && y < VIEWPORT_HEIGHT as i32 && y + 16 > 0)
        .then_some((x, y))
}

fn draw_ocean_line(indices: &mut [u8], mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: u8) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        put_ocean_pixel(indices, x0, y0, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let doubled = error * 2;
        if doubled >= dy {
            error += dy;
            x0 += sx;
        }
        if doubled <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

fn compose_ocean_selection(
    indices: &mut [u8],
    state: &GameState,
    interaction: &super::map_interaction::StrategicInteraction,
    hovered: Option<TileId>,
) {
    if interaction.mode != super::map_interaction::MapInteractionMode::Civilian {
        return;
    }
    let (Some(unit), Some(hovered)) = (interaction.civilian, hovered) else {
        return;
    };
    let Some(civilian) = state.civilian_unit(unit) else {
        return;
    };
    let action = state.civilian_tile_action(unit, hovered);
    if matches!(
        action,
        CivilianTileAction::None | CivilianTileAction::Blocked | CivilianTileAction::SelectUnit
    ) {
        return;
    }
    draw_ocean_tile_frame(indices, state.map().geometry(), hovered, &interaction.ocean);
    if civilian.unit_type() != CivilianUnitKind::Engineer
        || action != CivilianTileAction::EngineerSameTile
        || state.map()[hovered].region.is_some()
    {
        return;
    }
    let owner = TileOwnerTag::from_nation(state.turn().active_nation);
    for neighbor in state
        .map()
        .geometry()
        .neighbors(hovered)
        .into_iter()
        .flatten()
    {
        let tile = state.map()[neighbor];
        if tile.region.is_none()
            && (tile.terrain == TerrainKind::Water || tile.owner_nation == Some(owner))
        {
            draw_ocean_tile_frame(
                indices,
                state.map().geometry(),
                neighbor,
                &interaction.ocean,
            );
        }
    }
}

fn draw_ocean_tile_frame(
    indices: &mut [u8],
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanView,
) {
    let Some((x, y)) = ocean_tile_screen_origin(geometry, tile, ocean) else {
        return;
    };
    for offset in 0..16 {
        put_ocean_pixel(indices, x + offset, y, 0x20);
        put_ocean_pixel(indices, x + offset, y + 15, 0x20);
        put_ocean_pixel(indices, x, y + offset, 0x20);
        put_ocean_pixel(indices, x + 15, y + offset, 0x20);
    }
}

fn draw_ocean_borders(
    state: &GameState,
    tile: TileId,
    x: i32,
    y: i32,
    owner: usize,
    province: Option<ProvinceId>,
    water: bool,
    indices: &mut [u8],
) {
    let geometry = state.map().geometry();
    let neighbors = geometry.neighbors(tile);
    let owners = neighbors.map(|neighbor| {
        neighbor
            .map(|neighbor| ocean_owner(state.map()[neighbor].owner_nation) as i32)
            .unwrap_or(-1)
    });
    let provinces =
        neighbors.map(|neighbor| neighbor.and_then(|neighbor| state.map()[neighbor].province));
    let current = BORDER_PALETTE[owner];
    let mut put = |local_x: i32, local_y: i32, color: u8| {
        put_ocean_pixel(indices, x + local_x, y + local_y, color);
    };

    if owners[4] < 0 || owners[4] == owner as i32 {
        if province != provinces[4] {
            for py in 0..16 {
                put(0, py, current);
            }
        }
    } else {
        let neighbor = owners[4] as usize;
        let border = BORDER_PALETTE[neighbor];
        let pattern = usize::from(tile.get() % 4) * 4;
        if owners[5] == owners[4] {
            put(0, 0, OWNER_PALETTE[neighbor]);
            put(1, 0, border);
            put(0, 1, border);
            put(1, 1, current);
        } else {
            put(0, 0, current);
            put(0, 1, current);
        }
        for offset in 0..4 {
            let a = VERTICAL_OFFSETS[0][pattern + offset];
            let b = VERTICAL_OFFSETS[1][pattern + offset];
            let c = VERTICAL_OFFSETS[2][pattern + offset];
            put(0, c, current);
            put(0, b, border);
            put(1, b, current);
            if water {
                put(0, a, current);
                put(1, c, current);
                put(2, b, current);
            }
        }
        if owners[3] == owners[4] {
            put(0, 14, border);
            put(1, 14, current);
            put(0, 15, border);
            put(1, 15, OWNER_PALETTE[neighbor]);
        } else {
            put(0, 14, current);
            put(0, 15, current);
        }
    }

    if owners[1] >= 0 && owners[1] != owner as i32 {
        let neighbor = owners[1] as usize;
        let border = BORDER_PALETTE[neighbor];
        let neighbor_tile = neighbors[1].unwrap();
        let pattern = usize::from(neighbor_tile.get() % 4) * 4;
        if owners[0] == owners[1] {
            put(14, 0, border);
            put(15, 0, OWNER_PALETTE[owners[4].max(0) as usize]);
            put(15, 1, border);
            put(14, 1, current);
        } else {
            put(15, 0, current);
            put(15, 1, current);
        }
        for offset in 0..4 {
            let a = VERTICAL_OFFSETS[0][pattern + offset];
            let b = VERTICAL_OFFSETS[1][pattern + offset];
            let c = VERTICAL_OFFSETS[2][pattern + offset];
            put(15, c, current);
            put(15, b, border);
            put(14, b, current);
            if water {
                put(15, a, current);
                put(14, c, current);
                put(13, b, current);
            }
        }
        if owners[2] == owners[1] {
            put(15, 14, border);
            put(14, 14, current);
            put(15, 15, border);
            put(14, 15, OWNER_PALETTE[owners[4].max(0) as usize]);
        } else {
            put(15, 14, current);
            put(15, 15, current);
        }
    }

    draw_upper_edge(
        &mut put, tile, neighbors, owners, province, provinces, owner, water, false,
    );
    draw_upper_edge(
        &mut put, tile, neighbors, owners, province, provinces, owner, water, true,
    );
    draw_lower_edge(&mut put, tile, neighbors, owners, owner, water, true);
    draw_lower_edge(&mut put, tile, neighbors, owners, owner, water, false);
}

fn draw_upper_edge(
    put: &mut impl FnMut(i32, i32, u8),
    tile: TileId,
    neighbors: [Option<TileId>; 6],
    owners: [i32; 6],
    province: Option<ProvinceId>,
    provinces: [Option<ProvinceId>; 6],
    owner: usize,
    water: bool,
    right: bool,
) {
    let direction = if right { 0 } else { 5 };
    let base_x = if right { 8 } else { 0 };
    let current = BORDER_PALETTE[owner];
    if owners[direction] < 0 || owners[direction] == owner as i32 {
        if province != provinces[direction] {
            for px in 0..8 {
                put(base_x + px, 0, current);
            }
        }
        return;
    }
    let neighbor = owners[direction] as usize;
    let border = BORDER_PALETTE[neighbor];
    let pattern_tile = if right {
        neighbors[direction].unwrap()
    } else {
        tile
    };
    let pattern = usize::from(pattern_tile.get() % 4) * 2;
    if (!right && owners[5] != owners[4]) || (right && owners[5] != owner as i32) {
        put(base_x, 0, current);
        put(base_x + 1, 0, current);
    }
    for offset in 0..2 {
        let a = DIAGONAL_OFFSETS[0][pattern + offset];
        let b = DIAGONAL_OFFSETS[1][pattern + offset];
        let c = DIAGONAL_OFFSETS[2][pattern + offset];
        put(base_x + b, 0, current);
        put(base_x + a, 0, border);
        put(base_x + a, 1, current);
        if water {
            put(base_x + c, 0, current);
            put(base_x + b, 1, current);
            put(base_x + a, 2, current);
        }
    }
    if (!right && owners[0] != owner as i32) || (right && owners[0] != owners[1]) {
        put(base_x + 6, 0, current);
        put(base_x + 7, 0, current);
    }
}

fn draw_lower_edge(
    put: &mut impl FnMut(i32, i32, u8),
    tile: TileId,
    neighbors: [Option<TileId>; 6],
    owners: [i32; 6],
    owner: usize,
    water: bool,
    right: bool,
) {
    let direction = if right { 2 } else { 3 };
    if owners[direction] < 0 || owners[direction] == owner as i32 {
        return;
    }
    let base_x = if right { 8 } else { 0 };
    let current = BORDER_PALETTE[owner];
    let neighbor = owners[direction] as usize;
    let border = BORDER_PALETTE[neighbor];
    let pattern_tile = if right {
        neighbors[direction].unwrap()
    } else {
        tile
    };
    let pattern = usize::from(pattern_tile.get() % 4) * 2;
    if right || owners[3] != owners[4] {
        put(base_x, 15, current);
        put(base_x + 1, 15, current);
    }
    for offset in 0..2 {
        let a = DIAGONAL_OFFSETS[0][pattern + offset];
        let b = DIAGONAL_OFFSETS[1][pattern + offset];
        let c = DIAGONAL_OFFSETS[2][pattern + offset];
        put(base_x + b, 15, current);
        put(base_x + c, 15, border);
        put(base_x + c, 14, current);
        if water {
            put(base_x + a, 15, current);
            put(base_x + b, 14, current);
            put(base_x + c, 13, current);
        }
    }
    if (right && owners[2] != owners[1]) || (!right && owners[3] != owners[2]) {
        put(base_x + 6, 15, current);
        put(base_x + 7, 15, current);
    }
}

fn put_ocean_pixel(indices: &mut [u8], x: i32, y: i32, color: u8) {
    if (0..VIEWPORT_WIDTH as i32).contains(&x) && (0..VIEWPORT_HEIGHT as i32).contains(&y) {
        indices[y as usize * VIEWPORT_WIDTH + x as usize] = color;
    }
}

fn fill_ocean_cell(indices: &mut [u8], x: i32, y: i32, color: u8) {
    for dy in 0..OCEAN_TILE {
        let dest_y = y + dy;
        if !(0..VIEWPORT_HEIGHT as i32).contains(&dest_y) {
            continue;
        }
        for dx in 0..OCEAN_TILE {
            let dest_x = x + dx;
            if (0..VIEWPORT_WIDTH as i32).contains(&dest_x) {
                indices[dest_y as usize * VIEWPORT_WIDTH + dest_x as usize] = color;
            }
        }
    }
}

fn empty_ocean_image(palette: &DibPalette) -> Image {
    indexed_image(&vec![0; VIEWPORT_WIDTH * VIEWPORT_HEIGHT], palette)
}

fn indexed_image(indices: &[u8], palette: &DibPalette) -> Image {
    let mut rgba = Vec::with_capacity(indices.len() * 4);
    for &palette_index in indices {
        palette[palette_index].write_rgba(0xff, &mut rgba);
    }
    let mut image = Image::new(
        Extent3d {
            width: VIEWPORT_WIDTH as u32,
            height: VIEWPORT_HEIGHT as u32,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::strategic_map::StrategicInteraction;
    use crate::ui::test_support::{beginning_of_game_parts_with, strategic_map_beginning_context};

    fn pixel(indices: &[u8], x: usize, y: usize) -> u8 {
        indices[y * VIEWPORT_WIDTH + x]
    }

    fn clear_map(parts: &mut GameStateParts) {
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
            parts.map[tile].terrain = TerrainKind::Water;
            parts.map[tile].owner_nation = None;
            parts.map[tile].province = None;
        }
    }

    fn make_bounded(parts: &mut GameStateParts) {
        let tiles = TileId::all()
            .map(|tile| parts.map[tile])
            .collect::<Vec<_>>();
        parts.map = MapMgr::from_parts(MapTopology::Bounded, tiles, parts.map.provinces.clone());
    }

    #[test]
    fn alternate_map_is_hidden_instead_of_rendered_at_its_parked_coordinate() {
        let mut app = App::new();
        app.add_systems(Update, sync_ocean_view_frames);
        let land = app
            .world_mut()
            .spawn((
                LandMapFrame,
                Visibility::Visible,
                StrategicInteraction::default(),
            ))
            .id();
        let sea = app
            .world_mut()
            .spawn((OceanMapCanvas, Visibility::Hidden))
            .id();

        app.update();
        assert_eq!(
            app.world().get::<Visibility>(land),
            Some(&Visibility::Visible)
        );
        assert_eq!(
            app.world().get::<Visibility>(sea),
            Some(&Visibility::Hidden)
        );

        app.world_mut()
            .get_mut::<StrategicInteraction>(land)
            .unwrap()
            .ocean
            .active = true;
        app.update();
        assert_eq!(
            app.world().get::<Visibility>(land),
            Some(&Visibility::Hidden)
        );
        assert_eq!(
            app.world().get::<Visibility>(sea),
            Some(&Visibility::Visible)
        );
    }

    #[test]
    fn political_map_fills_land_by_owner_and_leaves_water_as_ocean() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let land = parts.map.geometry().tile(2, 10).unwrap();
        parts.map[land].terrain = TerrainKind::Plains;
        parts.map[land].owner_nation = Some(TileOwnerTag::new(3));
        let state = GameState::from_parts(parts);
        let indices = compose_ocean_indices(&state, &OceanView::default());

        assert_eq!(pixel(&indices, 160, 40), OWNER_PALETTE[3]);
        assert_eq!(pixel(&indices, 176, 40), OCEAN_FILL);
    }

    #[test]
    fn city_boundary_is_a_straight_owner_colored_edge() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(2, 10).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].terrain = TerrainKind::Plains;
        parts.map[tile].owner_nation = Some(TileOwnerTag::new(2));
        parts.map[tile].province = Some(ProvinceId::new(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileOwnerTag::new(2));
        parts.map[west].province = Some(ProvinceId::new(2));
        let state = GameState::from_parts(parts);
        let indices = compose_ocean_indices(&state, &OceanView::default());

        for y in 32..48 {
            assert_eq!(pixel(&indices, 152, y), BORDER_PALETTE[2]);
        }
    }

    #[test]
    fn different_owner_and_water_edges_use_the_retail_stipple_and_thickness() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(2, 10).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].owner_nation = Some(TileOwnerTag::new(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileOwnerTag::new(2));
        let state = GameState::from_parts(parts);
        let indices = compose_ocean_indices(&state, &OceanView::default());

        assert_eq!(pixel(&indices, 152, 38), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 153, 34), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 154, 34), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 152, 34), BORDER_PALETTE[2]);
    }

    #[test]
    fn wrapping_seam_uses_the_opposite_edge_neighbor() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        assert!(parts.map.geometry().wraps_horizontally());
        let left = parts.map.geometry().tile(3, 0).unwrap();
        let right = parts.map.geometry().tile(3, 107).unwrap();
        parts.map[left].terrain = TerrainKind::Plains;
        parts.map[left].owner_nation = Some(TileOwnerTag::new(0));
        parts.map[right].terrain = TerrainKind::Plains;
        parts.map[right].owner_nation = Some(TileOwnerTag::new(1));
        let state = GameState::from_parts(parts);
        let indices = compose_ocean_indices(&state, &OceanView::default());

        assert_eq!(pixel(&indices, 0, 48), BORDER_PALETTE[0]);
        assert!(indices.contains(&BORDER_PALETTE[1]));
    }

    #[test]
    fn bounded_map_blanks_and_rejects_the_right_wrapped_cell() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        make_bounded(&mut parts);
        let state = GameState::from_parts(parts);
        let ocean = OceanView {
            origin_column: 76,
            ..default()
        };
        let indices = compose_ocean_indices(&state, &ocean);

        assert_eq!(pixel(&indices, 511, 4), BOUNDED_MAP_BLANK);
        assert_eq!(
            ocean_tile_at_position(&state, Vec2::new(0.499, -0.49), 76, 0),
            None
        );
    }

    #[test]
    fn overlay_blit_preserves_retail_transparency_index() {
        let mut indices = vec![0x44; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
        let mut pixels = vec![0x10; 32 * 16];
        pixels[3 * 32 + 18] = 0x77;
        let picture = IndexedPicture {
            width: 32,
            height: 16,
            pixels,
        };
        blit_ocean_sprite(&mut indices, &picture, 16, 10, 20);
        assert_eq!(pixel(&indices, 12, 23), 0x77);
        assert_eq!(pixel(&indices, 11, 23), 0x44);
    }

    #[test]
    fn wrapped_routes_take_the_short_world_seam_path() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        parts.ocean.routes = vec![OceanRoute {
            start_column: 214,
            start_row: 2,
            end_column: 2,
            end_row: 2,
        }];
        let state = GameState::from_parts(parts);
        let ocean = OceanView::default();
        let mut indices = vec![0; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
        compose_ocean_routes(&mut indices, &state, &ocean);
        assert_eq!(pixel(&indices, 0, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 8, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 16, 32), 0);
        assert_eq!(pixel(&indices, 200, 32), 0);
    }
}
