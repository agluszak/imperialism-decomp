use super::*;

pub(crate) struct CityBuildingVisual {
    pub(crate) slot: CityFacilitySlot,
    pub(crate) origin: [i32; 2],
    pub(crate) draw_order: u8,
}

pub(crate) struct CityBuildingActionVisual {
    pub(crate) slot: CityFacilitySlot,
    pub(crate) level: u8,
    pub(crate) picture_id: PictureId,
    pub(crate) frame_count: u8,
    pub(crate) origin: [i32; 2],
    pub(crate) frame_size: [i32; 2],
}

pub(in crate::ui::city) struct CityBuildingHitRegion {
    pub(in crate::ui::city) origin: IVec2,
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) mask: CityBuildingHitMask,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityCanvas {
    pub(in crate::ui::city) buildings: Vec<CityBuildingHitRegion>,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityScreenRoot;

#[derive(Component)]
pub(in crate::ui::city) struct CitySceneRoot;

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum CitySummary {
    Labor(SkillBand),
    Population,
    Power,
    Need(ResourceKind),
    Treasury,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityHoverTitle;

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingSprite(CityFacilitySlot);

#[derive(Component)]
pub(in crate::ui::city) struct CityBuildingActionAnimation {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) frame_count: u8,
    pub(in crate::ui::city) frame_size: [i32; 2],
    pub(in crate::ui::city) frame: u8,
    pub(in crate::ui::city) timer: Timer,
}

pub(in crate::ui::city) const CITY_WIDTH: f32 = 640.0;
pub(in crate::ui::city) const CITY_HEIGHT: f32 = 480.0;

pub(in crate::ui::city) struct CityBuildingHitMask {
    pub(in crate::ui::city) width: i32,
    pub(in crate::ui::city) height: i32,
    pub(in crate::ui::city) polygon: Vec<IVec2>,
}

impl CityBuildingHitMask {
    pub(in crate::ui::city) fn from_indexed_picture(image: &IndexedPicture) -> Option<Self> {
        let width = image.width as usize;
        let height = image.height as usize;
        if width == 0 || height == 0 || image.pixels.len() != width * height {
            return None;
        }
        let transparent = image.pixels[(height - 1) * width];

        let mut edges = Vec::new();
        for y in (0..height).rev().step_by(2) {
            let row = &image.pixels[y * width..(y + 1) * width];
            let left = row.iter().position(|&pixel| pixel != transparent);
            let right = row.iter().rposition(|&pixel| pixel != transparent);
            if let (Some(left), Some(right)) = (left, right) {
                edges.push((y as i32, left as i32, right as i32));
            }
        }
        if edges.is_empty() {
            return None;
        }
        let mut polygon = Vec::with_capacity(edges.len() * 2);
        polygon.extend(edges.iter().map(|&(y, left, _)| IVec2::new(left, y)));
        polygon.extend(
            edges
                .iter()
                .rev()
                .map(|&(y, _, right)| IVec2::new(right, y)),
        );
        Some(Self {
            width: width as i32,
            height: height as i32,
            polygon,
        })
    }

    pub(in crate::ui::city) fn contains(&self, point: IVec2) -> bool {
        if point.x < 0 || point.y < 0 || point.x >= self.width || point.y >= self.height {
            return false;
        }
        let mut winding = 0_i32;
        let mut previous = self.polygon[self.polygon.len() - 1];
        for &current in &self.polygon {
            let side = i64::from(current.x - previous.x) * i64::from(point.y - previous.y)
                - i64::from(point.x - previous.x) * i64::from(current.y - previous.y);
            if previous.y <= point.y {
                if current.y > point.y && side > 0 {
                    winding += 1;
                }
            } else if current.y <= point.y && side < 0 {
                winding -= 1;
            }
            previous = current;
        }
        winding != 0
    }
}

pub(in crate::ui::city) fn apply_city_picture_transparency(
    image: &mut Image,
    indexed: &IndexedPicture,
) {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return;
    }
    let transparent = indexed.pixels[(height - 1) * width];
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == transparent {
            pixel[3] = 0;
        }
    }
}

pub(in crate::ui::city) fn enter_city_screen(mut commands: Commands) {
    let root = commands.spawn_scene(generated::citymain_2011()).id();
    commands
        .entity(root)
        .insert((CitySceneRoot, DespawnOnExit(AppState::City)));
}

pub(in crate::ui::city) fn bind_city_screen(
    mut commands: Commands,
    root: Single<Entity, Added<CitySceneRoot>>,
    tree: RetailTree,
    nodes: Query<&Node>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &tree,
        fourcc!("topB"),
        Some(fourcc!("tool")),
    );

    let nation = session.active_major_nation();
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
    bind_city_summary_values(&mut commands, *root, &tree, &nodes, &mut assets);
    bind_city_hover_title(&mut commands, *root, &tree, &mut assets);
    spawn_city_buildings(
        &mut commands,
        *root,
        &tree,
        generated::CITY_BUILDINGS,
        generated::CITY_BUILDING_ACTIONS,
        &session.game,
        nation,
        &mut assets,
    );
    commands.entity(*root).insert(CityScreenRoot);
}

/// `TPlacard::Draw` uses `BuildUiTextStyleDescriptor(0, 10, 0x2b6c)`: size 10
/// selects Book Antiqua (family 3), centered, palette `0x28`.
const CITY_SUMMARY_NUMBER_STYLE: RetailTextStylePreset = RetailTextStylePreset {
    font_family: 3,
    face_flags: 0,
    point_size: 10,
    alignment: 1,
};

fn bind_city_summary_values(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    nodes: &Query<&Node>,
    assets: &mut RetailUiAssets,
) {
    let (font, layout, line_height, _) = assets
        .text_style(CITY_SUMMARY_NUMBER_STYLE)
        .expect("retail city placard text style");
    let line_px = match line_height {
        LineHeight::Px(value) => value,
        LineHeight::RelativeToFont(_) => {
            unreachable!("retail placard line height is absolute")
        }
    };
    let text_color = assets.palette_color(0x28);
    let shadow_color = assets.palette_color(0);
    let bind_text = |commands: &mut Commands, tag, marker| {
        let entity = tree.find(root, tag);
        let node = nodes
            .get(entity)
            .expect("retail city placard has a native node");
        let Val::Px(height) = node.height else {
            unreachable!("retail city placard height is fixed in pixels");
        };
        // Bevy UI will not draw `Text` on the same entity as `ImageNode`. C++
        // `TPlacard::Draw` paints the picture first, then the count near the
        // bottom of the frame (`textY = frameHeight - 2`).
        commands.entity(entity).insert(marker).with_child((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(0),
                width: percent(100),
                height: percent(100),
                padding: UiRect::top(px((height - line_px).max(0.0))),
                ..default()
            },
            Text::new(""),
            font.clone(),
            layout,
            line_height,
            TextColor(text_color),
            TextShadow {
                offset: Vec2::ONE,
                color: shadow_color,
            },
            Pickable::IGNORE,
        ));
    };
    bind_text(
        commands,
        fourcc!("untr"),
        CitySummary::Labor(SkillBand::Low),
    );
    bind_text(
        commands,
        fourcc!("trai"),
        CitySummary::Labor(SkillBand::Medium),
    );
    bind_text(
        commands,
        fourcc!("prof"),
        CitySummary::Labor(SkillBand::High),
    );
    bind_text(commands, fourcc!("labP"), CitySummary::Population);
    bind_text(commands, fourcc!("powe"), CitySummary::Power);
    for (tag, resource) in [
        (fourcc!("grai"), ResourceKind::Grain),
        (fourcc!("prod"), ResourceKind::Fruit),
        (fourcc!("meat"), ResourceKind::Livestock),
        (fourcc!("hard"), ResourceKind::Hardware),
        (fourcc!("clot"), ResourceKind::Clothing),
        (fourcc!("furn"), ResourceKind::Furniture),
    ] {
        bind_text(commands, tag, CitySummary::Need(resource));
    }
    commands
        .entity(tree.find(root, fourcc!("trea")))
        .insert(CitySummary::Treasury);
}

fn bind_city_hover_title(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail city cursor-panel text style");
    commands.entity(tree.find(root, fourcc!("curs"))).insert((
        Text::new(""),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x28)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0),
        },
        CityHoverTitle,
    ));
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn spawn_city_buildings(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    visuals: &[CityBuildingVisual],
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut RetailUiAssets,
) {
    let main = tree.find(root, fourcc!("main"));
    let mut hit_regions = Vec::new();
    for visual in visuals {
        let level = city_building_level(state, nation, visual.slot);
        let offset = i16::from(visual.slot as u8);
        let mask_picture = PictureId::new(7100 + level * 16 + offset);
        let mask = match assets.indexed_picture(mask_picture) {
            Ok(indexed) => match CityBuildingHitMask::from_indexed_picture(&indexed) {
                Some(mask) => mask,
                None => {
                    warn!("city building mask {mask_picture} has no usable silhouette");
                    continue;
                }
            },
            Err(error) => {
                warn!("could not decode city building mask {mask_picture}: {error}");
                continue;
            }
        };
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(visual.origin[0] as f32),
                top: Val::Px(visual.origin[1] as f32),
                width: Val::Px(mask.width as f32),
                height: Val::Px(mask.height as f32),
                ..default()
            },
            ImageNode::default(),
            Visibility::Hidden,
            ZIndex(visual.draw_order as i32),
            Pickable::IGNORE,
            ChildOf(main),
            CityBuildingSprite(visual.slot),
            Name::new(format!("city-building:{:?}", visual.slot)),
        ));
        hit_regions.push((
            visual.draw_order,
            CityBuildingHitRegion {
                origin: IVec2::from_array(visual.origin),
                slot: visual.slot,
                mask,
            },
        ));
    }
    hit_regions.sort_by_key(|(draw_order, _)| *draw_order);
    commands.entity(main).insert((
        CityCanvas {
            buildings: hit_regions
                .into_iter()
                .map(|(_, building)| building)
                .collect(),
        },
        RelativeCursorPosition::default(),
    ));
    spawn_city_building_actions(commands, main, actions, state, nation, assets);
}

pub(in crate::ui::city) fn apply_palette_index_transparency(
    image: &mut Image,
    indexed: &IndexedPicture,
) -> bool {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return false;
    };
    if width == 0
        || height == 0
        || indexed.width as usize != width
        || indexed.height as usize != height
        || pixels.len() != width * height * 4
        || indexed.pixels.len() != width * height
    {
        return false;
    }
    for (pixel, &palette_index) in pixels.chunks_exact_mut(4).zip(&indexed.pixels) {
        if palette_index == 0x10 {
            pixel[3] = 0;
        }
    }
    true
}

pub(in crate::ui::city) fn apply_city_action_transparency(
    image: &mut Image,
    indexed: &IndexedPicture,
    frame_size: [i32; 2],
    frame_count: u8,
    occlusions: &[[i32; 4]],
) {
    if !apply_palette_index_transparency(image, indexed) {
        return;
    }
    let width = image.width() as usize;
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    let frame_width = frame_size[0] as usize;
    for &[left, top, right, bottom] in occlusions {
        for frame in 0..usize::from(frame_count) {
            for y in top as usize..bottom as usize {
                for x in left as usize..right as usize {
                    let alpha = ((y * width + frame * frame_width + x) * 4) + 3;
                    pixels[alpha] = 0;
                }
            }
        }
    }
}

pub(in crate::ui::city) fn city_building_action_enabled(
    city: &CityState,
    slot: CityFacilitySlot,
) -> bool {
    if slot == CityFacilitySlot::PowerPlant {
        !city.power_plant_upgrade_queued && city.orders.power_plant.progress.quantity > 0
    } else {
        assert!(
            industry_page(slot).is_some(),
            "generated city action belongs to a supported retail building"
        );
        !city_is_expanding(city, slot) && city.production_accum[slot] < city.production_orders[slot]
    }
}

pub(in crate::ui::city) fn spawn_city_building_actions(
    commands: &mut Commands,
    main: Entity,
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut RetailUiAssets,
) {
    let active_actions: Vec<_> = actions
        .iter()
        .filter(|action| city_building_level(state, nation, action.slot) == i16::from(action.level))
        .collect();
    for (draw_order, action) in active_actions.iter().enumerate() {
        let indexed = match assets.indexed_picture(action.picture_id) {
            Ok(indexed) => indexed,
            Err(error) => {
                warn!(
                    "could not decode city action strip {}: {error}",
                    action.picture_id
                );
                continue;
            }
        };
        let strip_width = u32::try_from(action.frame_size[0] * i32::from(action.frame_count))
            .expect("generated city action strip has a positive width");
        let frame_height = u32::try_from(action.frame_size[1])
            .expect("generated city action strip has a positive height");
        if indexed.width < strip_width || indexed.height < frame_height {
            warn!(
                "city action strip {} is smaller than its recovered frame table",
                action.picture_id
            );
            continue;
        }
        let mut occlusions = Vec::new();
        let action_right = action.origin[0] + action.frame_size[0];
        let action_bottom = action.origin[1] + action.frame_size[1];
        for later in &active_actions[draw_order + 1..] {
            let left = action.origin[0].max(later.origin[0]);
            let top = action.origin[1].max(later.origin[1]);
            let right = action_right.min(later.origin[0] + later.frame_size[0]);
            let bottom = action_bottom.min(later.origin[1] + later.frame_size[1]);
            if left < right && top < bottom {
                occlusions.push([
                    left - action.origin[0],
                    top - action.origin[1],
                    right - action.origin[0],
                    bottom - action.origin[1],
                ]);
            }
        }
        let handle = match assets.transformed_picture(action.picture_id, |image| {
            apply_city_action_transparency(
                image,
                &indexed,
                action.frame_size,
                action.frame_count,
                &occlusions,
            );
        }) {
            Ok(handle) => handle,
            Err(error) => {
                warn!(
                    "could not prepare city action strip {}: {error}",
                    action.picture_id
                );
                continue;
            }
        };
        let frame_width = action.frame_size[0] as f32;
        let frame_height = action.frame_size[1] as f32;
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(action.origin[0] as f32),
                top: Val::Px(action.origin[1] as f32),
                width: Val::Px(frame_width),
                height: Val::Px(frame_height),
                ..default()
            },
            ImageNode {
                image: handle,
                rect: Some(Rect::new(0.0, 0.0, frame_width, frame_height)),
                ..default()
            },
            CityBuildingActionAnimation {
                slot: action.slot,
                frame_count: action.frame_count,
                frame_size: action.frame_size,
                frame: 0,
                timer: Timer::new(
                    Duration::from_millis(if action.slot == CityFacilitySlot::PowerPlant {
                        160
                    } else {
                        224
                    }),
                    TimerMode::Repeating,
                ),
            },
            Visibility::Hidden,
            ZIndex(16 + draw_order as i32),
            Pickable::IGNORE,
            ChildOf(main),
            Name::new(format!("city-action:{}", action.picture_id)),
        ));
    }
}

pub(in crate::ui::city) fn animate_city_building_actions(
    time: Res<Time>,
    session: Res<GameSession>,
    mut actions: Query<(
        &mut CityBuildingActionAnimation,
        &mut ImageNode,
        &mut Visibility,
    )>,
) {
    let nation = session.active_major_nation();
    for (mut action, mut image, mut visibility) in &mut actions {
        action.timer.tick(time.delta());
        let advanced = action.timer.times_finished_this_tick();
        if advanced > 0 {
            let frame_count = u32::from(action.frame_count);
            let shown_frame = (u32::from(action.frame) + advanced - 1) % frame_count;
            action.frame = ((shown_frame + 1) % frame_count) as u8;
            let left = shown_frame as f32 * action.frame_size[0] as f32;
            image.rect = Some(Rect::new(
                left,
                0.0,
                left + action.frame_size[0] as f32,
                action.frame_size[1] as f32,
            ));
            let city = &session.game.nations().major(nation).city;
            *visibility = if city_building_action_enabled(city, action.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

fn city_summary_text_entity(
    entity: Entity,
    texts: &Query<&mut Text>,
    children: &Query<&Children>,
) -> Option<Entity> {
    if texts.contains(entity) {
        return Some(entity);
    }
    children
        .get(entity)
        .ok()?
        .iter()
        .find(|&child| texts.contains(child))
}

pub(in crate::ui::city) fn sync_city_summary(
    session: Res<GameSession>,
    added: Query<(), Added<CitySummary>>,
    mut summaries: Query<(Entity, &CitySummary, &mut Visibility)>,
    mut texts: Query<&mut Text>,
    children: Query<&Children>,
) {
    if !session.is_changed() && added.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let labor = city.population.baseline_labor();
    for (entity, summary, mut visibility) in &mut summaries {
        let Some(text_entity) = city_summary_text_entity(entity, &texts, &children) else {
            continue;
        };
        let Ok(mut text) = texts.get_mut(text_entity) else {
            continue;
        };
        let value = match *summary {
            CitySummary::Labor(SkillBand::Low) => labor.low.to_string(),
            CitySummary::Labor(SkillBand::Medium) => labor.medium.to_string(),
            CitySummary::Labor(SkillBand::High) => labor.high.to_string(),
            CitySummary::Population => city.population.strength().to_string(),
            CitySummary::Power => city.power_available.to_string(),
            CitySummary::Need(resource) => city
                .population
                .predicted_need_after_refresh(resource, city.orders.population_growth.quantity)
                .to_string(),
            CitySummary::Treasury => format_currency(major.common.treasury),
        };
        *visibility = if !matches!(summary, CitySummary::Treasury) && value == "0" {
            Visibility::Hidden
        } else {
            Visibility::Visible
        };
        text.0 = value;
    }
}

pub(in crate::ui::city) fn sync_city_hover_title(
    canvas: Option<Single<(&RelativeCursorPosition, &CityCanvas)>>,
    mut titles: Query<&mut Text, With<CityHoverTitle>>,
    assets: Res<RetailAssetsResource>,
    session: Res<GameSession>,
) {
    let Some((cursor, canvas)) = canvas.map(Single::into_inner) else {
        return;
    };
    let hovered = cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .map(|normalized| {
            IVec2::new(
                ((normalized.x + 0.5) * CITY_WIDTH).floor() as i32,
                ((normalized.y + 0.5) * CITY_HEIGHT).floor() as i32,
            )
        })
        .and_then(|point| {
            canvas
                .buildings
                .iter()
                .rev()
                .find(|building| building.mask.contains(point - building.origin))
        });
    let nation = session.active_major_nation();
    let text = hovered.map_or_else(String::new, |building| {
        if city_oil_industry_unlocked(&session.game, nation, building.slot) {
            assets
                .string(
                    CITY_BUILDING_STRING_GROUP,
                    city_string_index(building.slot as i16),
                )
                .expect("retail English City string")
        } else {
            String::new()
        }
    });
    for mut title in &mut titles {
        title.0.clone_from(&text);
    }
}

pub(in crate::ui::city) fn sync_city_buildings(
    session: Res<GameSession>,
    added: Query<(), Added<CityBuildingSprite>>,
    mut assets: RetailUiAssets,
    mut pictures: Query<(&CityBuildingSprite, &mut ImageNode, &mut Visibility)>,
) {
    if !session.is_changed() && added.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (CityBuildingSprite(slot), mut image, mut visibility) in &mut pictures {
        let level = city_building_level(&session.game, nation, *slot);
        let Some(picture) = city_building_picture(city, *slot, level) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let indexed = match assets.indexed_picture(picture) {
            Ok(indexed) => indexed,
            Err(error) => {
                warn!("could not decode indexed city building picture {picture}: {error}");
                continue;
            }
        };
        if let Err(error) = assets.with_picture_image_mut(picture, |picture_image| {
            apply_city_picture_transparency(picture_image, &indexed);
        }) {
            warn!("could not decode city building picture {picture}: {error}");
            continue;
        }
        match assets.picture(picture) {
            Ok(handle) => {
                image.image = handle;
                *visibility = Visibility::Visible;
            }
            Err(error) => warn!("could not load city building picture {picture}: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, peek_save_header};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

    #[test]
    fn city_production_placard_values_use_book_antiqua_10pt() {
        let style = resolve_retail_text_style(CITY_SUMMARY_NUMBER_STYLE).unwrap();
        assert_eq!(style.face, RetailFontFace::BookAntiquaRegular);
        assert_eq!(style.logical_pixel_height, 14);
        assert_eq!(style.alignment, RetailTextAlignment::Center);
    }

    #[test]
    fn beginning_city_need_windows_follow_predicted_needs() {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap();
        let state = LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        });
        let city = &state
            .nations()
            .major(MajorNationId::from_nation(selected_nation).unwrap())
            .city;
        let quantity = city.orders.population_growth.quantity;
        assert_eq!(city.population.count(), 7);
        assert_eq!(quantity, 0);
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Grain, quantity),
            4
        );
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Fruit, quantity),
            2
        );
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Livestock, quantity),
            1
        );
        assert_eq!(city.population.predicted_need(ResourceKind::Grain), 0);
        assert_eq!(city.population.predicted_need(ResourceKind::Fruit), 0);
        assert_eq!(city.population.predicted_need(ResourceKind::Livestock), 0);
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Hardware, quantity),
            0
        );
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Clothing, quantity),
            0
        );
        assert_eq!(
            city.population
                .predicted_need_after_refresh(ResourceKind::Furniture, quantity),
            0
        );
    }
}
