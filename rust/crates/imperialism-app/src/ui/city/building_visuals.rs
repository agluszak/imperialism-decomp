use super::*;

pub(in crate::ui::city) const CITY_WIDTH: f32 = 640.0;
pub(in crate::ui::city) const CITY_HEIGHT: f32 = 480.0;

#[derive(Component)]
pub(in crate::ui::city) struct CityScreenControls {
    labor_low: Entity,
    labor_medium: Entity,
    labor_high: Entity,
    labor_available: Entity,
    power_available: Entity,
    predicted_grain: Entity,
    predicted_fruit: Entity,
    predicted_livestock: Entity,
    predicted_hardware: Entity,
    predicted_clothing: Entity,
    predicted_furniture: Entity,
    treasury: Entity,
}

#[derive(Clone)]
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

pub(in crate::ui::city) fn enter_city_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    session: Option<Res<GameSession>>,
) {
    let view_id = city_view_id();
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    let mut root = commands.entity(spawned.root);
    root.insert((
        GameScreenRoot(view_id),
        CityScreenRoot,
        DespawnOnExit(AppState::City),
    ));

    let Some(session) = session else {
        warn!("city screen opened without an authoritative game session");
        return;
    };
    let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
        warn!("city screen active nation is not a major nation");
        return;
    };
    let controls = bind_city_summary_values(&mut commands, &spawned, &mut assets);
    commands.entity(spawned.root).insert(controls);
    spawn_city_buildings(
        &mut commands,
        &spawned,
        &view.city_buildings,
        &view.city_building_actions,
        &session.0,
        nation,
        &mut assets,
    );
}

pub(in crate::ui::city) fn bind_city_summary_values(
    commands: &mut Commands,
    spawned: &crate::ui::catalog::SpawnedView,
    assets: &mut UiAssetResources,
) -> CityScreenControls {
    let (font, layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 9,
            alignment: 1,
        })
        .expect("retail city placard text style");
    let bind_text = |commands: &mut Commands, tag| {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(""),
            font.clone(),
            layout,
            TextColor(Color::BLACK),
        ));
        entity
    };
    CityScreenControls {
        labor_low: bind_text(commands, fourcc!("untr")),
        labor_medium: bind_text(commands, fourcc!("trai")),
        labor_high: bind_text(commands, fourcc!("prof")),
        labor_available: bind_text(commands, fourcc!("labP")),
        power_available: bind_text(commands, fourcc!("powe")),
        predicted_grain: bind_text(commands, fourcc!("grai")),
        predicted_fruit: bind_text(commands, fourcc!("prod")),
        predicted_livestock: bind_text(commands, fourcc!("meat")),
        predicted_hardware: bind_text(commands, fourcc!("hard")),
        predicted_clothing: bind_text(commands, fourcc!("clot")),
        predicted_furniture: bind_text(commands, fourcc!("furn")),
        treasury: spawned.unique(fourcc!("trea")),
    }
}

pub(in crate::ui::city) fn spawn_city_buildings(
    commands: &mut Commands,
    spawned: &SpawnedView,
    visuals: &[CityBuildingVisual],
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut UiAssetResources,
) {
    let main = spawned.unique(fourcc!("main"));
    let city = &state.nations().major(nation).city;
    let mut buildings = Vec::new();
    for visual in visuals {
        let Some(level) = city_building_level(state, nation, visual.slot) else {
            continue;
        };
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
        let mut image = ImageNode::default();
        let mut visibility = Visibility::Hidden;
        if let Some(picture) = city_building_picture(city, visual.slot, level) {
            match assets.indexed_picture(picture) {
                Ok(indexed_picture) => {
                    if let Err(error) = assets.with_picture_image_mut(picture, |image| {
                        apply_city_picture_transparency(image, &indexed_picture);
                    }) {
                        warn!("could not decode city building picture {picture}: {error}");
                    } else {
                        match assets.picture(picture) {
                            Ok(handle) => {
                                image.image = handle;
                                visibility = Visibility::Visible;
                            }
                            Err(error) => {
                                warn!("could not load city building picture {picture}: {error}");
                            }
                        }
                    }
                }
                Err(error) => {
                    warn!("could not decode indexed city building picture {picture}: {error}");
                }
            }
        }
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(visual.origin[0] as f32),
                top: Val::Px(visual.origin[1] as f32),
                width: Val::Px(mask.width as f32),
                height: Val::Px(mask.height as f32),
                ..default()
            },
            image,
            visibility,
            CityBuildingPicture {
                nation,
                slot: visual.slot,
            },
            ZIndex(visual.draw_order as i32),
            Pickable::IGNORE,
            ChildOf(main),
            Name::new(format!("city-building:{:?}", visual.slot)),
        ));
        buildings.push(CityBuildingHitRegion {
            origin: IVec2::from_array(visual.origin),
            draw_order: visual.draw_order,
            slot: visual.slot,
            dialog: visual.dialog.clone(),
            mask,
        });
    }
    buildings.sort_by_key(|building| building.draw_order);
    commands
        .entity(main)
        .insert((CityCanvas { buildings }, RelativeCursorPosition::default()));
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
            is_ordinary_industry(slot),
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
    assets: &mut UiAssetResources,
) {
    let active_actions: Vec<_> = actions
        .iter()
        .filter(|action| {
            city_building_level(state, nation, action.slot) == Some(i16::from(action.level))
        })
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
                nation,
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
            let city = &session.0.nations().major(action.nation).city;
            *visibility = if city_building_action_enabled(city, action.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn transparent_picture(
    ui: &mut UiSpawner,
    picture_id: PictureId,
) -> Handle<Image> {
    let indexed = ui
        .indexed_picture(picture_id)
        .expect("retail City detail picture must have indexed pixels");
    ui.transformed_picture(picture_id, |image| {
        assert!(
            apply_palette_index_transparency(image, &indexed),
            "retail City detail picture dimensions must match its decoded image"
        );
    })
    .expect("retail City detail picture must load")
}

pub(in crate::ui::city) fn sync_city_screen(
    session: Res<GameSession>,
    screens: Query<(&CityScreenControls, Ref<CityScreenRoot>)>,
    mut texts: Query<&mut Text>,
    mut assets: UiAssetResources,
    mut buildings: Query<(&CityBuildingPicture, &mut ImageNode, &mut Visibility)>,
) {
    let mut refresh_buildings = false;
    for (controls, root) in &screens {
        if !session.is_changed() && !root.is_added() {
            continue;
        }
        refresh_buildings = true;
        let Some(nation) = MajorNationId::from_nation(session.0.turn().active_nation) else {
            warn!("city screen active nation is not a major nation");
            continue;
        };
        let major = session.0.nations().major(nation);
        let city = &major.city;
        let labor = city.population.baseline_labor();
        let values = [
            (controls.labor_low, labor.low),
            (controls.labor_medium, labor.medium),
            (controls.labor_high, labor.high),
            (controls.labor_available, city.population.strength()),
            (controls.power_available, city.power_available),
            (
                controls.predicted_grain,
                city.population.predicted_need(ResourceKind::Grain),
            ),
            (
                controls.predicted_fruit,
                city.population.predicted_need(ResourceKind::Fruit),
            ),
            (
                controls.predicted_livestock,
                city.population.predicted_need(ResourceKind::Livestock),
            ),
            (
                controls.predicted_hardware,
                city.population.predicted_need(ResourceKind::Hardware),
            ),
            (
                controls.predicted_clothing,
                city.population.predicted_need(ResourceKind::Clothing),
            ),
            (
                controls.predicted_furniture,
                city.population.predicted_need(ResourceKind::Furniture),
            ),
        ];
        for (entity, value) in values {
            texts
                .get_mut(entity)
                .expect("city summary control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(controls.treasury)
            .expect("city treasury control has text")
            .0 = format_currency(major.common.treasury);
    }

    if !refresh_buildings {
        return;
    }
    for (building, mut image, mut visibility) in &mut buildings {
        let Some(level) = city_building_level(&session.0, building.nation, building.slot) else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let city = &session.0.nations().major(building.nation).city;
        let Some(picture) = city_building_picture(city, building.slot, level) else {
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
