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

struct CitySummaryControls {
    labor: [Entity; 3],
    population: Entity,
    power: Entity,
    needs: [(Entity, ResourceKind); 6],
    treasury: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityScreenRoot {
    summary: CitySummaryControls,
    buildings: Vec<(Entity, CityFacilitySlot)>,
}

#[derive(Component)]
pub(in crate::ui::city) struct CitySceneRoot;

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

pub(in crate::ui::city) fn enter_city_screen(mut commands: Commands, mut assets: UiAssetResources) {
    let root = generated::citymain_2011(&mut commands, &mut assets);
    commands
        .entity(root)
        .insert((CitySceneRoot, DespawnOnExit(AppState::City)));
}

pub(in crate::ui::city) fn bind_city_screen(
    mut commands: Commands,
    root: Single<Entity, Added<CitySceneRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: UiAssetResources,
    session: Res<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &children,
        &tags,
        fourcc!("topB"),
        Some(fourcc!("tool")),
    );

    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    let summary = bind_city_summary_values(&mut commands, *root, &children, &tags, &mut assets);
    let buildings = spawn_city_buildings(
        &mut commands,
        *root,
        &children,
        &tags,
        generated::CITY_BUILDINGS,
        generated::CITY_BUILDING_ACTIONS,
        &session.0,
        nation,
        &mut assets,
    );
    commands
        .entity(*root)
        .insert(CityScreenRoot { summary, buildings });
}

fn bind_city_summary_values(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    assets: &mut UiAssetResources,
) -> CitySummaryControls {
    let (font, layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 9,
            alignment: 1,
        })
        .expect("retail city placard text style");
    let bind_text = |commands: &mut Commands, tag| {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert((
            Text::new(""),
            font.clone(),
            layout,
            TextColor(Color::BLACK),
        ));
        entity
    };
    CitySummaryControls {
        labor: [fourcc!("untr"), fourcc!("trai"), fourcc!("prof")]
            .map(|tag| bind_text(commands, tag)),
        population: bind_text(commands, fourcc!("labP")),
        power: bind_text(commands, fourcc!("powe")),
        needs: [
            (fourcc!("grai"), ResourceKind::Grain),
            (fourcc!("prod"), ResourceKind::Fruit),
            (fourcc!("meat"), ResourceKind::Livestock),
            (fourcc!("hard"), ResourceKind::Hardware),
            (fourcc!("clot"), ResourceKind::Clothing),
            (fourcc!("furn"), ResourceKind::Furniture),
        ]
        .map(|(tag, resource)| (bind_text(commands, tag), resource)),
        treasury: find_descendant(root, fourcc!("trea"), children, tags),
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn spawn_city_buildings(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    visuals: &[CityBuildingVisual],
    actions: &[CityBuildingActionVisual],
    state: &GameState,
    nation: MajorNationId,
    assets: &mut UiAssetResources,
) -> Vec<(Entity, CityFacilitySlot)> {
    let main = find_descendant(root, fourcc!("main"), children, tags);
    let mut hit_regions = Vec::new();
    let mut buildings = Vec::new();
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
        let entity = commands
            .spawn((
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
                Name::new(format!("city-building:{:?}", visual.slot)),
            ))
            .id();
        buildings.push((entity, visual.slot));
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
    buildings
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
    assets: &mut UiAssetResources,
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
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
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
            let city = &session.0.nations().major(nation).city;
            *visibility = if city_building_action_enabled(city, action.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}

pub(in crate::ui::city) fn transparent_picture(
    assets: &mut UiAssetResources,
    picture_id: PictureId,
) -> Handle<Image> {
    let indexed = assets
        .indexed_picture(picture_id)
        .expect("retail City detail picture must have indexed pixels");
    assets
        .transformed_picture(picture_id, |image| {
            assert!(
                apply_palette_index_transparency(image, &indexed),
                "retail City detail picture dimensions must match its decoded image"
            );
        })
        .expect("retail City detail picture must load")
}

pub(in crate::ui::city) fn sync_city_screen(
    session: Res<GameSession>,
    screens: Query<Ref<CityScreenRoot>>,
    mut texts: Query<&mut Text>,
    mut assets: UiAssetResources,
    mut pictures: Query<(&mut ImageNode, &mut Visibility)>,
) {
    for root in &screens {
        if !session.is_changed() && !root.is_added() {
            continue;
        }
        let nation = MajorNationId::from_nation(session.0.turn().active_nation)
            .expect("City active nation is a major nation");
        let major = session.0.nations().major(nation);
        let city = &major.city;
        let labor = city.population.baseline_labor();
        let values = [
            (root.summary.labor[0], labor.low),
            (root.summary.labor[1], labor.medium),
            (root.summary.labor[2], labor.high),
            (root.summary.population, city.population.strength()),
            (root.summary.power, city.power_available),
        ];
        for (entity, value) in values {
            texts
                .get_mut(entity)
                .expect("city summary control has text")
                .0 = value.to_string();
        }
        for &(entity, resource) in &root.summary.needs {
            texts
                .get_mut(entity)
                .expect("city summary need control has text")
                .0 = city.population.predicted_need(resource).to_string();
        }
        texts
            .get_mut(root.summary.treasury)
            .expect("city treasury control has text")
            .0 = format_currency(major.common.treasury);
        for &(entity, slot) in &root.buildings {
            let (mut image, mut visibility) = pictures
                .get_mut(entity)
                .expect("City screen owns its building picture");
            let level = city_building_level(&session.0, nation, slot);
            let Some(picture) = city_building_picture(city, slot, level) else {
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
}
