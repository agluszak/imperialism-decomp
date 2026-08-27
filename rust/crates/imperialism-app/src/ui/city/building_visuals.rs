use super::*;
use crate::ui::retail::apply_index_transparency;
use crate::ui::retail_raster::IndexedRasterExt;

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

pub(crate) struct CityBuildingHitRegion {
    pub(crate) origin: IVec2,
    pub(crate) slot: CityFacilitySlot,
    pub(crate) mask: CityBuildingHitMask,
}

#[derive(Component)]
pub(crate) struct CityCanvas {
    pub(crate) buildings: Vec<CityBuildingHitRegion>,
}

#[derive(Component)]
pub(crate) struct CitySceneRoot;

#[derive(Clone, Copy)]
struct PlacardUi(Entity, Entity);

struct CitySummaryUi {
    labor: [PlacardUi; 3],
    population: PlacardUi,
    power: PlacardUi,
    needs: [(ResourceKind, PlacardUi); 6],
    treasury: Entity,
}

#[derive(Component)]
pub(crate) struct CityScreenView {
    summary: CitySummaryUi,
    hover_title: Entity,
}

#[derive(Component)]
pub(crate) struct CityBuildingSprite {
    slot: CityFacilitySlot,
    picture: Option<PictureId>,
}

#[derive(Component)]
pub(crate) struct CityBuildingActionAnimation {
    pub(crate) slot: CityFacilitySlot,
    pub(crate) frame_count: u8,
    pub(crate) frame_size: [i32; 2],
    pub(crate) frame: u8,
    pub(crate) timer: Timer,
}

pub(crate) const CITY_WIDTH: f32 = 640.0;
pub(crate) const CITY_HEIGHT: f32 = 480.0;

pub(crate) struct CityBuildingHitMask {
    pub(crate) width: i32,
    pub(crate) height: i32,
    pub(crate) polygon: Vec<IVec2>,
}

impl CityBuildingHitMask {
    pub(crate) fn from_indexed_picture(image: &IndexedPicture) -> Option<Self> {
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

    pub(crate) fn contains(&self, point: IVec2) -> bool {
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

fn city_oil_industry_unlocked_for(slot: CityFacilitySlot, oil_drilling: bool) -> bool {
    !matches!(
        slot,
        CityFacilitySlot::OilRefinery | CityFacilitySlot::PowerPlant
    ) || oil_drilling
}

fn city_oil_industry_unlocked(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> bool {
    city_oil_industry_unlocked_for(
        slot,
        state.technology().city_capabilities_by_nation[nation].oil_drilling,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CityBuildingClick {
    Construction,
    Production,
}

fn city_building_click_action(
    slot: CityFacilitySlot,
    building_type: i16,
    oil_drilling: bool,
) -> Option<CityBuildingClick> {
    if slot.is_capacity_center() && building_type == 0 {
        return city_oil_industry_unlocked_for(slot, oil_drilling)
            .then_some(CityBuildingClick::Construction);
    }
    Some(CityBuildingClick::Production)
}

pub(crate) fn city_building_click(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> Option<CityBuildingClick> {
    let major = state.nations().major(nation);
    city_building_click_action(
        slot,
        major
            .city
            .building_type(slot, &major.economy, major.common.owned_region_count()),
        state.technology().city_capabilities_by_nation[nation].oil_drilling,
    )
}

pub(crate) fn city_building_level(
    state: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
) -> i16 {
    let major = state.nations().major(nation);
    major.city.next_building_type(
        slot,
        &major.economy,
        major.common.owned_region_count(),
        state.technology().city_capabilities_by_nation[nation].advanced_iron_working,
    )
}

pub(crate) fn city_is_expanding(city: &CityState, slot: CityFacilitySlot) -> bool {
    ExpandableFacility::try_from_slot(slot)
        .is_some_and(|facility| city.orders.expansions[facility].progress.quantity > 0)
}

pub(crate) fn city_building_picture(
    city: &CityState,
    slot: CityFacilitySlot,
    level: i16,
) -> Option<PictureId> {
    let expanding = city_is_expanding(city, slot);
    let should_draw = level >= 1
        || (ExpandableFacility::try_from_slot(slot).is_some() && expanding)
        || (slot == CityFacilitySlot::PowerPlant && city.power_plant_upgrade_queued);
    if !should_draw {
        return None;
    }
    if slot == CityFacilitySlot::PowerPlant {
        return Some(PictureId::new(if city.power_plant_upgrade_queued {
            7011
        } else {
            7027
        }));
    }
    let offset = i16::from(slot.retail());
    let normal = level == 0 || offset > 5 || !expanding || !slot.is_capacity_center();
    Some(PictureId::new(
        (if normal { 7000 } else { 7300 }) + level * 16 + offset,
    ))
}

pub(crate) fn enter_city_screen(mut commands: Commands) {
    let root = commands.spawn_scene(generated::citymain_2011()).id();
    commands
        .entity(root)
        .insert((CitySceneRoot, DespawnOnExit(AppState::City)));
}

pub(crate) fn bind_city_screen(
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
        true,
    );

    let nation = session.active_major_nation();
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
    let summary = bind_city_summary_values(&mut commands, *root, &tree, &nodes, &mut assets);
    let hover_title = bind_city_hover_title(&mut commands, *root, &tree, &mut assets);
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
    commands.entity(*root).insert(CityScreenView {
        summary,
        hover_title,
    });
}

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
) -> CitySummaryUi {
    let (font, layout, line_height, _) = assets
        .text_style(CITY_SUMMARY_NUMBER_STYLE)
        .expect("placard style");
    let line_px = match line_height {
        LineHeight::Px(value) => value,
        LineHeight::RelativeToFont(_) => unreachable!("absolute line height"),
    };
    let text_color = assets.palette_color(0x28);
    let shadow_color = assets.palette_color(0);
    let bind_placard = |commands: &mut Commands, tag| {
        let frame = tree.find(root, tag);
        let node = nodes.get(frame).expect("placard node");
        let Val::Px(height) = node.height else {
            unreachable!("fixed placard height");
        };
        let text = commands
            .spawn((
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
                Visibility::Inherited,
                ChildOf(frame),
            ))
            .id();
        PlacardUi(frame, text)
    };
    let labor = [
        bind_placard(commands, fourcc!("untr")),
        bind_placard(commands, fourcc!("trai")),
        bind_placard(commands, fourcc!("prof")),
    ];
    let population = bind_placard(commands, fourcc!("labP"));
    let power = bind_placard(commands, fourcc!("powe"));
    let needs = [
        (ResourceKind::Grain, fourcc!("grai")),
        (ResourceKind::Fruit, fourcc!("prod")),
        (ResourceKind::Livestock, fourcc!("meat")),
        (ResourceKind::Hardware, fourcc!("hard")),
        (ResourceKind::Clothing, fourcc!("clot")),
        (ResourceKind::Furniture, fourcc!("furn")),
    ]
    .map(|(resource, tag)| (resource, bind_placard(commands, tag)));
    let treasury = tree.find(root, fourcc!("trea"));
    CitySummaryUi {
        labor,
        population,
        power,
        needs,
        treasury,
    }
}

fn bind_city_hover_title(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
) -> Entity {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail city cursor-panel text style");
    let entity = tree.find(root, fourcc!("curs"));
    commands.entity(entity).insert((
        Text::new(""),
        font,
        layout,
        line_height,
        TextColor(assets.palette_color(0x28)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0),
        },
    ));
    entity
}

pub(crate) fn spawn_city_buildings(
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
            CityBuildingSprite {
                slot: visual.slot,
                picture: None,
            },
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
    commands
        .entity(main)
        .insert((
            CityCanvas {
                buildings: hit_regions
                    .into_iter()
                    .map(|(_, building)| building)
                    .collect(),
            },
            RelativeCursorPosition::default(),
        ))
        .observe(on_city_canvas_click);
    spawn_city_building_actions(commands, main, actions, state, nation, assets);
}

pub(crate) fn apply_city_action_transparency(
    image: &mut Image,
    indexed: &IndexedPicture,
    frame_size: [i32; 2],
    frame_count: u8,
    occlusions: &[[i32; 4]],
) {
    let mut mask = indexed.clone();
    for &[left, top, right, bottom] in occlusions {
        for frame in 0..i32::from(frame_count) {
            let frame_x = frame * frame_size[0];
            mask.fill_rect(
                IRect::new(left + frame_x, top, right + frame_x, bottom),
                0x10,
            );
        }
    }
    apply_index_transparency(image, &mask, 0x10);
}

pub(crate) fn city_building_action_enabled(city: &CityState, slot: CityFacilitySlot) -> bool {
    if slot == CityFacilitySlot::PowerPlant {
        !city.power_plant_upgrade_queued && city.orders.power_plant.progress.quantity > 0
    } else {
        assert!(
            ExpandableFacility::try_from_slot(slot).is_some(),
            "generated city action belongs to a supported retail building"
        );
        !city_is_expanding(city, slot) && city.production_accum[slot] < city.production_orders[slot]
    }
}

pub(crate) fn spawn_city_building_actions(
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

pub(crate) fn animate_city_building_actions(
    time: Res<Time>,
    mut actions: Query<(&mut CityBuildingActionAnimation, &mut ImageNode)>,
) {
    for (mut action, mut image) in &mut actions {
        action.timer.tick(time.delta());
        let advanced = action.timer.times_finished_this_tick();
        if advanced == 0 {
            continue;
        }
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
    }
}

fn render_placard(ui: &mut CityUi, placard: PlacardUi, value: String) {
    let shown = value != "0";
    ui.visible(placard.0, shown);
    ui.visible(placard.1, shown);
    ui.text(placard.1, value);
}

pub(crate) fn render_city_screen(
    session: Res<GameSession>,
    screen: Option<Single<&CityScreenView>>,
    canvas: Option<Single<(&RelativeCursorPosition, &CityCanvas)>>,
    mut ui: CityUi,
    assets: Res<RetailAssetsResource>,
) {
    let Some(screen) = screen.map(Single::into_inner) else {
        return;
    };
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let labor = city.population.baseline_labor();
    let summary = &screen.summary;
    render_placard(&mut ui, summary.labor[0], labor.low.to_string());
    render_placard(&mut ui, summary.labor[1], labor.medium.to_string());
    render_placard(&mut ui, summary.labor[2], labor.high.to_string());
    render_placard(
        &mut ui,
        summary.population,
        city.population.strength().to_string(),
    );
    render_placard(&mut ui, summary.power, city.power_available.to_string());
    for &(resource, placard) in &summary.needs {
        render_placard(
            &mut ui,
            placard,
            city.population
                .predicted_need_after_refresh(resource, city.orders.population_growth.quantity)
                .to_string(),
        );
    }
    ui.text(summary.treasury, format_currency(major.common.treasury));

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
    let text = hovered.map_or_else(String::new, |building| {
        if city_oil_industry_unlocked(&session.game, nation, building.slot) {
            assets
                .string(
                    CITY_BUILDING_STRING_GROUP,
                    city_string_index(i16::from(building.slot.retail())),
                )
                .expect("retail English City string")
        } else {
            String::new()
        }
    });
    ui.text(screen.hover_title, text);
}

pub(crate) fn render_city_buildings(
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    mut pictures: Query<(&mut CityBuildingSprite, &mut ImageNode, &mut Visibility)>,
    mut actions: Query<
        (&CityBuildingActionAnimation, &mut Visibility),
        Without<CityBuildingSprite>,
    >,
    added_sprites: Query<(), Added<CityBuildingSprite>>,
    added_actions: Query<(), Added<CityBuildingActionAnimation>>,
) {
    if !session.is_changed() && added_sprites.is_empty() && added_actions.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (mut sprite, mut image, mut visibility) in &mut pictures {
        let level = city_building_level(&session.game, nation, sprite.slot);
        let Some(picture) = city_building_picture(city, sprite.slot, level) else {
            sprite.picture = None;
            *visibility = Visibility::Hidden;
            continue;
        };
        if sprite.picture == Some(picture) {
            *visibility = Visibility::Visible;
            continue;
        }
        let indexed = match assets.indexed_picture(picture) {
            Ok(indexed) => indexed,
            Err(error) => {
                warn!("could not decode indexed city building picture {picture}: {error}");
                continue;
            }
        };
        if indexed.width == 0 || indexed.height == 0 {
            warn!("city building picture {picture} has no pixels");
            continue;
        }
        let transparent = indexed.pixels[(indexed.height as usize - 1) * indexed.width as usize];
        match assets.transformed_picture(picture, |picture_image| {
            apply_index_transparency(picture_image, &indexed, transparent);
        }) {
            Ok(handle) => {
                image.image = handle;
                sprite.picture = Some(picture);
                *visibility = Visibility::Visible;
            }
            Err(error) => warn!("could not load city building picture {picture}: {error}"),
        }
    }
    for (action, mut visibility) in &mut actions {
        *visibility = if city_building_action_enabled(city, action.slot) {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::DibPalette;

    #[test]
    fn action_occlusions_clear_the_same_rectangle_in_every_frame() {
        let indexed = IndexedPicture {
            width: 6,
            height: 2,
            pixels: vec![1; 12],
        };
        let mut image = indexed.to_image(&DibPalette::default());

        apply_city_action_transparency(&mut image, &indexed, [3, 2], 2, &[[1, 0, 2, 2]]);

        let alpha = image
            .data
            .as_ref()
            .unwrap()
            .chunks_exact(4)
            .map(|pixel| pixel[3])
            .collect::<Vec<_>>();
        assert_eq!(
            alpha,
            [0xff, 0, 0xff, 0xff, 0, 0xff, 0xff, 0, 0xff, 0xff, 0, 0xff]
        );
    }

    #[test]
    fn city_production_placard_values_use_book_antiqua_10pt() {
        let style = resolve_retail_text_style(CITY_SUMMARY_NUMBER_STYLE).unwrap();
        assert_eq!(style.face, RetailFontFace::BookAntiquaRegular);
        assert_eq!(style.logical_pixel_height, 14);
        assert_eq!(style.alignment, RetailTextAlignment::Center);
    }

    #[test]
    fn unbuilt_oil_and_power_stay_closed_without_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(city_building_click_action(slot, 0, false), None);
            assert!(!city_oil_industry_unlocked_for(slot, false));
        }
    }

    #[test]
    fn unbuilt_oil_and_power_open_construction_after_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(
                city_building_click_action(slot, 0, true),
                Some(CityBuildingClick::Construction)
            );
            assert!(city_oil_industry_unlocked_for(slot, true));
        }
    }

    #[test]
    fn built_oil_and_power_open_production_even_without_oil_drilling() {
        for slot in [CityFacilitySlot::OilRefinery, CityFacilitySlot::PowerPlant] {
            assert_eq!(
                city_building_click_action(slot, 1, false),
                Some(CityBuildingClick::Production)
            );
        }
    }

    #[test]
    fn other_unbuilt_capacity_centers_open_construction() {
        assert_eq!(
            city_building_click_action(CityFacilitySlot::TextileMill, 0, false),
            Some(CityBuildingClick::Construction)
        );
        assert_eq!(
            city_building_click_action(CityFacilitySlot::Shipyard, 0, false),
            Some(CityBuildingClick::Production)
        );
    }

    #[test]
    fn beginning_of_game_does_not_open_unbuilt_oil_or_power() {
        let state = crate::ui::test_support::beginning_of_game();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::OilRefinery),
            None
        );
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::PowerPlant),
            None
        );
        assert!(!city_oil_industry_unlocked(
            &state,
            nation,
            CityFacilitySlot::OilRefinery
        ));
        assert_eq!(
            city_building_click(&state, nation, CityFacilitySlot::TextileMill),
            Some(CityBuildingClick::Production)
        );
    }
}
