use super::*;
use crate::ui::retail::AmountBarParts;

pub(in crate::ui::city) struct WarehouseUi {
    stocks: Vec<(Entity, ResourceKind)>,
    labor: Entity,
    power: Entity,
}

pub(in crate::ui::city) struct FoodUi {
    rail: RailUi,
    labor: Entity,
    grain: Entity,
    fruit: Entity,
    fish_and_livestock: Entity,
}

pub(in crate::ui::city) struct TransportUi {
    rail: RailUi,
    labor: Entity,
    lumber: Entity,
    steel: Entity,
}

pub(in crate::ui::city) struct PopulationUi {
    rail: RailUi,
    food: Entity,
    clothing: Entity,
    furniture: Entity,
    capacity: Entity,
    provinces: Entity,
}

pub(in crate::ui::city) fn bind_warehouse(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) -> WarehouseUi {
    let advanced_production_unlocked = state.technology().advanced_production_unlocked();

    let stocks = (0..=ResourceKind::Livestock.retail())
        .filter_map(ResourceKind::from_index)
        .filter(|resource| *resource != ResourceKind::Fish)
        .map(|resource| (tree.find(root, resource_control_tag(resource)), resource))
        .collect();
    let labor = tree.find(root, fourcc!("labo"));
    let power = tree.find(root, fourcc!("powe"));
    for tag in [fourcc!("oil "), fourcc!("fuel"), fourcc!("powe")] {
        let control = tree.find(root, tag);
        let mut control_commands = commands.entity(control);
        if advanced_production_unlocked {
            control_commands
                .insert(Visibility::Visible)
                .remove::<InteractionDisabled>();
        } else {
            control_commands.insert((Visibility::Hidden, InteractionDisabled));
        }
    }
    if advanced_production_unlocked {
        let dialog = tree.find(root, fourcc!("DLOG"));
        commands
            .entity(dialog)
            .insert(ImageNode::new(assets.picture(PictureId::new(9215))));
        commands
            .entity(dialog)
            .entry::<Node>()
            .and_modify(|mut node| node.overflow = Overflow::clip());
        for entity in [root, dialog] {
            commands
                .entity(entity)
                .entry::<Node>()
                .and_modify(|mut node| {
                    node.width = px(176);
                    node.height = px(335);
                });
        }
        for tag in [
            fourcc!("hors"),
            fourcc!("food"),
            fourcc!("labo"),
            fourcc!("grai"),
            fourcc!("prod"),
            fourcc!("live"),
        ] {
            let entity = tree.find(root, tag);
            commands
                .entity(entity)
                .entry::<Node>()
                .and_modify(|mut node| {
                    let Val::Px(top) = node.top else {
                        panic!("generated Warehouse control has fixed retail coordinates");
                    };
                    node.top = px(top + 176.0);
                });
        }
    }
    WarehouseUi {
        stocks,
        labor,
        power,
    }
}

pub(in crate::ui::city) fn bind_food(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
) -> FoodUi {
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        amount_bars,
        CityFacilitySlot::FoodProcessing,
        CityOrderId::FoodProcessing,
        fourcc!("food"),
        2,
    );
    FoodUi {
        rail,
        labor: tree.find(root, fourcc!("labV")),
        grain: tree.find(root, fourcc!("grai")),
        fruit: tree.find(root, fourcc!("prod")),
        fish_and_livestock: tree.find(root, fourcc!("fish")),
    }
}

pub(in crate::ui::city) fn bind_power(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
) -> RailUi {
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        amount_bars,
        CityFacilitySlot::PowerPlant,
        CityOrderId::PowerPlant,
        fourcc!("powe"),
        6,
    );
    let fuel = tree.find(root, fourcc!("fuel"));
    commands
        .entity(fuel)
        .insert((Text::new("X"), Visibility::Hidden));
    rail
}

pub(in crate::ui::city) fn bind_transport(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
) -> TransportUi {
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        amount_bars,
        CityFacilitySlot::Transport,
        CityOrderId::TransportCapacity,
        fourcc!("rail"),
        1,
    );
    TransportUi {
        rail,
        labor: tree.find(root, fourcc!("labV")),
        lumber: tree.find(root, fourcc!("lumb")),
        steel: tree.find(root, fourcc!("stee")),
    }
}

pub(in crate::ui::city) fn bind_population(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
) -> PopulationUi {
    let rail = bind_rail(
        commands,
        assets,
        root,
        tree,
        amount_bars,
        CityFacilitySlot::RegionalPopulation,
        CityOrderId::PopulationGrowth,
        fourcc!("popu"),
        1,
    );
    PopulationUi {
        rail,
        food: tree.find(root, fourcc!("food")),
        clothing: tree.find(root, fourcc!("clot")),
        furniture: tree.find(root, fourcc!("furn")),
        capacity: tree.find(root, fourcc!("capT")),
        provinces: tree.find(root, fourcc!("prov")),
    }
}

pub(in crate::ui::city) fn render_warehouse(
    view: &WarehouseUi,
    session: &GameSession,
    ui: &mut CityUi,
) {
    let city = &session
        .game
        .nations()
        .major(session.active_major_nation())
        .city;
    for &(entity, resource) in &view.stocks {
        let value = if resource == ResourceKind::Livestock {
            city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
        } else {
            city.stockpile[resource]
        };
        ui.text(entity, value.to_string());
    }
    ui.text(view.labor, city.population.strength().to_string());
    ui.text(view.power, city.power_available.to_string());
}

pub(in crate::ui::city) fn render_food(
    view: &FoodUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    render_rail(session, nation, CityOrderId::FoodProcessing, &view.rail, ui);
    ui.visible(view.labor, city.population.strength() >= 2);
    ui.visible(view.grain, city.stockpile[ResourceKind::Grain] >= 2);
    ui.visible(view.fruit, city.stockpile[ResourceKind::Fruit] >= 1);
    ui.visible(
        view.fish_and_livestock,
        city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock] >= 1,
    );
}

pub(in crate::ui::city) fn render_power(
    view: &RailUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    render_rail(session, nation, CityOrderId::PowerPlant, view, ui);
}

pub(in crate::ui::city) fn render_transport(
    view: &TransportUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    render_rail(
        session,
        nation,
        CityOrderId::TransportCapacity,
        &view.rail,
        ui,
    );
    ui.visible(view.labor, city.population.strength() >= 2);
    ui.visible(view.lumber, city.stockpile[ResourceKind::Lumber] < 1);
    ui.visible(view.steel, city.stockpile[ResourceKind::Steel] < 1);
}

pub(in crate::ui::city) fn render_population(
    view: &PopulationUi,
    session: &GameSession,
    nation: MajorNationId,
    assets: &RetailUiAssets,
    ui: &mut CityUi,
) {
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let capacity_template = city_text(assets, 0x10);
    let province_template = city_text(assets, 0x1d);
    render_rail(
        session,
        nation,
        CityOrderId::PopulationGrowth,
        &view.rail,
        ui,
    );
    ui.visible(view.food, city.stockpile[ResourceKind::Food] >= 1);
    ui.visible(view.clothing, city.stockpile[ResourceKind::Clothing] >= 1);
    ui.visible(view.furniture, city.stockpile[ResourceKind::Furniture] >= 1);
    let owned_regions = major.common.owned_region_count();
    let building = city.building_type(
        CityFacilitySlot::RegionalPopulation,
        &major.economy,
        owned_regions,
    );
    ui.text(
        view.capacity,
        format_retail_number(&capacity_template, building),
    );
    ui.text(
        view.provinces,
        format_retail_number(&province_template, owned_regions as i16),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::advanced_production_game;
    use crate::ui::window::UiWindowPlugin;
    use crate::ui::RetailUiPlugin;
    use crate::RetailAssetsResource;
    use bevy::asset::AssetPlugin;
    use bevy::ecs::system::SystemState;
    use bevy::scene::ScenePlugin;
    use std::path::PathBuf;

    fn warehouse_test_app() -> App {
        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            RetailUiPlugin,
            UiWindowPlugin,
        ));
        app
    }

    #[derive(Resource)]
    struct WarehouseBindRequest {
        root: Entity,
        state: GameState,
    }

    fn bind_warehouse_for_test(
        mut commands: Commands,
        request: Res<WarehouseBindRequest>,
        tree: RetailTree,
        mut assets: RetailUiAssets,
    ) {
        bind_warehouse(
            &mut commands,
            &mut assets,
            request.root,
            &tree,
            &request.state,
        );
    }

    #[test]
    fn generated_warehouse_is_a_captioned_wind_root() {
        let generated = include_str!("../../generated.rs");
        let scene = generated
            .split("pub fn citydlog_9213()")
            .nth(1)
            .expect("generated warehouse scene");
        let end = scene
            .find("\npub fn ")
            .expect("generated warehouse scene terminator");
        assert!(
            !scene[..end].contains("retail_view("),
            "warehouse must bind to the recovered WIND root"
        );
        assert!(scene[..end].contains("captioned_window(bsn_list!["));
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at a retail Imperialism install"]
    fn bind_warehouse_advanced_layout_resizes_the_captioned_root() {
        use crate::ui::generated;

        let retail_dir = std::env::var("IMPERIALISM_RETAIL_DIR")
            .expect("set IMPERIALISM_RETAIL_DIR for this integration test");
        let retail_assets =
            RetailAssets::open(PathBuf::from(retail_dir)).expect("open retail assets");

        let state = advanced_production_game();
        assert!(state.technology().advanced_production_unlocked());

        let mut app = warehouse_test_app();
        app.insert_resource(RetailAssetsResource::new(retail_assets));
        let root = app
            .world_mut()
            .spawn_scene(generated::citydlog_9213())
            .expect("warehouse scene")
            .id();
        app.insert_resource(WarehouseBindRequest { root, state })
            .add_systems(Update, bind_warehouse_for_test);
        app.update();

        let mut tree_state = SystemState::<RetailTree>::new(app.world_mut());
        let tree = tree_state.get(app.world()).expect("RetailTree");
        let dialog = tree.find(root, fourcc!("DLOG"));
        let hors = tree.find(root, fourcc!("hors"));
        tree_state.apply(app.world_mut());
        assert_eq!(app.world().get::<Node>(root).unwrap().height, px(335));
        assert_eq!(app.world().get::<Node>(dialog).unwrap().height, px(335));
        assert_eq!(app.world().get::<Node>(hors).unwrap().top, px(455.0));
    }
}
