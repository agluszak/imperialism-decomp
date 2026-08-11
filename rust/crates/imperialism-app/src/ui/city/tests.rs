use super::*;
use crate::ui::catalog::spawn_view_nodes;
use bevy::ecs::system::RunSystemOnce;

const CATALOG_JSON: &str = include_str!("../../../../imperialism-formats/assets/ui_catalog.json");
const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

#[derive(Clone, Copy)]
struct TestDialog {
    root: Entity,
    window: Entity,
    decrease: Entity,
    increase: Entity,
    quantity: Entity,
    fabric: Entity,
    labor: Entity,
    capacity: Entity,
    expansion: Entity,
}

#[derive(Clone, Copy)]
struct TestTrainingDialog {
    root: Entity,
    medium_decrease: Entity,
    medium_increase: Entity,
    medium_quantity: Entity,
    high_decrease: Entity,
    high_increase: Entity,
    high_quantity: Entity,
}

#[derive(Clone, Copy)]
struct TestUniversityDialog {
    root: Entity,
    miner_button: Entity,
    forester_button: Entity,
    forester_increase: Entity,
    forester_decrease: Entity,
    forester_quantity: Entity,
    engineer_button: Entity,
    engineer_increase: Entity,
    engineer_quantity: Entity,
    driller_button: Entity,
    driller_increase: Entity,
}

fn fixture_session() -> GameSession {
    let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
    let state = save.game_state(LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
        selected_nation: NationId::new(6),
    });
    GameSession(state)
}

fn spawn_clothing_dialog(mut commands: Commands, catalog: Res<UiCatalogResource>) -> TestDialog {
    let city = catalog.required_view(&city_view_id());
    let view_id = city
        .city_buildings
        .iter()
        .find(|building| building.slot == CityFacilitySlot::ClothingFactory)
        .unwrap()
        .dialog
        .clone();
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
    let page = industry_page(CityFacilitySlot::ClothingFactory).unwrap();
    bind_industry_dialog(
        &mut commands,
        &catalog,
        &spawned,
        MajorNationId::new(6),
        page,
        "Clothing Factory".to_owned(),
        "Capacity: [1: number]".to_owned(),
        Color::WHITE,
    );
    TestDialog {
        root: spawned.root,
        window: spawned.unique(fourcc!("WIND")),
        decrease: spawned.under(&catalog, fourcc!("clot"), fourcc!("left")),
        increase: spawned.under(&catalog, fourcc!("clot"), fourcc!("rght")),
        quantity: spawned.under(&catalog, fourcc!("clot"), fourcc!("move")),
        fabric: spawned.unique(fourcc!("fabr")),
        labor: spawned.unique(fourcc!("labV")),
        capacity: spawned.unique(fourcc!("capT")),
        expansion: spawned.unique(fourcc!("flag")),
    }
}

fn spawn_training_dialog(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
) -> TestTrainingDialog {
    let city = catalog.required_view(&city_view_id());
    let view_id = city
        .city_buildings
        .iter()
        .find(|building| building.slot == CityFacilitySlot::TradeSchool)
        .unwrap()
        .dialog
        .clone();
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
    bind_training_dialog(
        &mut commands,
        &catalog,
        &spawned,
        MajorNationId::new(6),
        "Trade School".to_owned(),
    );
    TestTrainingDialog {
        root: spawned.root,
        medium_decrease: spawned.under(&catalog, fourcc!("trai"), fourcc!("left")),
        medium_increase: spawned.under(&catalog, fourcc!("trai"), fourcc!("rght")),
        medium_quantity: spawned.under(&catalog, fourcc!("trai"), fourcc!("move")),
        high_decrease: spawned.under(&catalog, fourcc!("prof"), fourcc!("left")),
        high_increase: spawned.under(&catalog, fourcc!("prof"), fourcc!("rght")),
        high_quantity: spawned.under(&catalog, fourcc!("prof"), fourcc!("move")),
    }
}

fn spawn_university_dialog(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    session: Res<GameSession>,
) -> TestUniversityDialog {
    let city = catalog.required_view(&city_view_id());
    let view_id = city
        .city_buildings
        .iter()
        .find(|building| building.slot == CityFacilitySlot::University)
        .unwrap()
        .dialog
        .clone();
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
    let technology =
        session.0.technology().city_capabilities_by_nation[MajorNationId::new(6)].university;
    bind_university_dialog(
        &mut commands,
        &catalog,
        &spawned,
        MajorNationId::new(6),
        UniversityDialogData {
            available: technology.available,
            rows: UNIVERSITY_ORDERS.map(|binding| {
                let CityOrderId::CivilianRecruit(kind) = binding.order else {
                    unreachable!("University binding has a civilian recruitment order");
                };
                UniversityRowText {
                    unit_name: format!("{kind:?}"),
                    description: format!("{kind:?} description"),
                    preview: Handle::default(),
                }
            }),
            resource_icons: Handle::default(),
            tier_labels: std::array::from_fn(|level| format!("Level {}", level + 1)),
            title_font: TextFont::default(),
            unit_font: TextFont::default(),
            detail_font: TextFont::default(),
            normal_color: Color::WHITE,
            warning_color: Color::BLACK,
        },
    );
    TestUniversityDialog {
        root: spawned.root,
        miner_button: spawned.unique(fourcc!("civ0")),
        forester_button: spawned.unique(fourcc!("civ3")),
        forester_increase: spawned.under(&catalog, fourcc!("clu3"), fourcc!("plus")),
        forester_decrease: spawned.under(&catalog, fourcc!("clu3"), fourcc!("minu")),
        forester_quantity: spawned.under(&catalog, fourcc!("clu3"), fourcc!("numb")),
        engineer_button: spawned.unique(fourcc!("civ4")),
        engineer_increase: spawned.under(&catalog, fourcc!("clu4"), fourcc!("plus")),
        engineer_quantity: spawned.under(&catalog, fourcc!("clu4"), fourcc!("numb")),
        driller_button: spawned.unique(fourcc!("civ8")),
        driller_increase: spawned.under(&catalog, fourcc!("clu8"), fourcc!("plus")),
    }
}

fn order_quantity(app: &mut App, order: CityOrderId) -> i16 {
    app.world_mut()
        .resource_mut::<GameSession>()
        .0
        .refresh_city_order(MajorNationId::new(6), order)
        .quantity
}

fn activate(app: &mut App, entity: Entity) {
    app.world_mut().commands().trigger(Activate { entity });
    app.world_mut().flush();
    app.update();
}

#[test]
fn clothing_order_round_trips_through_generated_controls_and_reopen() {
    let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
    let mut app = App::new();
    app.add_plugins(MinimalPlugins)
        .insert_resource(UiCatalogResource::new(catalog))
        .insert_resource(fixture_session())
        .add_observer(on_city_order_adjust)
        .add_systems(Update, sync_city_values);

    let first = app
        .world_mut()
        .run_system_once(spawn_clothing_dialog)
        .unwrap();
    app.update();
    assert_eq!(
        order_quantity(&mut app, CityOrderId::Item(ManufacturedItem::Clothing)),
        0
    );
    assert_eq!(
        *app.world().get::<Visibility>(first.fabric).unwrap(),
        Visibility::Hidden
    );
    assert_eq!(
        *app.world().get::<Visibility>(first.labor).unwrap(),
        Visibility::Visible
    );
    assert_eq!(
        app.world().get::<Text>(first.capacity).unwrap().0,
        "Capacity: 1"
    );
    assert_eq!(
        *app.world().get::<Visibility>(first.expansion).unwrap(),
        Visibility::Hidden
    );
    activate(&mut app, first.increase);
    assert_eq!(
        order_quantity(&mut app, CityOrderId::Item(ManufacturedItem::Clothing)),
        1
    );
    assert_eq!(app.world().get::<Text>(first.quantity).unwrap().0, "1");
    assert_eq!(
        *app.world().get::<Visibility>(first.fabric).unwrap(),
        Visibility::Hidden
    );
    {
        let session = app.world().resource::<GameSession>();
        let city = &session.0.nations().major(MajorNationId::new(6)).city;
        assert_eq!(city.stockpile[ResourceKind::Fabric], 8);
        assert_eq!(city.population.strength(), 10);
        assert_eq!(city.production_accum[CityFacilitySlot::ClothingFactory], 0);
    }

    app.world_mut().commands().entity(first.root).despawn();
    app.world_mut().flush();
    let reopened = app
        .world_mut()
        .run_system_once(spawn_clothing_dialog)
        .unwrap();
    app.update();
    assert_eq!(app.world().get::<Text>(reopened.quantity).unwrap().0, "1");

    activate(&mut app, reopened.decrease);
    assert_eq!(
        order_quantity(&mut app, CityOrderId::Item(ManufacturedItem::Clothing)),
        0
    );
    assert_eq!(app.world().get::<Text>(reopened.quantity).unwrap().0, "0");
    assert_eq!(
        *app.world().get::<Visibility>(reopened.fabric).unwrap(),
        Visibility::Hidden
    );
    {
        let session = app.world().resource::<GameSession>();
        let city = &session.0.nations().major(MajorNationId::new(6)).city;
        assert_eq!(city.stockpile[ResourceKind::Fabric], 10);
        assert_eq!(city.population.strength(), 12);
        assert_eq!(city.production_accum[CityFacilitySlot::ClothingFactory], 1);
    }

    {
        let mut window = app.world_mut().get_mut::<Node>(reopened.window).unwrap();
        window.left = px(123);
        window.top = px(87);
    }
    app.world_mut().run_system_once(leave_city_screen).unwrap();
    app.world_mut().flush();
    assert_eq!(
        app.world()
            .resource::<GameSession>()
            .0
            .nations()
            .major(MajorNationId::new(6))
            .city
            .building_window_state(CityFacilitySlot::ClothingFactory),
        BuildingWindowState {
            flag: 1,
            current: 123,
            accumulated: 87,
        }
    );
}

#[test]
fn training_orders_round_trip_through_both_generated_rows() {
    let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
    let mut app = App::new();
    app.add_plugins(MinimalPlugins)
        .insert_resource(UiCatalogResource::new(catalog))
        .insert_resource(fixture_session())
        .add_observer(on_city_order_adjust)
        .add_systems(Update, sync_city_values);

    let first = app
        .world_mut()
        .run_system_once(spawn_training_dialog)
        .unwrap();
    app.update();
    activate(&mut app, first.medium_increase);
    activate(&mut app, first.high_increase);
    assert_eq!(
        app.world().get::<Text>(first.medium_quantity).unwrap().0,
        "1"
    );
    assert_eq!(app.world().get::<Text>(first.high_quantity).unwrap().0, "1");
    {
        let session = app.world().resource::<GameSession>();
        let major = session.0.nations().major(MajorNationId::new(6));
        let city = &major.city;
        assert_eq!(city.stockpile[ResourceKind::Paper], 5);
        assert_eq!(major.common.treasury, 8_900);
        assert_eq!(city.population.production_labor(), LaborPool::new(3, 1, 1));
        assert_eq!(city.population.strength(), 9);
    }

    app.world_mut().commands().entity(first.root).despawn();
    app.world_mut().flush();
    let reopened = app
        .world_mut()
        .run_system_once(spawn_training_dialog)
        .unwrap();
    app.update();
    assert_eq!(
        app.world().get::<Text>(reopened.medium_quantity).unwrap().0,
        "1"
    );
    assert_eq!(
        app.world().get::<Text>(reopened.high_quantity).unwrap().0,
        "1"
    );

    activate(&mut app, reopened.medium_decrease);
    activate(&mut app, reopened.high_decrease);
    {
        let session = app.world().resource::<GameSession>();
        let major = session.0.nations().major(MajorNationId::new(6));
        let city = &major.city;
        assert_eq!(city.stockpile[ResourceKind::Paper], 8);
        assert_eq!(major.common.treasury, 10_000);
        assert_eq!(city.population.production_labor(), LaborPool::new(4, 2, 1));
        assert_eq!(city.population.strength(), 12);
    }
}

#[test]
fn university_availability_and_orders_round_trip_through_generated_rows() {
    let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
    let nation = MajorNationId::new(6);
    let mut session = fixture_session();
    session
        .0
        .set_university_civilian_available(nation, CivilianUnitKind::Forester, true);
    session
        .0
        .set_university_civilian_available(nation, CivilianUnitKind::Engineer, true);
    session
        .0
        .set_university_civilian_available(nation, CivilianUnitKind::Driller, false);

    let mut app = App::new();
    app.add_plugins(MinimalPlugins)
        .insert_resource(UiCatalogResource::new(catalog))
        .insert_resource(session)
        .add_observer(on_city_order_adjust)
        .add_observer(on_university_row_selected)
        .add_systems(Update, sync_city_values);

    let first = app
        .world_mut()
        .run_system_once(spawn_university_dialog)
        .unwrap();
    app.update();
    assert_eq!(
        *app.world()
            .get::<Visibility>(first.forester_button)
            .unwrap(),
        Visibility::Visible
    );
    assert!(
        app.world()
            .get::<InteractionDisabled>(first.forester_increase)
            .is_none()
    );
    assert_eq!(
        *app.world().get::<Visibility>(first.driller_button).unwrap(),
        Visibility::Hidden
    );
    assert!(
        app.world()
            .get::<InteractionDisabled>(first.driller_increase)
            .is_some()
    );
    assert!(app.world().get::<Checked>(first.miner_button).is_some());

    activate(&mut app, first.forester_increase);
    assert_eq!(
        app.world()
            .get::<UniversitySelection>(first.root)
            .unwrap()
            .kind,
        CivilianUnitKind::Forester
    );
    assert!(app.world().get::<Checked>(first.forester_button).is_some());
    assert_eq!(
        app.world().get::<Text>(first.forester_quantity).unwrap().0,
        "1"
    );
    assert_eq!(
        app.world()
            .resource::<GameSession>()
            .0
            .nations()
            .major(nation)
            .city
            .orders
            .civilian_recruitment[CivilianUnitKind::Forester]
            .quantity,
        1
    );

    activate(&mut app, first.engineer_increase);
    assert_eq!(
        app.world()
            .get::<UniversitySelection>(first.root)
            .unwrap()
            .kind,
        CivilianUnitKind::Engineer,
        "a rejected adjustment still selects its University row"
    );
    assert!(app.world().get::<Checked>(first.engineer_button).is_some());
    assert!(app.world().get::<Checked>(first.forester_button).is_none());
    assert_eq!(
        app.world().get::<Text>(first.engineer_quantity).unwrap().0,
        "0"
    );

    activate(&mut app, first.forester_decrease);
    assert_eq!(
        app.world()
            .get::<UniversitySelection>(first.root)
            .unwrap()
            .kind,
        CivilianUnitKind::Forester
    );
    assert_eq!(
        app.world().get::<Text>(first.forester_quantity).unwrap().0,
        "0"
    );
}
