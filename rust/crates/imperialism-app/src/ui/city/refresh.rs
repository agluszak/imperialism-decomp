use super::*;
use bevy::ecs::system::SystemParam;

#[derive(SystemParam)]
pub(in crate::ui::city) struct CityDialogs<'w, 's> {
    industry: Query<'w, 's, &'static IndustryDialogUi>,
    training: Query<'w, 's, &'static TrainingDialogUi>,
    armory: Query<'w, 's, (&'static ArmoryDialogUi, &'static CityRowSelection)>,
    university: Query<'w, 's, (&'static UniversityDialogUi, &'static CityRowSelection)>,
    shipyard: Query<'w, 's, (&'static ShipyardDialogUi, &'static CityRowSelection)>,
    warehouse: Query<'w, 's, &'static WarehouseDialogUi>,
    food: Query<'w, 's, &'static FoodDialogUi>,
    power: Query<'w, 's, &'static PowerDialogUi>,
    transport: Query<'w, 's, &'static TransportCapacityDialogUi>,
    population: Query<'w, 's, &'static PopulationDialogUi>,
}

#[derive(SystemParam)]
pub(in crate::ui::city) struct CityUiNodes<'w, 's> {
    texts: Query<'w, 's, &'static mut Text>,
    colors: Query<'w, 's, &'static mut TextColor>,
    visibilities: Query<'w, 's, &'static mut Visibility>,
    nodes: Query<'w, 's, &'static mut Node>,
    images: Query<'w, 's, &'static mut ImageNode>,
    sprites: Query<'w, 's, &'static mut CityBuildingSprite>,
    actions: Query<'w, 's, &'static CityBuildingActionAnimation>,
    university_visuals: Query<'w, 's, &'static UniversityDetailsVisual>,
    shipyard_visuals: Query<'w, 's, &'static ShipyardDetailsVisual>,
}

pub(in crate::ui::city) fn refresh_city_ui(
    mut commands: Commands,
    dirty: Query<Entity, With<CityUiDirty>>,
    session: Res<GameSession>,
    screens: Query<&CityScreenUi>,
    dialogs: CityDialogs,
    selections: Query<&CityRowSelection>,
    rows: Query<(Entity, &CityRowChoice, Has<Checked>)>,
    mut nodes: CityUiNodes,
    mut assets: RetailUiAssets,
    font_assets: Res<Assets<Font>>,
) {
    let Ok(root) = dirty.single() else {
        return;
    };
    commands.entity(root).remove::<CityUiDirty>();
    let nation = session.active_major_nation();
    let game = &session.game;
    if let Ok(ui) = screens.single() {
        refresh_city_summary(game, nation, ui, &mut nodes.texts, &mut nodes.visibilities);
        refresh_city_buildings(
            game,
            nation,
            ui,
            &mut assets,
            &mut nodes.sprites,
            &mut nodes.images,
            &mut nodes.visibilities,
        );
        refresh_city_building_actions(
            &game.nations().major(nation).city,
            ui,
            &nodes.actions,
            &mut nodes.visibilities,
        );
    }
    refresh_city_row_selection(&mut commands, &selections, &rows);
    for ui in &dialogs.industry {
        refresh_industry_dialog(
            game,
            nation,
            ui,
            &mut nodes.texts,
            &mut nodes.visibilities,
            &mut nodes.nodes,
            &mut nodes.images,
            &mut assets,
        );
    }
    for ui in &dialogs.training {
        refresh_training_dialog(game, nation, ui, &mut nodes.texts, &mut nodes.visibilities);
    }
    for (ui, selection) in &dialogs.armory {
        refresh_armory_dialog(
            game,
            nation,
            ui,
            selection,
            &mut assets,
            &mut nodes.texts,
            &mut nodes.colors,
            &mut nodes.visibilities,
            &mut nodes.images,
        );
    }
    for (ui, selection) in &dialogs.university {
        refresh_university_dialog(
            game,
            nation,
            ui,
            selection,
            &mut assets,
            &font_assets,
            &mut nodes.texts,
            &mut nodes.colors,
            &mut nodes.visibilities,
            &mut nodes.images,
            &nodes.university_visuals,
        );
    }
    for (ui, selection) in &dialogs.shipyard {
        refresh_shipyard_dialog(
            game,
            nation,
            ui,
            selection,
            &mut assets,
            &font_assets,
            &mut nodes.texts,
            &mut nodes.images,
            &nodes.shipyard_visuals,
        );
    }
    for ui in &dialogs.warehouse {
        refresh_warehouse_dialog(game, nation, ui, &mut nodes.texts);
    }
    for ui in &dialogs.food {
        refresh_food_dialog(
            game,
            nation,
            ui,
            &mut nodes.texts,
            &mut nodes.visibilities,
            &mut nodes.nodes,
            &mut nodes.images,
            &mut assets,
        );
    }
    for ui in &dialogs.power {
        refresh_power_dialog(
            game,
            nation,
            ui,
            &mut nodes.texts,
            &mut nodes.nodes,
            &mut nodes.images,
            &mut assets,
        );
    }
    for ui in &dialogs.transport {
        refresh_transport_capacity_dialog(
            game,
            nation,
            ui,
            &mut nodes.texts,
            &mut nodes.visibilities,
            &mut nodes.nodes,
            &mut nodes.images,
            &mut assets,
        );
    }
    for ui in &dialogs.population {
        refresh_population_dialog(
            game,
            nation,
            ui,
            &mut nodes.texts,
            &mut nodes.visibilities,
            &mut nodes.nodes,
            &mut nodes.images,
            &mut assets,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game;

    fn spawn_placard(world: &mut World) -> CityPlacard {
        let icon = world.spawn(Visibility::Inherited).id();
        let text = world.spawn((Text::new(""), Visibility::Inherited)).id();
        CityPlacard { text, icon }
    }

    fn spawn_screen(world: &mut World) -> (Entity, CityPlacard) {
        let labor_low = spawn_placard(world);
        let ui = CityScreenUi {
            labor_low,
            labor_medium: spawn_placard(world),
            labor_high: spawn_placard(world),
            population: spawn_placard(world),
            power: spawn_placard(world),
            grain: spawn_placard(world),
            fruit: spawn_placard(world),
            livestock: spawn_placard(world),
            hardware: spawn_placard(world),
            clothing: spawn_placard(world),
            furniture: spawn_placard(world),
            treasury: world.spawn(Text::new("")).id(),
            buildings: Vec::new(),
            actions: Vec::new(),
        };
        let expected = labor_low;
        let root = world.spawn((CityScreenRoot, ui, CityUiDirty)).id();
        (root, expected)
    }

    fn refresh_summary_if_dirty(
        mut commands: Commands,
        dirty: Query<Entity, With<CityUiDirty>>,
        session: Res<GameSession>,
        screens: Query<&CityScreenUi>,
        mut texts: Query<&mut Text>,
        mut visibilities: Query<&mut Visibility>,
    ) {
        let Ok(root) = dirty.single() else {
            return;
        };
        commands.entity(root).remove::<CityUiDirty>();
        let Ok(ui) = screens.single() else {
            return;
        };
        refresh_city_summary(
            &session.game,
            session.active_major_nation(),
            ui,
            &mut texts,
            &mut visibilities,
        );
    }

    #[test]
    fn city_ui_refresh_writes_bound_summary_only_when_dirty() {
        let game = beginning_of_game();
        let nation = MajorNationId::from_nation(game.turn().active_nation).unwrap();
        let expected = game
            .nations()
            .major(nation)
            .city
            .population
            .baseline_labor()
            .low
            .to_string();

        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(GameSession::new(game))
            .add_systems(Update, refresh_summary_if_dirty);
        let (root, labor_low) = spawn_screen(app.world_mut());
        app.update();

        assert!(app.world().entity(root).get::<CityUiDirty>().is_none());
        assert_eq!(app.world().get::<Text>(labor_low.text).unwrap().0, expected);

        app.world_mut().get_mut::<Text>(labor_low.text).unwrap().0 = "STALE".into();
        let _ = app.world_mut().resource_mut::<GameSession>();
        app.update();
        assert_eq!(app.world().get::<Text>(labor_low.text).unwrap().0, "STALE");

        app.world_mut().entity_mut(root).insert(CityUiDirty);
        app.update();
        assert!(app.world().entity(root).get::<CityUiDirty>().is_none());
        assert_eq!(app.world().get::<Text>(labor_low.text).unwrap().0, expected);
    }
}
