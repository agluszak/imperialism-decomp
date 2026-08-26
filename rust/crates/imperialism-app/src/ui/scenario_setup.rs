use super::generated;
use super::retail::{RetailTree, retail_text_style};
use super::satellite_preview::SatellitePreview;
use super::session::{apply_turn_stop, insert_game_session};
use crate::{AppState, RetailAssetsResource};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{
    MajorNationId, MapMgr, ScenarioInstruction, create_scenario_game,
    enter_strategic_map_without_capital_selection,
};
use imperialism_formats::{ScenarioInfo, fourcc};

#[derive(Component)]
struct ScenarioSetupRoot;

#[derive(Component, Clone, Copy)]
struct SelectScenario(usize);

#[derive(Component)]
struct ScenarioDescription;

#[derive(Component)]
struct NationDescription;

#[derive(Component, Default)]
struct ScenarioMapPreview {
    preview: SatellitePreview,
    rendered_selection: Option<(usize, MajorNationId)>,
}

#[derive(Component)]
struct StartScenario;

struct ScenarioChoice {
    info: ScenarioInfo,
    map: MapMgr,
    instructions: Vec<ScenarioInstruction>,
}

#[derive(Resource)]
struct ScenarioSetup {
    choices: Vec<ScenarioChoice>,
    selected: usize,
    nation: MajorNationId,
}

pub(crate) struct ScenarioSetupPlugin;

impl Plugin for ScenarioSetupPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::ScenarioSetup),
            (load_scenarios, enter_scenario_setup, bind_scenario_setup).chain(),
        )
        .add_systems(
            Update,
            project_scenario_setup.run_if(in_state(AppState::ScenarioSetup)),
        )
        .add_systems(OnExit(AppState::ScenarioSetup), drop_scenarios);
    }
}

fn load_scenarios(world: &mut World) {
    let assets = world.resource::<RetailAssetsResource>().assets();
    let choices = assets
        .single_player_scenarios()
        .expect("installed scenario metadata")
        .into_iter()
        .map(|info| ScenarioChoice {
            map: assets
                .scenario_map(info.scenario)
                .expect("installed scenario map"),
            instructions: assets
                .scenario_script(info.scenario)
                .expect("installed scenario script"),
            info,
        })
        .collect::<Vec<_>>();
    assert!(
        !choices.is_empty(),
        "retail installation has no single-player scenarios"
    );
    let nation = choices[0].info.preview_nation;
    world.insert_resource(ScenarioSetup {
        choices,
        selected: 0,
        nation,
    });
}

fn enter_scenario_setup(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1503()).id();
    commands
        .entity(root)
        .insert((ScenarioSetupRoot, DespawnOnExit(AppState::ScenarioSetup)));
}

fn bind_scenario_setup(
    mut commands: Commands,
    root: Single<Entity, Added<ScenarioSetupRoot>>,
    tree: RetailTree,
    setup: Res<ScenarioSetup>,
) {
    let root = *root;
    let list = tree.find(root, fourcc!("list"));
    for (index, choice) in setup.choices.iter().enumerate() {
        let row = commands
            .spawn_scene(scenario_row(choice.info.title.clone(), index))
            .id();
        commands.entity(row).observe(on_select_scenario);
        commands.entity(list).add_child(row);
    }

    commands
        .entity(tree.find(root, fourcc!("sdes")))
        .insert((Text::default(), ScenarioDescription));
    commands
        .entity(tree.find(root, fourcc!("cdes")))
        .insert((Text::default(), NationDescription));
    commands
        .entity(tree.find(root, fourcc!("pmap")))
        .insert((
            ScenarioMapPreview::default(),
            RelativeCursorPosition::default(),
        ))
        .remove::<InteractionDisabled>()
        .observe(on_map_click);
    commands
        .entity(tree.find(root, fourcc!("star")))
        .insert((StartScenario, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_start_scenario);
    commands
        .entity(tree.find(root, fourcc!("exit")))
        .insert(ActivateOnPress)
        .observe(on_exit_scenario_setup);
}

fn scenario_row(title: String, index: usize) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0), top: px(index as i32 * 16), width: percent(100), height: px(16),
        }
        Button
        ActivateOnPress
        template(move |_context| Ok(SelectScenario(index)))
        template(move |_context| Ok(Text::new(title.clone())))
        retail_text_style(1, 0, 12, -2)
        TextColor(Color::BLACK)
    }
}

fn on_select_scenario(
    activate: On<Activate>,
    rows: Query<&SelectScenario>,
    mut setup: ResMut<ScenarioSetup>,
) {
    let Ok(row) = rows.get(activate.entity) else {
        return;
    };
    setup.selected = row.0;
    setup.nation = setup.choices[row.0].info.preview_nation;
}

fn on_map_click(
    click: On<Pointer<Click>>,
    maps: Query<(&RelativeCursorPosition, &ScenarioMapPreview)>,
    mut setup: ResMut<ScenarioSetup>,
) {
    let Ok((cursor, map)) = maps.get(click.entity) else {
        return;
    };
    let Some(position) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    let Some(nation) = map.preview.major_nation_at(position) else {
        return;
    };
    if setup.choices[setup.selected].info.difficulty_by_nation[nation].is_some() {
        setup.nation = nation;
    }
}

fn project_scenario_setup(
    setup: Res<ScenarioSetup>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut descriptions: Query<&mut Text, With<ScenarioDescription>>,
    mut nation_descriptions: Query<
        &mut Text,
        (With<NationDescription>, Without<ScenarioDescription>),
    >,
    mut maps: Query<(Entity, &mut ScenarioMapPreview, Option<&mut ImageNode>)>,
    mut commands: Commands,
) {
    if !setup.is_changed() {
        return;
    }
    let choice = &setup.choices[setup.selected];
    for mut text in &mut descriptions {
        **text = choice.info.description.clone();
    }
    for mut text in &mut nation_descriptions {
        **text = choice.info.nation_descriptions[setup.nation].clone();
    }
    for (entity, mut map, image_node) in &mut maps {
        let mut preview = SatellitePreview::compose(|tile| choice.map[tile].owner_nation);
        preview.enhance(setup.nation.nation());
        let image = preview.to_image(retail.assets().default_dib_palette());
        if let Some(mut image_node) = image_node {
            image_node.image = images.add(image);
        } else {
            commands
                .entity(entity)
                .insert(ImageNode::new(images.add(image)));
        }
        map.preview = preview;
        map.rendered_selection = Some((setup.selected, setup.nation));
    }
}

fn on_start_scenario(
    activate: On<Activate>,
    starts: Query<(), With<StartScenario>>,
    setup: Res<ScenarioSetup>,
    retail: Res<RetailAssetsResource>,
    mut commands: Commands,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if starts.get(activate.entity).is_err() {
        return;
    }
    let choice = &setup.choices[setup.selected];
    let difficulty = choice.info.difficulty_by_nation[setup.nation]
        .expect("scenario chooser only permits available nations");
    let mut game = create_scenario_game(
        choice.map.clone(),
        choice.info.scenario,
        &choice.instructions,
        setup.nation,
        difficulty,
        1,
    );
    game.set_game_data(super::session::retail_game_data(&retail));
    let stop = enter_strategic_map_without_capital_selection(&mut game, setup.nation);
    apply_turn_stop(stop, &mut next_state);
    insert_game_session(&mut commands, game);
}

fn on_exit_scenario_setup(_activate: On<Activate>, mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::MainMenu);
}

fn drop_scenarios(mut commands: Commands) {
    commands.remove_resource::<ScenarioSetup>();
}
