use super::generated;
use super::hover_help::{HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, ui_string};
use super::retail::{RetailTree, RetailUiAssets};
use super::satellite_preview::SatellitePreview;
use super::session::GameSession;
use crate::{AppState, RetailAssetsResource};
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{MajorNationId, ScenarioGameInput, create_scenario_game};
use imperialism_formats::{RetailTextStylePreset, ScenarioCatalogEntry, fourcc};
use std::time::{SystemTime, UNIX_EPOCH};

const VISIBLE_ROWS: usize = 7;

#[derive(Component)]
struct ScenarioRoot;

#[derive(Component, Clone, Copy)]
enum ScenarioAction {
    Select(usize),
    Start,
    Exit,
    More,
}

#[derive(Component)]
struct ScenarioRow(usize);

#[derive(Component, Default)]
struct ScenarioMapPreview(SatellitePreview);

#[derive(Resource)]
struct ScenarioSetup {
    catalog: Vec<ScenarioCatalogEntry>,
    selected: Option<usize>,
    nation: MajorNationId,
    page: usize,
    game: Option<ScenarioGameInput>,
}

pub(crate) struct ScenarioPlugin;

impl Plugin for ScenarioPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Scenario),
            (enter_scenario, bind_scenario).chain(),
        )
        .add_systems(
            Update,
            project_scenario.run_if(in_state(AppState::Scenario)),
        )
        .add_systems(OnExit(AppState::Scenario), cleanup_scenario);
    }
}

fn enter_scenario(mut commands: Commands, retail: Res<RetailAssetsResource>) {
    let catalog = retail
        .assets()
        .scenario_catalog()
        .expect("retail scenario catalog");
    let nation = catalog
        .first()
        .map(|entry| entry.metadata.preview_nation)
        .unwrap_or(MajorNationId::new(0));
    commands.insert_resource(ScenarioSetup {
        catalog,
        selected: None,
        nation,
        page: 0,
        game: None,
    });
    let root = commands.spawn_scene(generated::startup_1503()).id();
    commands
        .entity(root)
        .insert((ScenarioRoot, DespawnOnExit(AppState::Scenario)));
}

fn bind_scenario(
    mut commands: Commands,
    root: Single<Entity, Added<ScenarioRoot>>,
    tree: RetailTree,
    setup: Res<ScenarioSetup>,
    mut assets: RetailUiAssets,
    mut nodes: Query<&mut Node>,
) {
    let root = *root;
    let list = tree.find(root, fourcc!("list"));
    let mut list_node = nodes.get_mut(list).expect("scenario list has Node");
    list_node.flex_direction = FlexDirection::Column;
    list_node.overflow = Overflow::clip();
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail scenario list style");
    for (index, entry) in setup.catalog.iter().enumerate() {
        commands
            .spawn((
                ScenarioRow(index),
                ScenarioAction::Select(index),
                ActivateOnPress,
                Button,
                Node {
                    width: Val::Percent(100.0),
                    height: Val::Px(15.0),
                    padding: UiRect::horizontal(Val::Px(2.0)),
                    ..default()
                },
                Text::new(entry.metadata.title.clone()),
                font.clone(),
                layout,
                line_height,
                TextColor(Color::BLACK),
                BackgroundColor(Color::NONE),
                if index < VISIBLE_ROWS {
                    Visibility::Inherited
                } else {
                    Visibility::Hidden
                },
                ChildOf(list),
            ))
            .observe(on_scenario_activate);
    }
    commands
        .entity(tree.find(root, fourcc!("exit")))
        .insert((ScenarioAction::Exit, ActivateOnPress))
        .observe(on_scenario_activate);
    commands
        .entity(tree.find(root, fourcc!("more")))
        .insert((Button, ScenarioAction::More, ActivateOnPress))
        .observe(on_scenario_activate);
    commands
        .entity(tree.find(root, fourcc!("star")))
        .insert((ScenarioAction::Start, ActivateOnPress))
        .observe(on_scenario_activate);
    commands
        .entity(tree.find(root, fourcc!("pmap")))
        .insert(ScenarioMapPreview::default())
        .remove::<InteractionDisabled>()
        .observe(on_scenario_map_click);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail scenario description style");
    for tag in [fourcc!("sdes"), fourcc!("cdes")] {
        commands.entity(tree.find(root, tag)).insert((
            Text::new(String::new()),
            body_font.clone(),
            body_layout,
            body_line_height,
            TextColor(assets.palette_color(0x5c)),
        ));
    }
    let (heading_font, heading_layout, heading_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: 0,
        })
        .expect("retail scenario More style");
    commands.entity(tree.find(root, fourcc!("more"))).insert((
        Text::new(ui_string(&assets, 0x2758, 0x20)),
        heading_font,
        heading_layout,
        heading_line_height,
        TextColor(assets.palette_color(0x5c)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0x28),
        },
    ));
    let cursor = tree.find(root, fourcc!("curs"));
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        cursor,
        &mut nodes.get_mut(cursor).expect("scenario curs has Node"),
        HoverHelpBarStyle::RANDOM_SETUP,
    );
    bind_hover_help_texts(
        &mut commands,
        root,
        &tree,
        [
            (fourcc!("exit"), ui_string(&assets, 0x2737, 0x14)),
            (fourcc!("pmap"), ui_string(&assets, 0x2737, 0x16)),
            (fourcc!("star"), ui_string(&assets, 0x2758, 0x19)),
            (fourcc!("list"), ui_string(&assets, 0x2758, 0x1a)),
            (fourcc!("more"), ui_string(&assets, 0x2758, 0x1c)),
        ],
    );
}

fn on_scenario_activate(
    activate: On<Activate>,
    actions: Query<&ScenarioAction>,
    mut setup: ResMut<ScenarioSetup>,
    mut commands: Commands,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let action = actions
        .get(activate.entity)
        .expect("scenario Activate is bound on a scenario action");
    match *action {
        ScenarioAction::Select(index) => match setup.catalog[index].load() {
            Ok(game) => {
                setup.selected = Some(index);
                setup.nation = setup.catalog[index].metadata.preview_nation;
                setup.game = Some(game);
            }
            Err(error) => warn!("could not load retail scenario: {error}"),
        },
        ScenarioAction::Start => {
            let Some(index) = setup.selected else {
                return;
            };
            let nation = setup.nation;
            let Some(difficulty) = setup.catalog[index].metadata.difficulty_by_nation[nation]
            else {
                return;
            };
            let game = create_scenario_game(
                setup
                    .game
                    .take()
                    .expect("selected scenario has loaded state"),
                nation,
                difficulty,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32,
            );
            let mut session = GameSession::new(game);
            if let Some(home) = session.game.nations().home_tile(nation.nation()) {
                session.center_map_on(home);
            }
            commands.insert_resource(session);
            next_state.set(AppState::StrategicMap);
        }
        ScenarioAction::Exit => next_state.set(AppState::MainMenu),
        ScenarioAction::More => {
            let pages = setup.catalog.len().div_ceil(VISIBLE_ROWS).max(1);
            setup.page = (setup.page + 1) % pages;
        }
    }
}

fn on_scenario_map_click(
    click: On<Pointer<Click>>,
    maps: Query<(&RelativeCursorPosition, &ScenarioMapPreview)>,
    mut setup: ResMut<ScenarioSetup>,
) {
    let Ok((cursor, preview)) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    }
    let Some(index) = setup.selected else {
        return;
    };
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(nation) = preview.0.major_nation_at(normalized) else {
        return;
    };
    if setup.catalog[index].metadata.difficulty_by_nation[nation].is_some() {
        setup.nation = nation;
    }
}

#[allow(clippy::too_many_arguments)]
fn project_scenario(
    setup: Res<ScenarioSetup>,
    root: Single<Entity, With<ScenarioRoot>>,
    tree: RetailTree,
    retail: Res<RetailAssetsResource>,
    mut commands: Commands,
    mut images: ResMut<Assets<Image>>,
    mut previews: Query<(Entity, &mut ScenarioMapPreview, Option<&mut ImageNode>)>,
    mut texts: Query<&mut Text>,
    mut rows: Query<(&ScenarioRow, &mut Visibility, &mut BackgroundColor)>,
) {
    if !setup.is_changed() {
        return;
    }
    let first = setup.page * VISIBLE_ROWS;
    for (row, mut visibility, mut background) in &mut rows {
        *visibility = if (first..first + VISIBLE_ROWS).contains(&row.0) {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        background.0 = if setup.selected == Some(row.0) {
            Color::srgba(1.0, 1.0, 1.0, 0.35)
        } else {
            Color::NONE
        };
    }
    let root = *root;
    let start = tree.find(root, fourcc!("star"));
    if let Some(index) = setup.selected {
        commands.entity(start).remove::<InteractionDisabled>();
        let metadata = &setup.catalog[index].metadata;
        texts
            .get_mut(tree.find(root, fourcc!("sdes")))
            .expect("scenario description is text")
            .0
            .clone_from(&metadata.description);
        texts
            .get_mut(tree.find(root, fourcc!("cdes")))
            .expect("country description is text")
            .0
            .clone_from(&metadata.nation_descriptions[setup.nation]);
    } else {
        commands.entity(start).insert(InteractionDisabled);
    }
    let Some(game) = setup.game.as_ref() else {
        return;
    };
    for (entity, mut preview, image_node) in &mut previews {
        preview.0 = SatellitePreview::compose(|tile| game.map[tile].owner_nation);
        preview.0.enhance(setup.nation.nation());
        let image = preview.0.to_image(retail.assets().default_dib_palette());
        if let Some(mut image_node) = image_node {
            if let Some(mut existing) = images.get_mut(&image_node.image) {
                *existing = image;
            } else {
                image_node.image = images.add(image);
            }
        } else {
            commands
                .entity(entity)
                .insert(ImageNode::new(images.add(image)));
        }
    }
}

fn cleanup_scenario(mut commands: Commands) {
    commands.remove_resource::<ScenarioSetup>();
}
