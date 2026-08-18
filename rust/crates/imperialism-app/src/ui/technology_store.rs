use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::map_help;
use super::retail::{RetailPictureSwap, RetailTree, RetailUiAssets};
use super::session::GameSession;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::{CountryStatus, MajorNationId, Technology, TechnologyResearchStatus};
use imperialism_formats::{PictureId, RetailTextStylePreset, fourcc};

#[derive(Component)]
struct TechnologyStoreRoot;

#[derive(Component)]
struct OpenTechnologyStore;

#[derive(Component, Clone, Copy)]
struct TechnologyPurchase(Technology);

#[derive(Component, Clone, Copy)]
struct TechnologyStatusText(Technology);

pub(crate) struct TechnologyStorePlugin;

impl Plugin for TechnologyStorePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::TechnologyStore),
            (spawn_technology_store, bind_technology_store).chain(),
        )
        .add_systems(
            Update,
            project_technology_status.run_if(in_state(AppState::TechnologyStore)),
        );
    }
}

pub(crate) fn bind_open_control(commands: &mut Commands, entity: Entity) {
    commands
        .entity(entity)
        .insert((OpenTechnologyStore, ActivateOnPress))
        .remove::<InteractionDisabled>()
        .observe(on_open_technology_store);
}

fn on_open_technology_store(
    activate: On<Activate>,
    controls: Query<(), With<OpenTechnologyStore>>,
    session: Res<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if controls.get(activate.entity).is_err() {
        return;
    }
    let Some(nation) = MajorNationId::from_nation(session.game.turn().active_nation) else {
        return;
    };
    if matches!(
        session.game.nations().major(nation).common.status(),
        CountryStatus::ProtectorateOf(_)
    ) {
        return;
    }
    next_state.set(AppState::TechnologyStore);
}

fn spawn_technology_store(mut commands: Commands) {
    let root = commands.spawn_scene(generated::techstore_2300()).id();
    commands.entity(root).insert((
        TechnologyStoreRoot,
        DespawnOnExit(AppState::TechnologyStore),
    ));
}

fn bind_technology_store(
    mut commands: Commands,
    root: Single<Entity, Added<TechnologyStoreRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    mut nodes: Query<&mut Node>,
) {
    let root = *root;
    bind_native_game_screen_nav(
        &mut commands,
        root,
        &tree,
        fourcc!("topB"),
        Some(fourcc!("tool")),
        false,
    );
    bind_game_status_display(&mut commands, &mut assets, root, &tree);
    commands
        .entity(tree.find(root, fourcc!("end ")))
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_leave_technology_store);
    commands
        .entity(tree.find(root, fourcc!("quer")))
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_technology_help);

    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 14,
            alignment: -2,
        })
        .expect("retail technology-store title style");
    for (tag, index) in [
        (fourcc!("ttl1"), 5),
        (fourcc!("ttl2"), 6),
        (fourcc!("ttl3"), 7),
    ] {
        commands.entity(tree.find(root, tag)).insert((
            Text::new(
                assets
                    .string(0x274f, index)
                    .expect("retail technology-store heading"),
            ),
            title_font.clone(),
            title_layout,
            title_line_height,
            TextColor(Color::BLACK),
        ));
    }

    let page = tree.find(root, fourcc!("page"));
    nodes
        .get_mut(page)
        .expect("technology-store page node")
        .overflow = Overflow::clip();
    let nation = session.active_major_nation();
    let row_style = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: -2,
        })
        .expect("retail technology-store row style");
    for (row, technology) in Technology::all()
        .rev()
        .filter(|&technology| {
            technology != Technology::ScientistsHaveDiscovered
                && session.game.technology().global_unlocks_by_technology[technology]
        })
        .enumerate()
    {
        spawn_technology_row(
            &mut commands,
            &mut assets,
            page,
            row,
            nation,
            technology,
            &session.game,
            &row_style,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_technology_row(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    page: Entity,
    row: usize,
    nation: MajorNationId,
    technology: Technology,
    game: &imperialism_core::GameState,
    row_style: &(TextFont, TextLayout, bevy::text::LineHeight, bool),
) {
    let y = row as f32 * 63.0;
    let row_entity = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(y),
                width: px(562),
                height: px(63),
                ..default()
            },
            ChildOf(page),
        ))
        .id();
    let picture = assets
        .picture(PictureId::new(0x08ff + i16::from(technology.retail()) * 2))
        .expect("retail technology illustration");
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(64),
            height: px(63),
            ..default()
        },
        ImageNode::new(picture),
        ChildOf(row_entity),
    ));

    let name = assets
        .string(0x2712, i16::from(technology.retail()) + 1)
        .expect("retail technology name");
    let available_year =
        1815 + i32::from(game.technology().scheduled_unlock_turn_by_technology[technology]) / 4;
    spawn_row_text(
        commands,
        row_entity,
        77.0,
        105.0,
        format!("{name}\n{available_year}"),
        row_style,
    );
    let description = assets
        .string(0x274e, i16::from(technology.retail()))
        .expect("retail technology benefit");
    spawn_row_text(commands, row_entity, 295.0, 269.0, description, row_style);

    let status = game.technology().research_status_by_nation[nation][technology];
    let status_entity = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(186),
                top: px(if status == TechnologyResearchStatus::Researched {
                    0
                } else {
                    18
                }),
                width: px(83),
                height: px(if status == TechnologyResearchStatus::Researched {
                    63
                } else {
                    24
                }),
                justify_content: JustifyContent::Center,
                align_items: AlignItems::Center,
                ..default()
            },
            TechnologyStatusText(technology),
            Text::default(),
            row_style.0.clone(),
            row_style.1,
            row_style.2,
            TextColor(Color::BLACK),
            ChildOf(row_entity),
        ))
        .id();
    if status != TechnologyResearchStatus::Researched
        && game.technology_prerequisites_completed(nation, technology)
    {
        let idle = assets
            .picture(PictureId::new(0x08ff))
            .expect("retail technology purchase button");
        let active = assets
            .picture(PictureId::new(0x0900))
            .unwrap_or_else(|_| idle.clone());
        commands
            .entity(status_entity)
            .insert((
                Button,
                ActivateOnPress,
                TechnologyPurchase(technology),
                ImageNode::new(idle.clone()),
                RetailPictureSwap { idle, active },
            ))
            .observe(on_technology_purchase);
    }
}

fn spawn_row_text(
    commands: &mut Commands,
    parent: Entity,
    left: f32,
    width: f32,
    text: String,
    style: &(TextFont, TextLayout, bevy::text::LineHeight, bool),
) {
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(0),
            width: px(width),
            height: px(63),
            align_items: AlignItems::Center,
            ..default()
        },
        Text::new(text),
        style.0.clone(),
        style.1,
        style.2,
        TextColor(Color::BLACK),
        ChildOf(parent),
    ));
}

fn on_technology_purchase(
    activate: On<Activate>,
    purchases: Query<&TechnologyPurchase>,
    mut session: ResMut<GameSession>,
) {
    let Ok(purchase) = purchases.get(activate.entity) else {
        return;
    };
    let nation = session.active_major_nation();
    let _ = session.game.toggle_technology_research(nation, purchase.0);
}

fn project_technology_status(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    added: Query<(), Added<TechnologyStatusText>>,
    mut statuses: Query<(&TechnologyStatusText, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    for (display, mut text) in &mut statuses {
        let technology = display.0;
        text.0 = match session.game.technology().research_status_by_nation[nation][technology] {
            TechnologyResearchStatus::Researched => {
                let template = retail
                    .string(0x274f, 1)
                    .expect("retail technology completion template");
                let year = (1815
                    + i32::from(
                        session.game.technology().completion_year_by_nation[nation][technology],
                    ))
                .to_string();
                fill_brackets(&template, &[&year])
            }
            TechnologyResearchStatus::Pending => {
                retail.string(0x274f, 4).expect("retail purchasing label")
            }
            TechnologyResearchStatus::NotStarted
                if session
                    .game
                    .technology_prerequisites_completed(nation, technology) =>
            {
                format_currency(imperialism_core::GameState::technology_purchase_cost(
                    technology,
                ))
            }
            TechnologyResearchStatus::NotStarted => {
                let missing = session
                    .game
                    .missing_technology_prerequisites(nation, technology);
                let names = missing
                    .into_iter()
                    .flatten()
                    .map(|prerequisite| {
                        retail
                            .string(0x2712, i16::from(prerequisite.retail()) + 1)
                            .expect("retail prerequisite technology name")
                    })
                    .collect::<Vec<_>>();
                let template = retail
                    .string(0x274f, if names.len() == 1 { 3 } else { 2 })
                    .expect("retail prerequisite template");
                fill_brackets(
                    &template,
                    &names.iter().map(String::as_str).collect::<Vec<_>>(),
                )
            }
        };
    }
}

fn on_leave_technology_store(_activate: On<Activate>, mut next_state: ResMut<NextState<AppState>>) {
    next_state.set(AppState::StrategicMap);
}

fn on_technology_help(_activate: On<Activate>, mut commands: Commands) {
    map_help::spawn_technology(&mut commands);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microscope_control_enters_the_technology_store() {
        let mut app = App::new();
        let game = crate::ui::test_support::beginning_of_game();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::StrategicMap)
            .insert_resource(GameSession { game })
            .add_observer(on_open_technology_store);
        let control = app.world_mut().spawn(OpenTechnologyStore).id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: control });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::TechnologyStore
        );
    }
}
