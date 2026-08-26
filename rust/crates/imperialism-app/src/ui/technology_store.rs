use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::map_help;
use super::retail::{RetailPictureSwap, RetailTree, RetailUiAssets, retail_text_style};
use super::session::GameSession;
use super::window::{ModalWindow, bind_modal_keys, dismiss_on_activate};
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress, ScrollArea};
use imperialism_core::{
    CountryStatus, MajorNationId, Technology, TechnologyResearchRejection, TechnologyResearchStatus,
};
use imperialism_formats::{PictureId, RetailTextStylePreset, fourcc};

const TECHNOLOGIES_PER_PAGE: usize = 6;

const fn technology_row_pictures(technology: Technology) -> [PictureId; 2] {
    let offset = technology.retail() as i16 * 2;
    [
        PictureId::new(0x08ff + offset),
        PictureId::new(0x0900 + offset),
    ]
}

#[derive(Component)]
struct TechnologyStoreRoot;

#[derive(Component)]
struct OpenTechnologyStore;

#[derive(Component, Clone, Copy)]
struct TechnologyPurchase(Technology);

#[derive(Component, Clone, Copy)]
struct TechnologyStatusText(Technology);

#[derive(Component)]
struct TechnologyStorePage {
    current: usize,
    last: usize,
}

#[derive(Component)]
struct TechnologyStoreRow(usize);

#[derive(Component, Clone, Copy)]
enum TechnologyPageAction {
    Previous,
    Next,
}

#[derive(Component, Clone, Copy)]
struct TechnologyHistory(Technology);

#[derive(Component)]
struct TechnologyHistoryRoot(Technology);

#[derive(Component)]
struct TechnologyNoticeRoot;

pub(crate) struct TechnologyStorePlugin;

impl Plugin for TechnologyStorePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::TechnologyStore),
            (
                spawn_technology_store,
                bind_technology_store,
                bind_technology_row_actions,
            )
                .chain(),
        )
        .add_systems(
            Update,
            (
                bind_technology_modals,
                project_technology_status,
                project_technology_page,
            )
                .run_if(in_state(AppState::TechnologyStore)),
        );
    }
}

pub(crate) fn bind_open_control(commands: &mut Commands, entity: Entity) {
    commands
        .entity(entity)
        .insert(OpenTechnologyStore)
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
        .remove::<InteractionDisabled>()
        .observe(on_leave_technology_store);
    commands
        .entity(tree.find(root, fourcc!("quer")))
        .remove::<InteractionDisabled>()
        .observe(on_technology_help);

    let page = tree.find(root, fourcc!("page"));
    nodes
        .get_mut(page)
        .expect("technology-store page node")
        .overflow = Overflow::clip();
    let nation = session.active_major_nation();
    let technologies = Technology::all()
        .rev()
        .filter(|&technology| {
            technology != Technology::ScientistsHaveDiscovered
                && session.game.technology().global_unlocks_by_technology[technology]
        })
        .collect::<Vec<_>>();
    commands.entity(root).insert(TechnologyStorePage {
        current: 0,
        last: technologies.len().saturating_sub(1) / TECHNOLOGIES_PER_PAGE,
    });
    for (tag, action) in [
        (fourcc!("lcor"), TechnologyPageAction::Previous),
        (fourcc!("rcor"), TechnologyPageAction::Next),
    ] {
        commands
            .entity(tree.find(root, tag))
            .insert((Button, action))
            .observe(on_technology_page);
    }
    for (row, technology) in technologies.into_iter().enumerate() {
        spawn_technology_row(
            &mut commands,
            &mut assets,
            page,
            row,
            nation,
            technology,
            &session.game,
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
) {
    let y = (row % TECHNOLOGIES_PER_PAGE) as f32 * 63.0;
    let [idle_id, active_id] = technology_row_pictures(technology);
    let picture = assets
        .picture(idle_id)
        .expect("retail technology illustration");
    let active_picture = assets
        .picture(active_id)
        .unwrap_or_else(|_| picture.clone());
    let name = assets
        .string(0x2712, i16::from(technology.retail()) + 1)
        .expect("retail technology name");
    let available_year =
        1815 + i32::from(game.technology().scheduled_unlock_turn_by_technology[technology]) / 4;
    let name = format!("{name}\n{available_year}");
    let description = assets
        .string(0x274e, i16::from(technology.retail()))
        .expect("retail technology benefit");
    let status = game.technology().research_status_by_nation[nation][technology];
    let purchase_pictures = (status != TechnologyResearchStatus::Researched
        && game.technology_prerequisites_completed(nation, technology))
    .then(|| {
        let idle = assets
            .picture(PictureId::new(0x08ff))
            .expect("retail technology purchase button");
        let active = assets
            .picture(PictureId::new(0x0900))
            .unwrap_or_else(|_| idle.clone());
        (idle, active)
    });
    commands
        .spawn_scene(technology_row_scene(
            y,
            row / TECHNOLOGIES_PER_PAGE,
            technology,
            picture,
            active_picture,
            name,
            description,
            status,
            purchase_pictures,
        ))
        .insert(ChildOf(page));
}

fn bind_technology_row_actions(
    mut commands: Commands,
    history: Query<Entity, Added<TechnologyHistory>>,
    purchases: Query<Entity, Added<TechnologyPurchase>>,
) {
    for entity in &history {
        commands.entity(entity).observe(on_technology_history);
    }
    for entity in &purchases {
        commands.entity(entity).observe(on_technology_purchase);
    }
}

#[allow(clippy::too_many_arguments)]
fn technology_row_scene(
    y: f32,
    page: usize,
    technology: Technology,
    picture: Handle<Image>,
    active_picture: Handle<Image>,
    name: String,
    description: String,
    status: TechnologyResearchStatus,
    purchase_pictures: Option<(Handle<Image>, Handle<Image>)>,
) -> impl Scene {
    let purchase = purchase_pictures.map(|(idle, active)| {
        let image = idle.clone();
        bsn! {
            Button
            ActivateOnPress
            template(move |_context| Ok(TechnologyPurchase(technology)))
            template(move |_context| Ok(ImageNode::new(image.clone())))
            template(move |_context| Ok(RetailPictureSwap {
                idle: idle.clone(),
                active: active.clone(),
            }))
        }
    });
    let history_picture = picture.clone();
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(y),
            width: px(562),
            height: px(63),
        }
        template(move |_context| Ok(TechnologyStoreRow(page)))
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(0), width: px(64), height: px(63),
                }
                Button
                ActivateOnPress
                template(move |_context| Ok(TechnologyHistory(technology)))
                template(move |_context| Ok(ImageNode::new(history_picture.clone())))
                template(move |_context| Ok(RetailPictureSwap {
                    idle: picture.clone(),
                    active: active_picture.clone(),
                }))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(77), top: px(0), width: px(105), height: px(63),
                    align_items: AlignItems::Center,
                }
                template(move |_context| Ok(Text::new(name.clone())))
                retail_text_style(1, 0, 12, -2)
                TextColor(Color::BLACK)
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(186),
                    top: px(if status == TechnologyResearchStatus::Researched { 0 } else { 18 }),
                    width: px(83),
                    height: px(if status == TechnologyResearchStatus::Researched { 63 } else { 24 }),
                    justify_content: JustifyContent::Center,
                    align_items: AlignItems::Center,
                }
                template(move |_context| Ok(TechnologyStatusText(technology)))
                Text::default()
                retail_text_style(1, 0, 12, -2)
                TextColor(Color::BLACK)
                {purchase}
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(295), top: px(0), width: px(269), height: px(63),
                    align_items: AlignItems::Center,
                }
                template(move |_context| Ok(Text::new(description.clone())))
                retail_text_style(1, 0, 12, -2)
                TextColor(Color::BLACK)
            ),
        ]
    }
}

fn on_technology_purchase(
    activate: On<Activate>,
    purchases: Query<&TechnologyPurchase>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(purchase) = purchases.get(activate.entity) else {
        return;
    };
    let nation = session.active_major_nation();
    if matches!(
        session.game.toggle_technology_research(nation, purchase.0),
        Err(TechnologyResearchRejection::InsufficientFunds)
    ) {
        spawn_linger_dialog(
            &mut commands,
            TechnologyNoticeRoot,
            AppState::TechnologyStore,
        );
    }
}

fn on_technology_page(
    activate: On<Activate>,
    actions: Query<&TechnologyPageAction>,
    mut pages: Query<&mut TechnologyStorePage>,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Ok(mut page) = pages.single_mut() else {
        return;
    };
    page.current = match action {
        TechnologyPageAction::Previous => page.current.saturating_sub(1),
        TechnologyPageAction::Next => (page.current + 1).min(page.last),
    };
}

fn project_technology_page(
    mut commands: Commands,
    pages: Query<&TechnologyStorePage, Changed<TechnologyStorePage>>,
    mut rows: Query<(&TechnologyStoreRow, &mut Visibility), Without<TechnologyPageAction>>,
    mut buttons: Query<
        (Entity, &TechnologyPageAction, &mut Visibility),
        Without<TechnologyStoreRow>,
    >,
) {
    let Ok(page) = pages.single() else {
        return;
    };
    for (row, mut visibility) in &mut rows {
        *visibility = if row.0 == page.current {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
    }
    for (entity, action, mut visibility) in &mut buttons {
        let enabled = match action {
            TechnologyPageAction::Previous => page.current > 0,
            TechnologyPageAction::Next => page.current < page.last,
        };
        *visibility = if enabled {
            Visibility::Inherited
        } else {
            Visibility::Hidden
        };
        if enabled {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn on_technology_history(
    activate: On<Activate>,
    histories: Query<&TechnologyHistory>,
    mut commands: Commands,
) {
    let Ok(history) = histories.get(activate.entity).copied() else {
        return;
    };
    let root = commands.spawn_scene(generated::techstore_2370()).id();
    commands.entity(root).insert((
        TechnologyHistoryRoot(history.0),
        ModalWindow,
        DespawnOnExit(AppState::TechnologyStore),
    ));
}

fn bind_technology_modals(
    mut commands: Commands,
    histories: Query<(Entity, &TechnologyHistoryRoot), Added<TechnologyHistoryRoot>>,
    notices: Query<Entity, Added<TechnologyNoticeRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
    mut nodes: Query<&mut Node>,
) {
    for (root, history) in &histories {
        let view = tree.view(root);
        let technology = history.0;
        let (title_font, title_layout, title_line_height, _) = assets
            .text_style(RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 18,
                alignment: 1,
            })
            .expect("retail technology-history title style");
        commands.entity(view.find(fourcc!("titl"))).insert((
            Text::new(
                assets
                    .string(0x2712, i16::from(technology.retail()) + 1)
                    .expect("retail technology-history title"),
            ),
            title_font,
            title_layout,
            title_line_height,
            TextColor(Color::BLACK),
        ));
        let picture = assets
            .picture(PictureId::new(0x0944 + i16::from(technology.retail())))
            .expect("retail technology-history picture");
        commands
            .entity(view.find(fourcc!("pict")))
            .insert(ImageNode::new(picture));

        let scroll = view.find(fourcc!("scvw"));
        nodes
            .get_mut(scroll)
            .expect("technology-history scroll view")
            .overflow = Overflow::scroll_y();
        commands
            .entity(scroll)
            .insert((ScrollArea, Pickable::default()));
        let (body_font, body_layout, body_line_height, _) = assets
            .text_style(RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 12,
                alignment: -2,
            })
            .expect("retail technology-history body style");
        commands.spawn((
            Node {
                width: percent(100),
                ..default()
            },
            Text::new(
                retail
                    .text(u16::from(technology.retail()) + 0x08fc)
                    .expect("retail technology-history body"),
            ),
            body_font,
            body_layout,
            body_line_height,
            TextColor(Color::BLACK),
            Pickable::IGNORE,
            ChildOf(scroll),
        ));
        let okay = view.find(fourcc!("okay"));
        dismiss_on_activate(&mut commands, okay, root);
        bind_modal_keys(&mut commands, root, Some(okay), None);
    }
    for root in &notices {
        let linger = bind_linger_dialog(&mut commands, root, &tree);
        let body = assets
            .string(0x2745, 4)
            .expect("retail insufficient-funds message");
        linger.set_title(&mut commands, &mut assets, "");
        linger.set_body(&mut commands, &mut assets, body);
        commands.entity(linger.cancel).insert(Visibility::Hidden);
    }
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
    fn page_controls_reveal_later_technology_rows() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_observer(on_technology_page)
            .add_systems(Update, project_technology_page);
        app.world_mut().spawn(TechnologyStorePage {
            current: 0,
            last: 1,
        });
        let previous = app
            .world_mut()
            .spawn((TechnologyPageAction::Previous, Visibility::Inherited))
            .id();
        let next = app
            .world_mut()
            .spawn((TechnologyPageAction::Next, Visibility::Inherited))
            .id();
        let first_page = app
            .world_mut()
            .spawn((TechnologyStoreRow(0), Visibility::Inherited))
            .id();
        let second_page = app
            .world_mut()
            .spawn((TechnologyStoreRow(1), Visibility::Inherited))
            .id();

        app.update();
        assert_eq!(
            app.world().get::<Visibility>(first_page),
            Some(&Visibility::Inherited)
        );
        assert_eq!(
            app.world().get::<Visibility>(second_page),
            Some(&Visibility::Hidden)
        );
        assert!(app.world().get::<InteractionDisabled>(previous).is_some());
        assert!(app.world().get::<InteractionDisabled>(next).is_none());

        app.world_mut()
            .commands()
            .trigger(Activate { entity: next });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            app.world().get::<Visibility>(first_page),
            Some(&Visibility::Hidden)
        );
        assert_eq!(
            app.world().get::<Visibility>(second_page),
            Some(&Visibility::Inherited)
        );
        assert!(app.world().get::<InteractionDisabled>(previous).is_none());
        assert!(app.world().get::<InteractionDisabled>(next).is_some());
    }

    #[test]
    fn microscope_control_enters_the_technology_store() {
        let mut app = App::new();
        let game = crate::ui::test_support::beginning_of_game();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::StrategicMap)
            .insert_resource(GameSession::new(game))
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
