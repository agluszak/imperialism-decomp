//! Retail cinematics, Council of Governors, Game Score, and high-score screens.

use super::generated;
use super::retail::RetailTree;
use super::session::{GameSession, apply_turn_stop};
use crate::media::{MovieBackend, MusicDirector, rgba_frame_to_image};
use crate::ui::load_save::SaveDirectory;
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui::widget::NodeImageMode;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{
    FourCc, MovieId, empty_high_score_table, fourcc, insert_high_score, read_scores_dat,
    write_scores_dat,
};
use std::time::Duration;

#[derive(Resource)]
struct ActiveCinematic {
    movie: MovieBackend,
    image: Handle<Image>,
}

#[derive(Component)]
struct CouncilRoot;

#[derive(Component)]
struct CouncilClose;

#[derive(Component)]
struct GameScoreRoot;

#[derive(Component)]
struct GameScoreClose;

#[derive(Component)]
struct HighScoreRoot;

#[derive(Component)]
struct HighScoreClose;

pub(crate) struct OpeningCinematicPlugin;
pub(crate) struct CouncilOfGovernorsPlugin;
pub(crate) struct GameScorePlugin;
pub(crate) struct HighScorePlugin;

impl Plugin for OpeningCinematicPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::OpeningCinematic), spawn_opening_cinematic)
            .add_systems(
                Update,
                pump_opening_cinematic.run_if(in_state(AppState::OpeningCinematic)),
            )
            .add_systems(OnExit(AppState::OpeningCinematic), cleanup_opening_cinematic);
    }
}

fn spawn_opening_cinematic(
    mut commands: Commands,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut music: ResMut<MusicDirector>,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    music.stop_all();
    let movie_id = session.as_ref().map_or(MovieId::Open, |session| {
        movie_id_for_stem(session.game.opening_cinematic_movie())
    });
    let path = retail.assets().movie_path(movie_id);
    let movie = match MovieBackend::open(&path) {
        Ok(movie) => movie,
        Err(error) => {
            warn!("skipping unavailable retail movie {movie_id}: {error}");
            finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
            return;
        }
    };
    if let Err(error) = movie.play() {
        warn!("skipping unplayable retail movie {movie_id}: {error}");
        finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
        return;
    }

    let image = images.add(Image::default());
    commands
        .spawn((
            Name::new(format!("Retail movie: {movie_id}")),
            DespawnOnExit(AppState::OpeningCinematic),
            Node {
                position_type: PositionType::Absolute,
                width: Val::Percent(100.0),
                height: Val::Percent(100.0),
                justify_content: JustifyContent::Center,
                align_items: AlignItems::Center,
                ..default()
            },
            BackgroundColor(Color::BLACK),
            GlobalZIndex(100),
            Pickable::IGNORE,
        ))
        .with_children(|parent| {
            parent.spawn((
                Node {
                    width: Val::Px(640.0),
                    height: Val::Px(480.0),
                    ..default()
                },
                ImageNode::new(image.clone()).with_mode(NodeImageMode::Stretch),
                Pickable::IGNORE,
            ));
        });
    commands.insert_resource(ActiveCinematic { movie, image });
}

fn pump_opening_cinematic(
    active: Option<Res<ActiveCinematic>>,
    keyboard: Res<ButtonInput<KeyCode>>,
    mouse: Res<ButtonInput<MouseButton>>,
    mut images: ResMut<Assets<Image>>,
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Some(active) = active else {
        return;
    };
    let skip = keyboard.just_pressed(KeyCode::Escape)
        || keyboard.just_pressed(KeyCode::Space)
        || keyboard.just_pressed(KeyCode::Enter)
        || keyboard.just_pressed(KeyCode::NumpadEnter)
        || mouse.get_just_pressed().next().is_some();

    let mut finished = skip;
    if !finished {
        match active.movie.pull_video_frame(Duration::ZERO) {
            Ok(Some(frame)) => {
                if let Some(image) = images.get_mut(&active.image) {
                    *image = rgba_frame_to_image(&frame);
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!("retail movie playback failed: {error}");
                finished = true;
            }
        }
        finished |= active.movie.reached_eos();
    }

    if finished {
        active.movie.stop();
        finish_opening_cinematic(&mut commands, &mut session, &mut next_state);
    }
}

fn cleanup_opening_cinematic(mut commands: Commands) {
    commands.remove_resource::<ActiveCinematic>();
}

fn finish_opening_cinematic(
    commands: &mut Commands,
    session: &mut Option<ResMut<GameSession>>,
    next_state: &mut NextState<AppState>,
) {
    commands.remove_resource::<ActiveCinematic>();
    let Some(session) = session.as_mut() else {
        next_state.set(AppState::MainMenu);
        return;
    };
    let stop = session.game.close_opening_cinematic();
    if stop == TurnStop::SessionEnded {
        commands.remove_resource::<GameSession>();
        next_state.set(AppState::MainMenu);
    } else {
        apply_turn_stop(stop, next_state);
    }
}

fn movie_id_for_stem(stem: &str) -> MovieId {
    match stem {
        "open" => MovieId::Open,
        "vote" => MovieId::Vote,
        "win" => MovieId::Win,
        "lose" => MovieId::Lose,
        _ => panic!("core returned unknown retail movie stem {stem:?}"),
    }
}

impl Plugin for CouncilOfGovernorsPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::CouncilOfGovernors),
            (spawn_council, bind_council).chain(),
        )
        .add_systems(
            Update,
            project_council.run_if(
                in_state(AppState::CouncilOfGovernors).and_then(resource_exists::<GameSession>),
            ),
        )
        .add_observer(on_council_close.run_if(in_state(AppState::CouncilOfGovernors)));
    }
}

fn spawn_council(mut commands: Commands) {
    let root = commands.spawn_scene(generated::diplo_2016()).id();
    commands
        .entity(root)
        .insert((CouncilRoot, DespawnOnExit(AppState::CouncilOfGovernors)));
}

fn bind_council(
    mut commands: Commands,
    root: Single<Entity, Added<CouncilRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("end ")))
        .insert((CouncilClose, ActivateOnPress));
}

#[derive(Component)]
struct CouncilText(FourCc);

fn project_council(
    session: Res<GameSession>,
    added: Query<(), Added<CouncilRoot>>,
    mut commands: Commands,
    tree: RetailTree,
    root: Query<Entity, With<CouncilRoot>>,
    mut texts: Query<(&CouncilText, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) && !texts.is_empty() {
        return;
    }
    let Ok(root) = root.single() else {
        return;
    };
    if texts.is_empty() {
        for tag in [
            fourcc!("can0"),
            fourcc!("can1"),
            fourcc!("num0"),
            fourcc!("num1"),
            fourcc!("num2"),
        ] {
            let entity = tree.find(root, tag);
            commands.entity(entity).insert(CouncilText(tag));
        }
        return;
    }
    let congress = &session.game.diplomacy().congress;
    let chairman = congress
        .chairman
        .and_then(|id| session.game.nations().display_name(id.nation()))
        .unwrap_or("")
        .to_owned();
    let counterpart = congress
        .counterpart
        .and_then(|id| session.game.nations().display_name(id.nation()))
        .unwrap_or("")
        .to_owned();
    for (label, mut text) in &mut texts {
        text.0 = match label.0 {
            tag if tag == fourcc!("can0") => chairman.clone(),
            tag if tag == fourcc!("can1") => counterpart.clone(),
            tag if tag == fourcc!("num0") => congress.chairman_support.to_string(),
            tag if tag == fourcc!("num1") => congress.counterpart_support.to_string(),
            tag if tag == fourcc!("num2") => congress.neutral_support.to_string(),
            _ => continue,
        };
    }
}

fn on_council_close(
    activate: On<Activate>,
    actions: Query<(), With<CouncilClose>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    apply_turn_stop(session.game.close_council_of_governors(), &mut next_state);
}

impl Plugin for GameScorePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::GameScore),
            (spawn_game_score, bind_game_score).chain(),
        )
        .add_systems(
            Update,
            project_game_score
                .run_if(in_state(AppState::GameScore).and_then(resource_exists::<GameSession>)),
        )
        .add_observer(on_game_score_close.run_if(in_state(AppState::GameScore)));
    }
}

fn spawn_game_score(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1515()).id();
    commands
        .entity(root)
        .insert((GameScoreRoot, DespawnOnExit(AppState::GameScore)));
}

fn bind_game_score(
    mut commands: Commands,
    root: Single<Entity, Added<GameScoreRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("done")))
        .insert((GameScoreClose, ActivateOnPress));
}

#[derive(Component)]
struct GameScoreValue(usize);

fn project_game_score(
    session: Res<GameSession>,
    added: Query<(), Added<GameScoreRoot>>,
    mut commands: Commands,
    tree: RetailTree,
    root: Query<Entity, With<GameScoreRoot>>,
    mut values: Query<(&GameScoreValue, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) && !values.is_empty() {
        return;
    }
    let Ok(root) = root.single() else {
        return;
    };
    const NUMS: [imperialism_formats::FourCc; 12] = [
        fourcc!("numa"),
        fourcc!("numb"),
        fourcc!("numc"),
        fourcc!("numd"),
        fourcc!("nume"),
        fourcc!("numf"),
        fourcc!("numg"),
        fourcc!("numh"),
        fourcc!("numi"),
        fourcc!("numj"),
        fourcc!("numk"),
        fourcc!("numl"),
    ];
    if values.is_empty() {
        for (index, tag) in NUMS.iter().enumerate() {
            commands
                .entity(tree.find(root, *tag))
                .insert(GameScoreValue(index));
        }
        return;
    }
    let Some(nation) = MajorNationId::from_nation(session.game.turn().active_nation) else {
        return;
    };
    let rows = session.game.generate_game_score(nation).rows();
    for (slot, mut text) in &mut values {
        text.0 = rows[slot.0].to_string();
    }
}

fn on_game_score_close(
    activate: On<Activate>,
    actions: Query<(), With<GameScoreClose>>,
    mut session: ResMut<GameSession>,
    save_dir: Res<SaveDirectory>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    if let Some(nation) = MajorNationId::from_nation(session.game.turn().active_nation) {
        persist_high_score(&session.game, nation, &save_dir.0);
    }
    apply_turn_stop(session.game.close_game_score(), &mut next_state);
}

fn persist_high_score(state: &GameState, nation: MajorNationId, directory: &std::path::Path) {
    let path = directory.join("scores.dat");
    let mut table = std::fs::read(&path)
        .map(|bytes| read_scores_dat(&bytes))
        .unwrap_or_else(|_| empty_high_score_table());
    let score = state.generate_game_score(nation);
    let name = state.nations().display_name(nation.nation()).unwrap_or("");
    insert_high_score(&mut table, score.total, name);
    let _ = std::fs::write(&path, write_scores_dat(&table));
}

impl Plugin for HighScorePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::HighScore),
            (spawn_high_score, bind_high_score).chain(),
        )
        .add_systems(Update, project_high_score.run_if(in_state(AppState::HighScore)))
        .add_observer(on_high_score_close.run_if(in_state(AppState::HighScore)));
    }
}

fn spawn_high_score(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1504()).id();
    commands
        .entity(root)
        .insert((HighScoreRoot, DespawnOnExit(AppState::HighScore)));
}

fn bind_high_score(
    mut commands: Commands,
    root: Single<Entity, Added<HighScoreRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("labl")))
        .insert((HighScoreClose, ActivateOnPress));
}

fn project_high_score(
    save_dir: Option<Res<SaveDirectory>>,
    added: Query<(), Added<HighScoreRoot>>,
    tree: RetailTree,
    root: Query<Entity, With<HighScoreRoot>>,
    mut labels: Query<&mut Text>,
) {
    if added.is_empty() {
        return;
    }
    let Ok(root) = root.single() else {
        return;
    };
    let label = tree.find(root, fourcc!("labl"));
    let table = save_dir
        .and_then(|dir| std::fs::read(dir.0.join("scores.dat")).ok())
        .map(|bytes| read_scores_dat(&bytes))
        .unwrap_or_else(empty_high_score_table);
    let mut listing = String::new();
    for (rank, entry) in table.iter().enumerate() {
        if !listing.is_empty() {
            listing.push('\n');
        }
        listing.push_str(&format!(
            "{:>2}. {:>6}  {}",
            rank + 1,
            entry.score,
            entry.name
        ));
    }
    if let Ok(mut text) = labels.get_mut(label) {
        text.0 = listing;
    }
}

fn on_high_score_close(
    activate: On<Activate>,
    actions: Query<(), With<HighScoreClose>>,
    mut commands: Commands,
    mut session: Option<ResMut<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    if let Some(session) = session.as_mut() {
        let _ = session.game.close_high_scores();
    }
    commands.remove_resource::<GameSession>();
    next_state.set(AppState::MainMenu);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retail_movie_stems_map_to_typed_assets() {
        assert_eq!(movie_id_for_stem("open"), MovieId::Open);
        assert_eq!(movie_id_for_stem("vote"), MovieId::Vote);
        assert_eq!(movie_id_for_stem("win"), MovieId::Win);
        assert_eq!(movie_id_for_stem("lose"), MovieId::Lose);
    }
}
