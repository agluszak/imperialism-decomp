use super::GameSession;
use super::retail::{ModalDialog, RetailTag};
use crate::{AppState, GamePlugin, RandomGameNamesResource};
use bevy::asset::AssetPlugin;
use bevy::camera::NormalizedRenderTarget;
use bevy::picking::backend::HitData;
use bevy::picking::events::{Click, Pointer, Press, Release};
use bevy::picking::pointer::{Location, PointerId};
use bevy::prelude::*;
use bevy::scene::ScenePlugin;
use bevy::state::app::StatesPlugin;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button as UiButton, ButtonPlugin};
use imperialism_core::GameState;
use imperialism_formats::FourCc;
use std::time::Duration;

const DEFAULT_UPDATE_LIMIT: usize = 32;

/// Semantic driver for deterministic, renderer-free Bevy integration tests.
pub(crate) struct HeadlessGame {
    app: App,
}

impl HeadlessGame {
    pub(crate) fn new(app: App) -> Self {
        Self { app }
    }

    pub(crate) fn from_game(game: GameState, state: AppState) -> Self {
        let mut headless = Self::at_state(state);
        headless.app.insert_resource(GameSession::new(game));
        headless
    }

    pub(crate) fn at_state(state: AppState) -> Self {
        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            StatesPlugin,
            ButtonPlugin,
            GamePlugin,
        ))
        .insert_resource(RandomGameNamesResource(
            imperialism_testkit::random_game_names(),
        ))
        .insert_state(state);
        Self { app }
    }

    pub(crate) fn from_beginning_of_game() -> Self {
        Self::from_game(
            imperialism_testkit::beginning_of_game(),
            AppState::StrategicMap,
        )
    }

    pub(crate) fn state(&self) -> AppState {
        *self.app.world().resource::<State<AppState>>().get()
    }

    pub(crate) fn core(&self) -> &GameState {
        &self.app.world().resource::<GameSession>().game
    }

    pub(crate) fn app_mut(&mut self) -> &mut App {
        &mut self.app
    }

    pub(crate) fn update(&mut self) {
        self.app.update();
    }

    pub(crate) fn advance_until_state(&mut self, expected: AppState) {
        self.advance_until(|game| game.state() == expected);
    }

    pub(crate) fn advance_until(&mut self, mut predicate: impl FnMut(&Self) -> bool) {
        for _ in 0..DEFAULT_UPDATE_LIMIT {
            if predicate(self) {
                return;
            }
            self.update();
        }
        panic!(
            "headless game did not reach its expected condition after {DEFAULT_UPDATE_LIMIT} updates: {}",
            self.diagnostics()
        );
    }

    pub(crate) fn entity_with_tag(&mut self, tag: FourCc) -> Entity {
        let mut query = self.app.world_mut().query::<(
            Entity,
            &RetailTag,
            Option<&Visibility>,
            Has<InteractionDisabled>,
        )>();
        let matches = query
            .iter(self.app.world())
            .filter_map(|(entity, candidate, visibility, disabled)| {
                (candidate.0 == tag && visibility != Some(&Visibility::Hidden) && !disabled)
                    .then_some(entity)
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [entity] => *entity,
            _ => panic!(
                "expected one enabled visible control tagged {tag:?}, found {matches:?}: {}",
                self.diagnostics()
            ),
        }
    }

    pub(crate) fn trigger_action_tag(&mut self, tag: FourCc) {
        let entity = self.entity_with_tag(tag);
        self.trigger_action_entity(entity);
    }

    pub(crate) fn trigger_action_entity(&mut self, entity: Entity) {
        self.app.world_mut().commands().trigger(Activate { entity });
        self.app.world_mut().flush();
        self.update();
    }

    pub(crate) fn press_tag(&mut self, tag: FourCc) {
        let entity = self.entity_with_tag(tag);
        assert!(
            self.app.world().entity(entity).contains::<UiButton>(),
            "tagged entity {entity:?} is not a Bevy button: {}",
            self.diagnostics()
        );
        let location = Location {
            target: NormalizedRenderTarget::None {
                width: 0,
                height: 0,
            },
            position: Vec2::ZERO,
        };
        let hit = HitData {
            camera: Entity::PLACEHOLDER,
            depth: 0.0,
            position: None,
            normal: None,
            extra: None,
        };
        let mut commands = self.app.world_mut().commands();
        commands.trigger(Pointer::new(
            PointerId::Mouse,
            location.clone(),
            Press {
                button: PointerButton::Primary,
                hit: hit.clone(),
                count: 1,
            },
            entity,
        ));
        commands.trigger(Pointer::new(
            PointerId::Mouse,
            location.clone(),
            Click {
                button: PointerButton::Primary,
                hit: hit.clone(),
                duration: Duration::ZERO,
                count: 1,
            },
            entity,
        ));
        commands.trigger(Pointer::new(
            PointerId::Mouse,
            location,
            Release {
                button: PointerButton::Primary,
                hit,
            },
            entity,
        ));
        self.app.world_mut().flush();
        self.update();
    }

    pub(crate) fn assert_state(&self, expected: AppState) {
        assert_eq!(self.state(), expected, "{}", self.diagnostics());
    }

    pub(crate) fn assert_no_modal(&mut self) {
        let modals = self
            .app
            .world_mut()
            .query_filtered::<Entity, With<ModalDialog>>()
            .iter(self.app.world())
            .collect::<Vec<_>>();
        assert!(modals.is_empty(), "{}", self.diagnostics());
    }

    pub(crate) fn assert_tag_visible(&mut self, tag: FourCc) {
        let _ = self.entity_with_tag(tag);
    }

    fn diagnostics(&self) -> String {
        let world = self.app.world();
        let state = world
            .get_resource::<State<AppState>>()
            .map(|state| format!("{:?}", state.get()))
            .unwrap_or_else(|| "<missing>".to_owned());
        let core = world.get_resource::<GameSession>().map(|session| {
            format!(
                "phase={:?}, continuation={:?}",
                session.game.turn().phase(),
                session.game.turn_continuation()
            )
        });
        let mut modals = world
            .iter_entities()
            .filter(|entity| entity.contains::<ModalDialog>())
            .map(|entity| entity.id())
            .collect::<Vec<_>>();
        let mut roots = world
            .iter_entities()
            .filter(|entity| !entity.contains::<ChildOf>())
            .map(|entity| entity.id())
            .collect::<Vec<_>>();
        let mut tags = world
            .iter_entities()
            .filter_map(|entity| entity.get::<RetailTag>().map(|tag| (entity.id(), tag.0)))
            .collect::<Vec<_>>();
        modals.sort();
        roots.sort();
        tags.sort_by_key(|(entity, _)| *entity);
        format!(
            "state={state}, {}, modals={modals:?}, roots={roots:?}, tags={tags:?}",
            core.unwrap_or_else(|| "core=<missing>".to_owned())
        )
    }
}
