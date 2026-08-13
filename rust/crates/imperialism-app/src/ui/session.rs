use bevy::prelude::*;
use imperialism_core::GameState;

/// Authoritative in-memory game owned by the running Bevy app.
#[derive(Resource, Clone, Debug, PartialEq)]
pub(crate) struct GameSession(pub(crate) GameState);
