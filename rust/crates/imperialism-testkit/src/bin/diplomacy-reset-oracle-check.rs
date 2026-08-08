#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_core::{GameState, MajorNationId};
use imperialism_testkit::{first_serialized_difference, read_game_state, read_runtime_capture};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Compare a native diplomacy-commitment reset with the core rule")]
struct Options {
    /// Native result containing diplomacy_commitments_input and game_state captures.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let mut actual: GameState =
        read_runtime_capture(&options.result, "diplomacy_commitments_input").with_context(
            || format!("reading diplomacy input from {}", options.result.display()),
        )?;
    let expected = read_game_state(&options.result)
        .with_context(|| format!("reading final state from {}", options.result.display()))?;
    let nation = MajorNationId::from_nation(actual.turn.active_nation)
        .context("the native diplomacy reset did not have an active major nation")?;

    actual
        .reset_diplomacy_commitments(nation)
        .context("Rust diplomacy reset failed")?;
    if let Some(difference) = first_serialized_difference(&expected, &actual)
        .context("comparing diplomacy reset states")?
    {
        bail!(
            "{} differs: C++ {:?}, Rust {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        );
    }

    println!("semantic game states are identical");
    Ok(())
}
