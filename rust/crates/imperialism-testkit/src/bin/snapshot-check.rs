#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::Parser;
use imperialism_testkit::{first_serialized_difference, read_game_state};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Validate or compare captured Imperialism game states")]
struct Args {
    /// Runtime result containing a game_state capture.
    result: PathBuf,

    /// Optional runtime result to compare semantically.
    comparison: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let state = read_game_state(&args.result)
        .with_context(|| format!("reading game state {}", args.result.display()))?;
    println!(
        "{} tiles, {} major nations, {} minor nations, {} military units, {} civilian units, {} ships, {} missions",
        state.world.tiles.len(),
        state.major_nations.iter().flatten().count(),
        state.minor_nations.iter().flatten().count(),
        state.military_units.len(),
        state.civilian_units.len(),
        state.ships.len(),
        state.missions.len()
    );
    if let Some(comparison_path) = args.comparison {
        let comparison = read_game_state(&comparison_path).with_context(|| {
            format!(
                "reading comparison game state {}",
                comparison_path.display()
            )
        })?;
        if let Some(difference) = first_serialized_difference(&state, &comparison)
            .context("could not compare game states")?
        {
            bail!(
                "{} differs: C++ {:?}, Rust {:?}",
                difference.path,
                difference.original,
                difference.reimplementation
            );
        }
        println!("semantic game states are identical");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_result_and_optional_comparison() {
        let args = Args::try_parse_from(["snapshot-check", "left.json", "right.json"]).unwrap();
        assert_eq!(args.result, PathBuf::from("left.json"));
        assert_eq!(args.comparison, Some(PathBuf::from("right.json")));
    }
}
