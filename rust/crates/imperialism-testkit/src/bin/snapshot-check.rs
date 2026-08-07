#![forbid(unsafe_code)]

use anyhow::{Context, bail};
use clap::Parser;
use imperialism_formats::game_state_from_snapshot;
use imperialism_testkit::{first_snapshot_difference, read_game_snapshot};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Validate or compare canonical Imperialism snapshots")]
struct Args {
    /// Snapshot to validate.
    snapshot: PathBuf,

    /// Optional snapshot to compare semantically.
    comparison: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let snapshot = read_game_snapshot(&args.snapshot)
        .with_context(|| format!("reading snapshot {}", args.snapshot.display()))?;
    let state =
        game_state_from_snapshot(snapshot.clone()).context("snapshot cannot populate GameState")?;
    println!(
        "{}: {} tiles, {} nations, {} cities, {} military units, {} civilian units, {} ships, {} missions, state {}",
        snapshot.schema,
        snapshot.world.tiles.len(),
        state.nations.iter().flatten().count(),
        state.cities.iter().flatten().count(),
        state.military_units.len(),
        state.civilian_units.len(),
        state.ships.len(),
        state.missions.len(),
        snapshot.hashes.state
    );
    if let Some(comparison_path) = args.comparison {
        let comparison = read_game_snapshot(&comparison_path).with_context(|| {
            format!("reading comparison snapshot {}", comparison_path.display())
        })?;
        if let Some(difference) = first_snapshot_difference(&snapshot, &comparison)
            .context("could not compare snapshots")?
        {
            bail!(
                "{} differs: C++ {:?}, Rust {:?}",
                difference.path,
                difference.original,
                difference.reimplementation
            );
        }
        println!("semantic snapshots are identical");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_snapshot_and_optional_comparison() {
        let args = Args::try_parse_from(["snapshot-check", "left.json", "right.json"]).unwrap();
        assert_eq!(args.snapshot, PathBuf::from("left.json"));
        assert_eq!(args.comparison, Some(PathBuf::from("right.json")));
    }
}
