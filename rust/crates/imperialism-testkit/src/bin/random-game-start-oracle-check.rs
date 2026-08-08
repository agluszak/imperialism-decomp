#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_core::{
    Difficulty, MajorNationId, RandomGameDraft, RetailCrtRng, RetailLcg, RetailTopologyByte,
    create_random_game, generate_english_random_setup_name,
    generate_random_setup_preview_with_clock_seed,
};
use imperialism_testkit::{
    compare_random_game_start_boundary, project_random_game_start_boundary, read_game_state,
    read_runtime_seed,
};
use std::path::{Path, PathBuf};

/// Country name forced by `RandomSetupFlow` before Accept on Normal start scenarios.
const HARNESS_COUNTRY_NAME: &str = "Testland";
/// Difficulty forced by `CapitalSelectionScriptScenario::DifficultyLevel`.
const HARNESS_DIFFICULTY: Difficulty = Difficulty::Normal;
const DEFAULT_TOPOLOGY: RetailTopologyByte = RetailTopologyByte::from_wraps_horizontally(true);

#[derive(Debug, Parser)]
#[command(
    about = "Compare create_random_game against a random_game_normal_start game_state allowlist"
)]
struct Options {
    /// Native runtime result containing a game_state capture from random_game_normal_start.
    result: PathBuf,
}

fn main() -> Result<()> {
    check_start_boundary(&Options::parse().result)
}

fn check_start_boundary(result: &Path) -> Result<()> {
    let clock_seed = read_runtime_seed(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let cpp_state =
        read_game_state(result).with_context(|| format!("could not read {}", result.display()))?;

    let draft = harness_draft(clock_seed, &cpp_state)?;
    let preview = generate_random_setup_preview_with_clock_seed(
        draft_planet_seed(clock_seed).as_bytes(),
        draft.topology,
        clock_seed,
    );
    let rust_state = create_random_game(&draft, &preview)
        .context("create_random_game rejected the harness draft/preview")?;

    if let Some(difference) = compare_random_game_start_boundary(&cpp_state, &rust_state)
        .context("could not compare start-boundary subsets")?
    {
        bail!(
            "start-boundary mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        );
    }

    let subset = project_random_game_start_boundary(&rust_state);
    println!(
        "random-game start boundary matched: seed={} nation={} difficulty={} tiles={} nations={} cities={} map_generation={:08x}",
        clock_seed,
        draft.nation.get(),
        draft.difficulty.retail_byte(),
        subset.tile_provinces.len(),
        subset.nations.len(),
        subset.cities.iter().flatten().count(),
        rust_state.rng.map_generation,
    );
    Ok(())
}

fn harness_draft(
    clock_seed: u32,
    cpp_state: &imperialism_core::GameState,
) -> Result<RandomGameDraft> {
    let nation = seeded_major_nation(clock_seed);
    if cpp_state.turn.selected_nation != nation.nation() {
        bail!(
            "C++ selected_nation {} differs from clock-seeded default {}",
            cpp_state.turn.selected_nation.get(),
            nation.get()
        );
    }
    if cpp_state.turn.difficulty != HARNESS_DIFFICULTY {
        bail!(
            "C++ difficulty {} differs from harness Normal difficulty {}",
            cpp_state.turn.difficulty.retail_byte(),
            HARNESS_DIFFICULTY.retail_byte()
        );
    }
    if !cpp_state.world.wraps_horizontally {
        bail!("C++ world is not the default wrapping topology");
    }
    Ok(RandomGameDraft {
        topology: DEFAULT_TOPOLOGY,
        nation,
        country_name: HARNESS_COUNTRY_NAME.to_owned(),
        difficulty: HARNESS_DIFFICULTY,
        localized_names: true,
    })
}

fn seeded_major_nation(clock_seed: u32) -> MajorNationId {
    let mut crt_rng = RetailCrtRng::from_state(clock_seed);
    MajorNationId::new((crt_rng.next_rand() % i32::from(MajorNationId::COUNT)) as u8)
}

fn draft_planet_seed(clock_seed: u32) -> String {
    let mut name_rng = RetailLcg::from_state(clock_seed);
    generate_english_random_setup_name(&mut name_rng)
}
