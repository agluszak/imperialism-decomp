//! Oracle check commands shared by the `imperialism-oracle` binary.

use anyhow::{Context, Result, bail};
use imperialism_core::{
    Difficulty, GameState, MajorNationId, RetailCrtRng, RetailLcg, RetailTopologyByte,
    create_random_game, differential_trace::RandomMapTerrainCapture,
    generate_english_random_setup_name, generate_random_map, generate_random_setup_preview,
};
use std::path::Path;

use crate::{
    RandomGameSetupCapture, RandomGameStartBoundarySubset, RuntimeResult, assert_game_state_eq,
    first_serialized_difference, generate_and_compare_coarse_trace,
    generate_and_compare_terrain_capture,
};

const DEFAULT_TOPOLOGY: RetailTopologyByte = RetailTopologyByte::from_wraps_horizontally(true);

pub fn check_coarse(result: &Path) -> Result<()> {
    let runtime = RuntimeResult::read(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let oracle = runtime
        .capture("coarse_map_generation")
        .with_context(|| format!("could not read {}", result.display()))?;
    let trace = generate_and_compare_coarse_trace(&oracle).map_err(|difference| {
        anyhow::anyhow!(
            "coarse oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    if trace.attempts.is_empty() {
        bail!("coarse generation produced no attempts");
    }
    let attempts = trace
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "{:08x}/{}",
                attempt.pre_validation_grid.fnv1a_hash(),
                attempt.draw_count
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "coarse oracle matched: initial={:08x} attempts={} [{}] accepted={:08x} expanded_tiles={} expanded_provinces={}",
        trace.initial_map_lcg,
        trace.attempts.len(),
        attempts,
        trace.accepted_grid.fnv1a_hash(),
        trace.expanded_tiles.len(),
        trace.expanded_provinces.len(),
    );
    Ok(())
}

pub fn check_terrain(result: &Path) -> Result<()> {
    let runtime = RuntimeResult::read(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let capture: RandomMapTerrainCapture = runtime
        .capture("random_map_terrain")
        .with_context(|| format!("could not read {}", result.display()))?;
    let trace = generate_and_compare_terrain_capture(&capture).map_err(|difference| {
        anyhow::anyhow!(
            "terrain oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    let final_attempt = trace.attempts.last().expect("accepted terrain attempt");
    println!(
        "terrain oracle matched: tag={:?} initial={:08x} attempts={} templates={:08x} features={:08x} water={:08x} keyword={:08x} final={:08x}",
        capture.scenario_tag,
        trace.initial_map_lcg,
        trace.attempts.len(),
        final_attempt.after_templates.map_lcg,
        final_attempt.after_features.map_lcg,
        final_attempt.after_water_regions.map_lcg,
        final_attempt.after_keyword.map_lcg,
        trace.final_map_lcg,
    );
    Ok(())
}

pub fn check_random_setup(result: &Path) -> Result<()> {
    let runtime = RuntimeResult::read(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let setup: RandomGameSetupCapture = runtime
        .capture("random_game_setup")
        .with_context(|| format!("could not read {}", result.display()))?;
    let preview = generate_random_setup_preview(setup.planet_seed.as_bytes(), setup.topology)
        .with_context(|| {
            format!(
                "could not replay the explicit setup seed {:?}",
                setup.planet_seed
            )
        })?;
    let terrain: RandomMapTerrainCapture = runtime
        .capture("random_map_terrain")
        .with_context(|| format!("could not read {}", result.display()))?;

    if terrain.scenario_tag != setup.planet_seed {
        bail!(
            "random-game setup seed {:?} differs from terrain capture seed {:?}",
            setup.planet_seed,
            terrain.scenario_tag
        );
    }
    if terrain.retail_topology != setup.topology {
        bail!(
            "random-game setup topology {} differs from terrain capture topology {}",
            setup.topology.retail_byte(),
            terrain.retail_topology.retail_byte()
        );
    }

    let trace = generate_and_compare_terrain_capture(&terrain).map_err(|difference| {
        anyhow::anyhow!(
            "terrain oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    let accepted = trace
        .attempts
        .last()
        .context("terrain capture contains no accepted map attempt")?;
    if preview.final_map_lcg != trace.final_map_lcg {
        bail!(
            "random-game setup preview final LCG {:08x} differs from terrain capture {:08x}",
            preview.final_map_lcg,
            trace.final_map_lcg
        );
    }
    if preview.map.seed_candidate_tiles != accepted.seed_candidate_tiles {
        bail!("random-game setup preview seed candidates differ from terrain capture");
    }

    println!(
        "random-game setup matched: seed={:?} topology={} nation={} country={:?} difficulty={:?} localized_names={} tiles={} provinces={} final={:08x}",
        setup.planet_seed,
        setup.topology.retail_byte(),
        setup.nation.get(),
        setup.country_name,
        setup.difficulty,
        setup.localized_names,
        preview.map.tiles.len(),
        preview.map.provinces.len(),
        preview.final_map_lcg,
    );
    Ok(())
}

pub fn check_random_setup_initial(result: &Path) -> Result<()> {
    let runtime = RuntimeResult::read(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let clock_seed = runtime.seed;
    let setup: RandomGameSetupCapture = runtime
        .capture("random_game_setup")
        .with_context(|| format!("could not read {}", result.display()))?;
    let expected = initial_defaults(clock_seed);
    validate_setup(&setup, &expected)?;

    let terrain: RandomMapTerrainCapture = runtime
        .capture("random_map_terrain")
        .with_context(|| format!("could not read {}", result.display()))?;
    if terrain.scenario_tag != expected.planet_seed {
        bail!(
            "random-game setup seed {:?} differs from terrain capture seed {:?}",
            expected.planet_seed,
            terrain.scenario_tag
        );
    }
    if terrain.retail_topology != expected.topology {
        bail!(
            "random-game setup topology {} differs from terrain capture topology {}",
            expected.topology.retail_byte(),
            terrain.retail_topology.retail_byte()
        );
    }

    let preview = generate_random_setup_preview(expected.planet_seed.as_bytes(), expected.topology)
        .context("could not replay the generated initial setup seed")?;
    let trace = generate_and_compare_terrain_capture(&terrain).map_err(|difference| {
        anyhow::anyhow!(
            "terrain oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    let mut terrain_rng = RetailLcg::from_state(terrain.generation.initial_map_lcg);
    let terrain_map = generate_random_map(
        terrain.scenario_tag.as_bytes(),
        terrain.retail_topology,
        &mut terrain_rng,
    );
    if preview.map != terrain_map {
        bail!("initial random-game setup preview map differs from terrain capture replay");
    }
    if preview.final_map_lcg != terrain_rng.state() {
        bail!(
            "initial random-game setup preview final LCG {:08x} differs from terrain replay {:08x}",
            preview.final_map_lcg,
            terrain_rng.state()
        );
    }
    if preview.final_map_lcg != trace.final_map_lcg {
        bail!(
            "initial random-game setup preview final LCG {:08x} differs from terrain capture {:08x}",
            preview.final_map_lcg,
            trace.final_map_lcg
        );
    }

    println!(
        "initial random-game setup matched: clock_seed={} planet={:?} topology={} nation={} country={:?} difficulty={:?} localized_names={} tiles={} provinces={} final={:08x}",
        clock_seed,
        setup.planet_seed,
        setup.topology.retail_byte(),
        setup.nation.get(),
        setup.country_name,
        setup.difficulty,
        setup.localized_names,
        preview.map.tiles.len(),
        preview.map.provinces.len(),
        preview.final_map_lcg,
    );
    Ok(())
}

/// Compare `create_random_game` against a native pre-capital `game_state` capture
/// using the allowlisted [`RandomGameStartBoundarySubset`].
pub fn check_random_game_start(result: &Path) -> Result<()> {
    let runtime = RuntimeResult::read(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let setup: RandomGameSetupCapture = runtime
        .capture("random_game_setup")
        .with_context(|| format!("could not read {}", result.display()))?;
    if setup.difficulty != Difficulty::Normal
        && setup.difficulty != Difficulty::Hard
        && setup.difficulty != Difficulty::NighOnImpossible
    {
        bail!(
            "random_game_normal_start oracle expects a Normal+ setup, got {:?}",
            setup.difficulty
        );
    }

    let preview = generate_random_setup_preview(setup.planet_seed.as_bytes(), setup.topology)
        .with_context(|| {
            format!(
                "could not replay the explicit setup seed {:?}",
                setup.planet_seed
            )
        })?;
    let actual = create_random_game(&preview, setup.nation, setup.difficulty, runtime.seed);
    let expected: GameState = runtime
        .capture("game_state")
        .with_context(|| format!("could not read {}", result.display()))?;

    let expected_subset = RandomGameStartBoundarySubset::from_game_state(&expected);
    let actual_subset = RandomGameStartBoundarySubset::from_game_state(&actual);
    assert_game_state_eq(
        &expected_subset.into_comparable(),
        &actual_subset.into_comparable(),
    )?;

    println!(
        "random-game start boundary matched allowlisted blocks: seed={:?} topology={} nation={} difficulty={:?} tiles={} map_lcg={:#x}",
        setup.planet_seed,
        setup.topology.retail_byte(),
        setup.nation.get(),
        setup.difficulty,
        actual.world.tiles.len(),
        actual.rng.map_generation.state(),
    );
    Ok(())
}

pub fn check_snapshot(result: &Path, comparison: Option<&Path>) -> Result<()> {
    let state: GameState = RuntimeResult::read(result)
        .with_context(|| format!("reading game state {}", result.display()))?
        .capture("game_state")
        .with_context(|| format!("reading game state {}", result.display()))?;
    println!(
        "{} tiles, {} nations, {} cities, {} military units, {} civilian units, {} ships, {} missions",
        state.world.tiles.len(),
        state.nations.majors.iter().flatten().count()
            + state.nations.minors.iter().flatten().count(),
        state
            .nations
            .majors
            .iter()
            .flatten()
            .filter(|major| major.city.is_some())
            .count(),
        state.military_units.len(),
        state.civilian_units.len(),
        state.ships.len(),
        state.missions.len()
    );
    if let Some(comparison_path) = comparison {
        let comparison: GameState = RuntimeResult::read(comparison_path)
            .with_context(|| {
                format!(
                    "reading comparison game state {}",
                    comparison_path.display()
                )
            })?
            .capture("game_state")
            .with_context(|| {
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

fn initial_defaults(clock_seed: u32) -> RandomGameSetupCapture {
    let mut crt_rng = RetailCrtRng::from_state(clock_seed);
    let nation = MajorNationId::new((crt_rng.next_rand() % i32::from(MajorNationId::COUNT)) as u8);

    let mut name_rng = RetailLcg::from_state(clock_seed);
    let planet_seed = generate_english_random_setup_name(&mut name_rng);
    let country_name = generate_english_random_setup_name(&mut name_rng);

    RandomGameSetupCapture {
        planet_seed,
        topology: DEFAULT_TOPOLOGY,
        nation,
        country_name,
        difficulty: Difficulty::Introductory,
        localized_names: true,
    }
}

fn validate_setup(
    actual: &RandomGameSetupCapture,
    expected: &RandomGameSetupCapture,
) -> Result<()> {
    if actual.planet_seed != expected.planet_seed {
        bail!(
            "initial planet seed {:?} differs from retail default {:?}",
            actual.planet_seed,
            expected.planet_seed
        );
    }
    if actual.topology != expected.topology {
        bail!(
            "initial topology {} differs from retail default {}",
            actual.topology.retail_byte(),
            expected.topology.retail_byte()
        );
    }
    if actual.nation != expected.nation {
        bail!(
            "initial nation {} differs from retail default {}",
            actual.nation.get(),
            expected.nation.get()
        );
    }
    if actual.country_name != expected.country_name {
        bail!(
            "initial country name {:?} differs from retail default {:?}",
            actual.country_name,
            expected.country_name
        );
    }
    if actual.difficulty != expected.difficulty {
        bail!(
            "initial difficulty {:?} differs from retail default {:?}",
            actual.difficulty,
            expected.difficulty
        );
    }
    if actual.localized_names != expected.localized_names {
        bail!(
            "initial localized-names setting {} differs from retail default {}",
            actual.localized_names,
            expected.localized_names
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_the_seed_one_initial_defaults() {
        assert_eq!(
            initial_defaults(1),
            RandomGameSetupCapture {
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_retail_byte(0),
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: Difficulty::Introductory,
                localized_names: true,
            }
        );
    }

    #[test]
    fn seed_one_initial_preview_reaches_the_native_final_state() {
        let setup = initial_defaults(1);
        let preview =
            generate_random_setup_preview(setup.planet_seed.as_bytes(), setup.topology).unwrap();
        assert_eq!(preview.map.tiles.len(), 6_480);
        assert_eq!(preview.map.provinces.len(), 120);
        assert_eq!(preview.final_map_lcg, 0x8c98_13e1);
    }
}
