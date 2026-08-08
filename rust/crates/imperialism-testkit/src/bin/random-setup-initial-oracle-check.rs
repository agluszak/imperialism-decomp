#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_core::{
    MajorNationId, RetailCrtRng, RetailLcg, RetailTopologyByte,
    differential_trace::RandomMapTerrainCapture, generate_english_random_setup_name,
    generate_random_map, generate_random_setup_preview,
};
use imperialism_testkit::{
    RandomGameSetupCapture, generate_and_compare_terrain_capture, read_random_game_setup,
    read_runtime_capture, read_runtime_seed,
};
use std::path::{Path, PathBuf};

const DEFAULT_TOPOLOGY: RetailTopologyByte = RetailTopologyByte::from_wraps_horizontally(true);

#[derive(Debug, Parser)]
#[command(about = "Validate native initial random-game setup defaults")]
struct Options {
    /// Native runtime result containing random_game_setup and random_map_terrain captures.
    result: PathBuf,
}

fn main() -> Result<()> {
    check_initial_setup(&Options::parse().result)
}

fn check_initial_setup(result: &Path) -> Result<()> {
    let clock_seed = read_runtime_seed(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let setup = read_random_game_setup(result)
        .with_context(|| format!("could not read {}", result.display()))?;
    let expected = initial_defaults(clock_seed);
    validate_setup(&setup, &expected)?;

    let terrain: RandomMapTerrainCapture = read_runtime_capture(result, "random_map_terrain")
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
        "initial random-game setup matched: clock_seed={} planet={:?} topology={} nation={} country={:?} difficulty={} localized_names={} tiles={} provinces={} final={:08x}",
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
        difficulty: 0,
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
            "initial difficulty {} differs from retail default {}",
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
                difficulty: 0,
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
