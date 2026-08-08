#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_core::{
    differential_trace::RandomMapTerrainCapture, generate_random_setup_preview,
};
use imperialism_testkit::{
    generate_and_compare_terrain_capture, read_random_game_setup, read_runtime_capture,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(about = "Validate a native random-game setup preview")]
struct Options {
    /// Native runtime result containing random_game_setup and random_map_terrain captures.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let setup = read_random_game_setup(&options.result)
        .with_context(|| format!("could not read {}", options.result.display()))?;
    let preview = generate_random_setup_preview(setup.planet_seed.as_bytes(), setup.topology)
        .with_context(|| {
            format!(
                "could not replay the explicit setup seed {:?}",
                setup.planet_seed
            )
        })?;
    let terrain: RandomMapTerrainCapture =
        read_runtime_capture(&options.result, "random_map_terrain")
            .with_context(|| format!("could not read {}", options.result.display()))?;

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
