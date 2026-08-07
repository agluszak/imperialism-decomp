use anyhow::{Context, Result};
use clap::Parser;
use imperialism_testkit::{generate_and_compare_terrain_oracle, read_generated_world_terrain};
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    /// Native runtime result.json containing GeneratedWorldV1 terrain-generation evidence.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let oracle = read_generated_world_terrain(&options.result)
        .with_context(|| format!("could not read {}", options.result.display()))?;
    let generation = generate_and_compare_terrain_oracle(&oracle).map_err(|difference| {
        anyhow::anyhow!(
            "terrain oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    let final_attempt = generation
        .attempts
        .last()
        .expect("accepted terrain attempt");
    println!(
        "terrain oracle matched: tag={:?} initial={:08x} attempts={} templates={:08x} features={:08x} water={:08x} keyword={:08x} final={:08x}",
        oracle.scenario_tag,
        generation.initial_map_lcg,
        generation.attempts.len(),
        final_attempt.after_templates.map_lcg,
        final_attempt.after_features.map_lcg,
        final_attempt.after_water_regions.map_lcg,
        final_attempt.after_keyword.map_lcg,
        generation.final_map_lcg,
    );
    Ok(())
}
