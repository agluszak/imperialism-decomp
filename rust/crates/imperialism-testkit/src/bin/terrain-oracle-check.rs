use anyhow::{Context, Result};
use clap::Parser;
use imperialism_core::differential_trace::RandomMapTerrainCapture;
use imperialism_testkit::{generate_and_compare_terrain_capture, read_runtime_capture};
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    /// Native runtime result.json containing the random-map terrain capture.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let capture: RandomMapTerrainCapture =
        read_runtime_capture(&options.result, "random_map_terrain")
            .with_context(|| format!("could not read {}", options.result.display()))?;
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
