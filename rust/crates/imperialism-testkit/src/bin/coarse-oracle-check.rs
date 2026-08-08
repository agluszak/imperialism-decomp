use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_testkit::{generate_and_compare_coarse_trace, read_coarse_map_trace};
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    /// Native runtime result containing a coarse_map_generation capture.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let oracle = read_coarse_map_trace(&options.result)
        .with_context(|| format!("could not read {}", options.result.display()))?;
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
