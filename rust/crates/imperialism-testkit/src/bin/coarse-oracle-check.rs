use anyhow::{Context, Result, bail};
use clap::Parser;
use imperialism_testkit::{generate_and_compare_coarse_capture, read_coarse_map_generation};
use std::path::PathBuf;

#[derive(Parser)]
struct Options {
    /// Native runtime result containing a coarse_map_generation capture.
    result: PathBuf,
}

fn main() -> Result<()> {
    let options = Options::parse();
    let oracle = read_coarse_map_generation(&options.result)
        .with_context(|| format!("could not read {}", options.result.display()))?;
    let generation = generate_and_compare_coarse_capture(&oracle).map_err(|difference| {
        anyhow::anyhow!(
            "coarse oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    if generation.attempts.is_empty() {
        bail!("coarse generation produced no attempts");
    }
    let attempts = generation
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
        generation.initial_map_lcg,
        generation.attempts.len(),
        attempts,
        generation.accepted_grid.fnv1a_hash(),
        generation.expanded_tiles.len(),
        generation.expanded_provinces.len(),
    );
    Ok(())
}
