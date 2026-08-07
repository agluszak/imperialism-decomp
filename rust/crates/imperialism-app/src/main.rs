#![forbid(unsafe_code)]

use imperialism_app::{ViewerConfig, load_viewer, run_viewer};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match ViewerConfig::parse(env::args_os().skip(1)) {
        Ok(Some(config)) => config,
        Ok(None) => {
            println!("{}", ViewerConfig::usage());
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n\n{}", ViewerConfig::usage());
            return ExitCode::FAILURE;
        }
    };

    match load_viewer(&config) {
        Ok(input) => {
            run_viewer(input);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not start strategic-map viewer: {error}");
            ExitCode::FAILURE
        }
    }
}
