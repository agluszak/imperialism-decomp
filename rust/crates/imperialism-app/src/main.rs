#![forbid(unsafe_code)]

use clap::Parser;
use imperialism_app::{MainMenuConfig, prepare_main_menu, run_main_menu};
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = MainMenuConfig::parse();

    match prepare_main_menu(&config) {
        Ok(prepared) => match run_main_menu(prepared) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("could not construct main menu: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("could not prepare main menu: {error}");
            ExitCode::FAILURE
        }
    }
}
