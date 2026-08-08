#![forbid(unsafe_code)]

use imperialism_app::{MainMenuConfig, prepare_main_menu, run_main_menu};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match MainMenuConfig::parse(env::args_os().skip(1)) {
        Ok(None) => {
            println!("{}", MainMenuConfig::usage());
            return ExitCode::SUCCESS;
        }
        Ok(Some(config)) => config,
        Err(error) => {
            eprintln!("{error}\n\n{}", MainMenuConfig::usage());
            return ExitCode::FAILURE;
        }
    };

    match prepare_main_menu(&config) {
        Ok(prepared) => {
            run_main_menu(prepared);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not prepare main menu: {error}");
            ExitCode::FAILURE
        }
    }
}
