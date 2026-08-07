#![forbid(unsafe_code)]

use imperialism_app::{ExecutableMode, load_viewer, prepare_main_menu, run_main_menu, run_viewer};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = match ExecutableMode::parse(env::args_os().skip(1)) {
        Ok(ExecutableMode::Help) => {
            println!("{}", ExecutableMode::usage());
            return ExitCode::SUCCESS;
        }
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("{error}\n\n{}", ExecutableMode::usage());
            return ExitCode::FAILURE;
        }
    };

    match mode {
        ExecutableMode::MainMenu(config) => match prepare_main_menu(&config) {
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
        },
        ExecutableMode::StateViewer(config) => match load_viewer(&config) {
            Ok(input) => {
                run_viewer(input);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("could not start strategic-map viewer: {error}");
                ExitCode::FAILURE
            }
        },
        ExecutableMode::Help => {
            unreachable!("help exits before launch dispatch")
        }
    }
}
