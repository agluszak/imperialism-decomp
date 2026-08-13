mod city;
mod city_site;
mod diplomacy;
mod game_shell;
pub(crate) mod generated;
mod hover_help;
mod main_menu;
mod random_setup;
mod random_setup_map;
mod retail;
mod strategic_map;
mod trade;
mod transport;

pub(crate) use city::CityPlugin;
pub(crate) use city_site::CitySitePlugin;
pub(crate) use diplomacy::DiplomacyPlugin;
pub(crate) use game_shell::GameShellPlugin;
pub(crate) use main_menu::MainMenuPlugin;
pub(crate) use random_setup::GameSession;
pub(crate) use random_setup::RandomSetupPlugin;
pub(crate) use random_setup_map::MapPreviewPlugin;
pub(crate) use retail::{RetailUiAssets, RetailUiPlugin};
pub(crate) use trade::TradePlugin;
pub(crate) use transport::TransportPlugin;

pub(in crate::ui) fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}
