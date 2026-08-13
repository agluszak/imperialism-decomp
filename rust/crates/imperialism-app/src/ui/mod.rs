mod city;
mod city_site;
mod credits;
mod cursor;
mod deal_book;
mod diplomacy;
mod game_shell;
pub(crate) mod generated;
mod hover_help;
pub(crate) mod load_save;
mod main_menu;
mod newspaper;
mod offer_sheet;
mod preferences;
mod query_floater;
mod random_setup;
mod random_setup_map;
mod retail;
mod session;
mod strategic_map;
mod technology;
mod trade;
mod transport;

pub(crate) use city::CityPlugin;
pub(crate) use city_site::CitySitePlugin;
pub(crate) use credits::CreditsPlugin;
pub(crate) use cursor::CursorPlugin;
pub(crate) use deal_book::DealBookPlugin;
pub(crate) use diplomacy::DiplomacyPlugin;
pub(crate) use game_shell::GameShellPlugin;
pub(crate) use load_save::{LoadSavePlugin, SaveDirectory};
pub(crate) use main_menu::MainMenuPlugin;
pub(crate) use newspaper::NewspaperPlugin;
pub(crate) use offer_sheet::OfferSheetPlugin;
pub(crate) use preferences::PreferencesPlugin;
pub(crate) use query_floater::QueryFloaterPlugin;
pub(crate) use random_setup::RandomSetupPlugin;
pub(crate) use random_setup_map::MapPreviewPlugin;
pub(crate) use retail::{RetailUiAssets, RetailUiPlugin};
pub(crate) use session::GameSession;
pub(crate) use technology::TechnologyAdvancePlugin;
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
