mod battle_reports;
mod city;
mod city_site;
mod credits;
mod cursor;
mod deal_book;
mod diplomacy;
mod endgame;
mod game_shell;
pub(crate) mod generated;
mod hover_help;
mod land_battle;
mod linger;
pub(crate) mod load_save;
mod main_menu;
mod map_help;
mod naval_battle;
mod newspaper;
mod offer_sheet;
mod preferences;
mod query_floater;
mod random_setup;
mod random_setup_map;
mod retail;
mod retail_palette;
mod retail_raster;
mod satellite_preview;
mod session;
mod strategic_map;
mod technology;
mod technology_store;
#[cfg(test)]
mod test_support;
mod trade;
mod transport;
mod viewport;

pub(crate) use battle_reports::BattleReportPlugin;
pub(crate) use city::CityPlugin;
pub(crate) use city_site::CitySitePlugin;
pub(crate) use credits::CreditsPlugin;
pub(crate) use cursor::CursorPlugin;
pub(crate) use deal_book::DealBookPlugin;
pub(crate) use diplomacy::DiplomacyPlugin;
pub(crate) use endgame::EndgamePlugin;
pub(crate) use game_shell::GameShellPlugin;
pub(crate) use land_battle::LandBattlePlugin;
pub(crate) use load_save::{LoadSavePlugin, SaveDirectory};
pub(crate) use main_menu::MainMenuPlugin;
pub(crate) use naval_battle::NavalBattlePlugin;
pub(crate) use newspaper::NewspaperPlugin;
pub(crate) use offer_sheet::OfferSheetPlugin;
pub(crate) use preferences::{GamePreferences, PreferencesPlugin};
pub(crate) use query_floater::QueryFloaterPlugin;
pub(crate) use random_setup::RandomSetupPlugin;
pub(crate) use random_setup_map::MapPreviewPlugin;
pub(crate) use retail::{RetailUiAssets, RetailUiPlugin};
pub(crate) use session::GameSession;
pub(crate) use technology::TechnologyAdvancePlugin;
pub(crate) use technology_store::TechnologyStorePlugin;
pub(crate) use trade::TradePlugin;
pub(crate) use transport::TransportPlugin;
pub(crate) use viewport::RetailViewportPlugin;

use bevy::prelude::{DetectChanges, Res};

pub(in crate::ui) fn projection_idle(session: &Res<GameSession>, added: bool) -> bool {
    !session.is_changed() && !added
}

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

pub(in crate::ui) fn fill_brackets(template: &str, args: &[&str]) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '[' {
            let mut scan = index + 1;
            while scan < chars.len() && chars[scan] != ']' && !chars[scan].is_ascii_digit() {
                scan += 1;
            }
            if scan < chars.len() && chars[scan].is_ascii_digit() {
                let slot = (chars[scan] as u8 - b'0') as usize;
                if slot >= 1 && slot <= args.len() {
                    out.push_str(args[slot - 1]);
                }
                while scan < chars.len() && chars[scan] != ']' {
                    scan += 1;
                }
                index = scan.saturating_add(1);
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}
