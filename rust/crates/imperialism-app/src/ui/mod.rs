mod catalog;
mod city;
mod city_site;
mod diplomacy;
mod game_shell;
mod main_menu;
mod random_setup;
mod random_setup_map;
mod strategic_map;
mod trade;
mod transport;

pub(crate) use catalog::{UiCatalogPlugin, UiCatalogResource};
pub(crate) use city::CityPlugin;
pub(crate) use city_site::CitySitePlugin;
pub(crate) use diplomacy::DiplomacyPlugin;
pub(crate) use game_shell::GameShellPlugin;
pub(crate) use main_menu::MainMenuPlugin;
pub(crate) use random_setup::GameSession;
pub(crate) use random_setup::RandomSetupPlugin;
pub(crate) use random_setup_map::MapPreviewPlugin;
pub(crate) use trade::TradePlugin;
pub(crate) use transport::TransportPlugin;

#[cfg(test)]
mod tests {
    use imperialism_formats::UiCatalog;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    #[test]
    fn embedded_catalog_parses() {
        serde_json::from_str::<UiCatalog>(CATALOG_JSON)
            .expect("the embedded UI catalog must deserialize");
    }
}
