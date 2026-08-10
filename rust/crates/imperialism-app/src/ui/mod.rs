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
pub(crate) use random_setup::RandomSetupPlugin;
pub(crate) use random_setup_map::MapPreviewPlugin;
pub(crate) use trade::TradePlugin;
pub(crate) use transport::TransportPlugin;

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    main_menu::validate_application_bindings(catalog)?;
    random_setup::validate_application_bindings(catalog)?;
    random_setup_map::validate_application_bindings(catalog)?;
    city_site::validate_application_bindings(catalog)?;
    city::validate_application_bindings(catalog)?;
    transport::validate_application_bindings(catalog)?;
    trade::validate_application_bindings(catalog)?;
    diplomacy::validate_application_bindings(catalog)?;
    game_shell::validate_application_bindings(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{UiCatalog, UiNodeId, fourcc};

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    #[test]
    fn embedded_catalog_contains_all_application_bindings() {
        let catalog = UiCatalogResource::new(catalog()).unwrap();
        validate_application_bindings(&catalog).unwrap();
    }

    #[test]
    fn required_application_tags_must_be_unambiguous() {
        let mut catalog = catalog();
        let view = catalog
            .views
            .iter_mut()
            .find(|view| view.id == main_menu::main_menu_view_id())
            .unwrap();
        let mut duplicate = view
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("rand"))
            .unwrap()
            .clone();
        duplicate.id = UiNodeId(view.nodes.iter().map(|node| node.id.0).max().unwrap() + 1);
        view.nodes.push(duplicate);

        let catalog = UiCatalogResource::new(catalog).unwrap();
        assert!(validate_application_bindings(&catalog).is_err());
    }
}
