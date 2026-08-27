use imperialism_core::ResourceKind;
use imperialism_formats::{FourCc, fourcc};

/// Retail control tag for a city stockpile or production resource row.
pub(in crate::ui::city) fn resource_control_tag(resource: ResourceKind) -> FourCc {
    match resource {
        ResourceKind::Cotton => fourcc!("cott"),
        ResourceKind::Wool => fourcc!("wool"),
        ResourceKind::Timber => fourcc!("timb"),
        ResourceKind::Coal => fourcc!("coal"),
        ResourceKind::Iron => fourcc!("iron"),
        ResourceKind::Horses => fourcc!("hors"),
        ResourceKind::Oil => fourcc!("oil "),
        ResourceKind::Food => fourcc!("food"),
        ResourceKind::Fabric => fourcc!("fabr"),
        ResourceKind::Lumber => fourcc!("lumb"),
        ResourceKind::Paper => fourcc!("pape"),
        ResourceKind::Steel => fourcc!("stee"),
        ResourceKind::Fuel => fourcc!("fuel"),
        ResourceKind::Clothing => fourcc!("clot"),
        ResourceKind::Furniture => fourcc!("furn"),
        ResourceKind::Hardware => fourcc!("hard"),
        ResourceKind::Arms => fourcc!("arma"),
        ResourceKind::Grain => fourcc!("grai"),
        ResourceKind::Fruit => fourcc!("prod"),
        ResourceKind::Livestock => fourcc!("live"),
        ResourceKind::Fish | ResourceKind::Gems | ResourceKind::Gold => {
            panic!("city resource control tag requested for {resource:?}")
        }
    }
}
