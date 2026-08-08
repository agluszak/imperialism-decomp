mod runtime;
mod startup;

pub(crate) use runtime::UiCatalogResource;
pub use runtime::{
    DespawnUiView, InteractiveUiWidget, PresentedUiNode, PresentedViewId, SpawnUiView, UiIntent,
    UiPictureLookup, UiRuntimePlugin, UiRuntimeSet, UiViewRoot, UiViewSpawned, UiWidgetFlags,
    ViewInstanceId, WidgetTag,
};
pub use startup::{
    Difficulty, RandomGameSetup, StartupScreenInstances, StartupUiPlugin, main_menu_view_id,
    random_setup_view_id,
};
