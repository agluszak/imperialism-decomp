use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::{
    AmountBarParts, AmountBarStyle, PlacardParts, RetailTree, RetailUiAssets, apply_amount_bar_fill,
    placard_text_layout,
};
use super::retail_amount_bar::{amount_bar_counter_offset, amount_bar_geometry};
use super::window::{
    CaptionedWindow, ModalWindow, bind_modal_keys, dismiss_on_activate, set_window_position,
    window_position,
};
use super::{CityWindows, GameSession};
use crate::{AppState, RetailAssetsResource, RetailFonts};
use bevy::ecs::system::SystemParam;
use bevy::log::warn;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled, RelativeCursorPosition};
use bevy::ui_widgets::{Activate, ValueChange};
use enum_map::Enum;
use imperialism_core::*;
use imperialism_formats::*;
use std::time::Duration;

mod building_visuals;
mod dialogs;
mod lifecycle;
use building_visuals::*;
pub(super) use building_visuals::{CityBuildingActionVisual, CityBuildingVisual};
use dialogs::*;
use lifecycle::*;

const CITY_BUILDING_STRING_GROUP: i16 = 0x2719;
const CITY_TEXT_STRING_GROUP: i16 = 0x2738;

fn city_string(assets: &RetailUiAssets, group: i16, zero_based_index: i16) -> String {
    assets
        .string(group, city_string_index(zero_based_index))
        .expect("city string")
}

const fn city_string_index(zero_based_index: i16) -> i16 {
    zero_based_index + 1
}

fn format_retail_number(template: &str, value: i16) -> String {
    fill_brackets(template, &[&value.to_string()])
}

#[derive(SystemParam)]
struct CityUi<'w, 's> {
    commands: Commands<'w, 's>,
    texts: Query<'w, 's, &'static mut Text>,
    colors: Query<'w, 's, &'static mut TextColor>,
    visibility: Query<'w, 's, &'static mut Visibility>,
    images: Query<'w, 's, &'static mut ImageNode>,
    checked: Query<'w, 's, Has<Checked>>,
    nodes: Query<'w, 's, &'static mut Node>,
    amount_bars: Query<'w, 's, &'static AmountBarParts>,
    placard_parts: Query<'w, 's, &'static PlacardParts>,
}

impl CityUi<'_, '_> {
    fn text(&mut self, entity: Entity, value: impl Into<String>) {
        self.texts.get_mut(entity).expect("text").0 = value.into();
    }

    fn visible(&mut self, entity: Entity, visible: bool) {
        *self.visibility.get_mut(entity).expect("vis") = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }

    fn color(&mut self, entity: Entity, color: Color) {
        self.colors.get_mut(entity).expect("color").0 = color;
    }

    fn image(&mut self, entity: Entity, image: Handle<Image>) {
        self.images.get_mut(entity).expect("image").image = image;
    }

    fn checked(&mut self, entity: Entity, checked: bool) {
        let is_checked = self.checked.get(entity).unwrap_or(false);
        if checked && !is_checked {
            self.commands.entity(entity).insert(Checked);
        } else if !checked && is_checked {
            self.commands.entity(entity).remove::<Checked>();
        }
    }

    fn placard(&mut self, root: Entity, value: i16) {
        let shown = value != 0;
        *self.visibility.get_mut(root).expect("placard") = if shown {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        if !shown {
            return;
        }
        let text = self
            .placard_parts
            .get(root)
            .expect("placard parts")
            .text;
        let (width, height) = {
            let node = self.nodes.get(root).expect("placard node");
            let (Val::Px(width), Val::Px(height)) = (node.width, node.height) else {
                return;
            };
            (width, height)
        };
        let (left, top) = placard_text_layout(width, height, value);
        self.texts.get_mut(text).expect("placard text").0 = value.to_string();
        let mut text_node = self.nodes.get_mut(text).expect("placard text node");
        text_node.left = Val::Px(left);
        text_node.top = Val::Px(top);
    }
}

#[derive(Clone, Copy)]
struct SelectionRow(Entity, Entity);

fn sync_recruitment_row(ui: &mut CityUi, row: SelectionRow, selected: bool, quantity_text: String) {
    ui.checked(row.0, selected);
    ui.text(row.1, quantity_text);
}

fn bind_row_selection(
    commands: &mut Commands,
    tree: &RetailTree,
    root: Entity,
    row: Entity,
    button: Entity,
    select: impl Fn(&mut CityDialogView) + Copy + Send + Sync + 'static,
) {
    for tag in [fourcc!("minu"), fourcc!("plus")] {
        commands.entity(tree.find(row, tag)).observe(
            move |_: On<Activate>, mut views: Query<&mut CityDialogView>| {
                if let Ok(mut view) = views.get_mut(root) {
                    select(&mut view);
                }
            },
        );
    }
    commands.entity(button).observe(
        move |change: On<ValueChange<bool>>, mut views: Query<&mut CityDialogView>| {
            if change.value
                && let Ok(mut view) = views.get_mut(root)
            {
                select(&mut view);
            }
        },
    );
}

#[derive(Component)]
enum CityDialogView {
    Industry(IndustryUi),
    Training(TrainingUi),
    Armory(ArmoryUi),
    University(UniversityUi),
    Shipyard(ShipyardUi),
    Warehouse(WarehouseUi),
    Food(FoodUi),
    Power(RailUi),
    Transport(TransportUi),
    Population(PopulationUi),
}

pub(crate) struct CityPlugin;

impl Plugin for CityPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::City),
            (enter_city_screen, bind_city_screen).chain(),
        )
        .add_systems(OnExit(AppState::City), leave_city_screen)
        .add_systems(
            Update,
            (
                restore_city_dialogs,
                bind_building_change_dialogs,
                bind_city_dialogs,
            )
                .chain()
                .run_if(in_state(AppState::City)),
        )
        .add_systems(
            Update,
            (
                render_city_screen,
                render_city_buildings,
                render_city_dialogs,
                animate_city_building_actions,
            )
                .run_if(in_state(AppState::City)),
        );
    }
}

fn render_city_dialogs(
    session: Res<GameSession>,
    dialogs: Query<(&CityBuildingDialog, Ref<CityDialogView>)>,
    mut ui: CityUi,
    mut assets: RetailUiAssets,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
) {
    let nation = session.active_major_nation();
    let game_changed = session.is_changed();
    for (dialog, view) in &dialogs {
        let expensive = game_changed || view.is_added() || view.is_changed();
        match &*view {
            CityDialogView::Industry(v) => {
                render_industry(dialog.slot, v, &session, nation, &assets, &mut ui)
            }
            CityDialogView::Training(v) => render_training(v, &session, nation, &mut ui),
            CityDialogView::Armory(v) => render_armory(v, &session, &mut assets, &mut ui),
            CityDialogView::University(v) if expensive => {
                render_university(v, &session, &mut assets, &fonts, &font_assets, &mut ui)
            }
            CityDialogView::Shipyard(v) if expensive => {
                render_shipyard(v, &session, &mut assets, &fonts, &font_assets, &mut ui)
            }
            CityDialogView::Warehouse(v) => render_warehouse(v, &session, &mut ui),
            CityDialogView::Food(v) => render_food(v, &session, nation, &mut ui),
            CityDialogView::Power(v) => render_power(v, &session, nation, &mut ui),
            CityDialogView::Transport(v) => render_transport(v, &session, nation, &mut ui),
            CityDialogView::Population(v) => {
                render_population(v, &session, nation, &assets, &mut ui)
            }
            CityDialogView::University(_) | CityDialogView::Shipyard(_) => {}
        }
    }
}
