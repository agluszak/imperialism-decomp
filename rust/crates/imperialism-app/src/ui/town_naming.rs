use crate::ui::generated;
use crate::ui::retail::{retail_text_color, retail_text_style};
use crate::ui::session::apply_turn_stop;
use crate::ui::window::{ModalCancel, ModalDefault, ModalWindow};
use crate::ui::{GameSession, RetailUiAssets};
use crate::{AppState, RetailAssetsResource};
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::EditableText;
use bevy::ui_widgets::{Activate, ActivateOnPress, SelectAllOnFocus};
use imperialism_core::ResourceTable;
use imperialism_formats::PictureId;

const ROW_HEIGHT: i32 = 0x20;
const ICON_PICTURE_BASE: i16 = 700;

#[derive(Component)]
struct TownNamingRoot;

#[derive(Component)]
struct TownNameField;

#[derive(Component)]
struct TownNamingWired;

pub(crate) struct TownNamingPlugin;

impl Plugin for TownNamingPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::TownNaming), spawn_town_naming)
            .add_systems(
                Update,
                bind_town_naming.run_if(in_state(AppState::TownNaming)),
            );
    }
}

fn spawn_town_naming(mut commands: Commands) {
    let ui = generated::spawn_mapview_3508(&mut commands);
    commands.entity(ui.root).insert((
        TownNamingRoot,
        ui,
        ModalWindow,
        DespawnOnExit(AppState::TownNaming),
    ));
}

fn bind_town_naming(
    mut commands: Commands,
    ui: Query<&generated::Mapview3508, (With<TownNamingRoot>, Without<TownNamingWired>)>,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
    retail_assets: Res<RetailAssetsResource>,
    mut session: ResMut<GameSession>,
) {
    let Ok(ui) = ui.single() else {
        return;
    };
    let Some((nation, tile)) = session.game.prepare_pending_town_naming() else {
        return;
    };
    let suggestion = retail_assets
        .string(
            0x1c52,
            i16::from(session.game.roll_pending_town_name_suggestion()),
        )
        .expect("retail town-name string");
    let yields = session.game.nations().major(nation).towns[&tile].resource_yield_by_type;
    let visible = yields.values().filter(|&&amount| amount != 0).count() as i32;
    let extra_height = visible * ROW_HEIGHT;
    for entity in [ui.wind, ui.dlog] {
        let mut node = nodes.get_mut(entity).expect("town-name chrome has Node");
        if let Val::Px(height) = node.height {
            node.height = px(height + extra_height as f32);
        }
    }
    for entity in [ui.okay, ui.cncl] {
        let mut node = nodes.get_mut(entity).expect("town-name button has Node");
        if let Val::Px(top) = node.top {
            node.top = px(top + extra_height as f32);
        }
        commands
            .entity(entity)
            .insert((ActivateOnPress, TownNamingWired))
            .observe(commit_town_name);
    }
    commands.entity(ui.okay).insert(ModalDefault);
    commands.entity(ui.cncl).insert(ModalCancel);

    commands.entity(ui.name).insert((
        TownNameField,
        AutoFocus,
        SelectAllOnFocus,
        EditableText {
            max_characters: Some(16),
            allow_newlines: false,
            ..EditableText::new(suggestion)
        },
    ));
    spawn_resource_rows(&mut commands, &mut assets, ui.dlog, yields);
    commands.entity(ui.root).insert(TownNamingWired);
}

fn spawn_resource_rows(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    parent: Entity,
    yields: ResourceTable<i16>,
) {
    let mut row = 0;
    for (resource, amount) in yields {
        if amount == 0 {
            continue;
        }
        let icon = assets
            .transparent_picture(
                PictureId::new(ICON_PICTURE_BASE + i16::from(resource.retail())),
                0x10,
            )
            .expect("retail town resource icon");
        commands
            .spawn_scene(town_resource_row(row, icon, amount))
            .insert(ChildOf(parent));
        row += 1;
    }
}

fn town_resource_row(row: i32, icon: Handle<Image>, amount: i16) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0x18), top: px(0x40 + row * ROW_HEIGHT),
            width: px(0xdc), height: px(0x10),
        }
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0), top: px(0), width: px(31), height: px(23),
                }
                template(move |_context| Ok(ImageNode::new(icon.clone())))
                Pickable::IGNORE
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0x28), top: px(0), width: px(0xb0), height: px(0x10),
                }
                template(move |_context| Ok(Text::new(amount.to_string())))
                retail_text_style(3, 0, 10, -2)
                retail_text_color(0)
                Pickable::IGNORE
            )
        ]
    }
}

fn commit_town_name(
    _activate: On<Activate>,
    field: Single<&EditableText, With<TownNameField>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    session.game.name_pending_town(field.value().to_string());
    let stop = session.game.advance_turn();
    apply_turn_stop(stop, &mut next_state);
}
