use crate::ui::generated;
use crate::ui::retail::{RetailTree, retail_text_color, retail_text_style};
use crate::ui::retail_resources::ResourceKindRetailResources;
use crate::ui::session::apply_turn_stop;
use crate::ui::window::{ModalWindow, bind_modal_keys};
use crate::ui::{GameSession, RetailUiAssets};
use crate::{AppState, RetailAssetsResource};
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::EditableText;
use bevy::ui_widgets::{Activate, ActivateOnPress, SelectAllOnFocus};
use imperialism_core::ResourceTable;
use imperialism_formats::fourcc;

const ROW_HEIGHT: i32 = 0x20;

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
    let root = commands.spawn_scene(generated::mapview_3508()).id();
    commands.entity(root).insert((
        TownNamingRoot,
        ModalWindow,
        DespawnOnExit(AppState::TownNaming),
    ));
}

fn bind_town_naming(
    mut commands: Commands,
    roots: Query<Entity, (With<TownNamingRoot>, Without<TownNamingWired>)>,
    tree: RetailTree,
    children: Query<&Children>,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
    retail_assets: Res<RetailAssetsResource>,
    mut session: ResMut<GameSession>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    if !children
        .get(root)
        .is_ok_and(|children| !children.is_empty())
    {
        return;
    }
    let Some((nation, tile)) = session.game.prepare_pending_town_naming() else {
        return;
    };
    let suggestion = retail_assets.ui_string(
        0x1c52,
        u16::from(session.game.roll_pending_town_name_suggestion()),
    );
    let yields = session.game.nations().major(nation).towns[&tile].resource_yield_by_type;
    let visible = yields.values().filter(|&&amount| amount != 0).count() as i32;
    let extra_height = visible * ROW_HEIGHT;
    for tag in [fourcc!("WIND"), fourcc!("DLOG")] {
        let mut node = nodes
            .get_mut(tree.find(root, tag))
            .expect("town-name chrome has Node");
        if let Val::Px(height) = node.height {
            node.height = px(height + extra_height as f32);
        }
    }
    for tag in [fourcc!("okay"), fourcc!("cncl")] {
        let entity = tree.find(root, tag);
        let mut node = nodes.get_mut(entity).expect("town-name button has Node");
        if let Val::Px(top) = node.top {
            node.top = px(top + extra_height as f32);
        }
        commands
            .entity(entity)
            .insert((ActivateOnPress, TownNamingWired))
            .observe(commit_town_name);
    }
    bind_modal_keys(
        &mut commands,
        root,
        Some(tree.find(root, fourcc!("okay"))),
        Some(tree.find(root, fourcc!("cncl"))),
    );

    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert((
        TownNameField,
        AutoFocus,
        SelectAllOnFocus,
        EditableText {
            max_characters: Some(16),
            allow_newlines: false,
            ..EditableText::new(suggestion)
        },
    ));
    spawn_resource_rows(
        &mut commands,
        &mut assets,
        tree.find(root, fourcc!("DLOG")),
        yields,
    );
    commands.entity(root).insert(TownNamingWired);
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
        let icon = assets.transparent_picture(resource.material_picture(), 0x10);
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
