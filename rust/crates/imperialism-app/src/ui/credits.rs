use super::generated;
use super::hover_help::retail_string;
use super::retail::{RetailTree, RetailUiAssets};
use crate::{AppState, ReturnTo};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_formats::{RetailTextStylePreset, StringResourceId, fourcc};

#[derive(Component)]
struct CreditsRoot {
    second_page: bool,
}

pub(crate) struct CreditsPlugin;

impl Plugin for CreditsPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::Credits),
            (spawn_credits, bind_credits).chain(),
        )
        .add_systems(
            Update,
            sync_credits_page.run_if(in_state(AppState::Credits)),
        )
        .add_systems(OnExit(AppState::Credits), super::session::clear_return_to);
    }
}

fn spawn_credits(mut commands: Commands) {
    let root = commands.spawn_scene(generated::linger_4175()).id();
    commands.entity(root).insert((
        CreditsRoot { second_page: false },
        DespawnOnExit(AppState::Credits),
    ));
}

fn bind_credits(
    mut commands: Commands,
    root: Single<Entity, Added<CreditsRoot>>,
    tree: RetailTree,
) {
    commands
        .entity(tree.find(*root, fourcc!("main")))
        .insert((Button, ActivateOnPress))
        .observe(on_credits_activate)
        .remove::<InteractionDisabled>();
}

fn sync_credits_page(
    mut commands: Commands,
    roots: Query<(Entity, &CreditsRoot), Changed<CreditsRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    for (root, screen) in &roots {
        fill_credits_page(&mut commands, &mut assets, root, &tree, screen.second_page);
    }
}

fn fill_credits_page(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    second_page: bool,
) {
    // `TCreditsPicture::SetTextFromUiStringResourceId`: LoadStringA ids 0xfb0..0xfb3.
    let (left_id, right_id) = if second_page {
        (0xfb2, 0xfb3)
    } else {
        (0xfb0, 0xfb1)
    };
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail credits text style");
    let color = TextColor(assets.palette_color(0x13));
    let shadow = second_page.then_some(TextShadow {
        offset: Vec2::ONE,
        color: assets.palette_color(0xd2),
    });
    for (tag, string_id) in [(fourcc!("cred"), left_id), (fourcc!("cre2"), right_id)] {
        let mut entity = commands.entity(tree.find(root, tag));
        entity.insert((
            Text::new(string_from_id(assets, string_id)),
            font.clone(),
            layout,
            line_height,
            color,
        ));
        if let Some(shadow) = shadow {
            entity.insert(shadow);
        } else {
            entity.remove::<TextShadow>();
        }
    }
}

fn string_from_id(assets: &RetailUiAssets, string_id: i16) -> String {
    // `LoadUiStringResourceById` is LoadStringA(id); the flat id is the final resource id.
    retail_string(assets, StringResourceId::new(string_id as u32))
}

fn on_credits_activate(
    _activate: On<Activate>,
    mut roots: Query<&mut CreditsRoot>,
    returning: Res<ReturnTo>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(mut root) = roots.single_mut() else {
        return;
    };
    if root.second_page {
        next_state.set(returning.0);
        return;
    }
    root.second_page = true;
}
