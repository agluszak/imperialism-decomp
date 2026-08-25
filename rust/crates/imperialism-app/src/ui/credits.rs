use super::generated;
use super::hover_help::ui_string;
use super::retail::{RetailTree, RetailUiAssets};
use super::window::ModalWindow;
use crate::AppState;
use crate::media::{MusicDirector, play_credits_music, play_host_screen_music};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_formats::{RetailTextStylePreset, fourcc};

#[derive(Component)]
struct CreditsRoot {
    second_page: bool,
}

pub(crate) struct CreditsPlugin;

impl Plugin for CreditsPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, bind_credits)
            .add_systems(
                Update,
                sync_credits_page.run_if(any_with_component::<CreditsRoot>),
            )
            .add_observer(on_credits_spawned)
            .add_observer(on_credits_despawned);
    }
}

pub(crate) fn open_credits(commands: &mut Commands, host: AppState) {
    let root = commands.spawn_scene(generated::linger_4175()).id();
    commands.entity(root).insert((
        CreditsRoot { second_page: false },
        ModalWindow,
        DespawnOnExit(host),
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
    // `LoadUiStringResourceById` is LoadStringA(id); group/index form is id = group*100+index.
    ui_string(assets, string_id / 100, string_id % 100)
}

fn on_credits_activate(
    _activate: On<Activate>,
    mut roots: Query<(Entity, &mut CreditsRoot)>,
    mut commands: Commands,
) {
    let Ok((entity, mut root)) = roots.single_mut() else {
        return;
    };
    if root.second_page {
        commands.entity(entity).try_despawn();
        return;
    }
    root.second_page = true;
}

fn on_credits_spawned(
    _added: On<Add, CreditsRoot>,
    music: Option<ResMut<MusicDirector>>,
    time: Option<Res<Time>>,
) {
    let Some(mut music) = music else {
        return;
    };
    play_credits_music(&mut music, time.as_deref());
}

fn on_credits_despawned(
    _removed: On<Remove, CreditsRoot>,
    state: Res<State<AppState>>,
    music: Option<ResMut<MusicDirector>>,
    time: Option<Res<Time>>,
) {
    let Some(mut music) = music else {
        return;
    };
    play_host_screen_music(&mut music, *state.get(), time.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_credits_despawns_the_overlay_and_keeps_the_host_screen() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::StrategicMap)
            .add_observer(on_credits_activate);
        let root = app
            .world_mut()
            .spawn(CreditsRoot { second_page: true })
            .id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: root });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert!(app.world().get_entity(root).is_err());
    }
}
