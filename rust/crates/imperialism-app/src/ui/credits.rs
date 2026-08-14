use super::generated;
use super::hover_help::ui_string;
use super::retail::{RetailTag, RetailUiAssets, find_descendant};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_formats::{RetailTextStylePreset, fourcc};

/// Screen restored when credits close. Retail `EnterOptionalPhase(0x71)` posts
/// `kTurnEventCredits` and later `StartNextPhase` redisplays the previous phase.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CreditsReturn(pub(crate) AppState);

#[derive(Component)]
struct CreditsRoot {
    second_page: bool,
}

#[derive(Component)]
struct CreditsAction;

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
        .add_observer(on_credits_activate.run_if(in_state(AppState::Credits)));
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
    children: Query<&Children>,
    tags: Query<&RetailTag>,
) {
    commands
        .entity(find_descendant(*root, fourcc!("main"), &children, &tags))
        .insert((CreditsAction, Button, ActivateOnPress))
        .remove::<InteractionDisabled>();
}

fn sync_credits_page(
    mut commands: Commands,
    roots: Query<(Entity, &CreditsRoot), Changed<CreditsRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    for (root, screen) in &roots {
        fill_credits_page(
            &mut commands,
            &mut assets,
            root,
            &children,
            &tags,
            screen.second_page,
        );
    }
}

fn fill_credits_page(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
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
        let mut entity = commands.entity(find_descendant(root, tag, children, tags));
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
    activate: On<Activate>,
    actions: Query<&CreditsAction>,
    mut roots: Query<&mut CreditsRoot>,
    returning: Res<CreditsReturn>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if actions.get(activate.entity).is_err() {
        return;
    }
    let Ok(mut root) = roots.single_mut() else {
        return;
    };
    if root.second_page {
        next_state.set(returning.0);
        return;
    }
    root.second_page = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::Credits)
            .insert_resource(CreditsReturn(AppState::StrategicMap))
            .add_observer(on_credits_activate);
        let root = app
            .world_mut()
            .spawn(CreditsRoot { second_page: false })
            .id();
        app.world_mut().spawn((CreditsAction, ChildOf(root)));
        app
    }

    #[test]
    fn first_click_stays_on_credits_and_second_click_returns() {
        let mut app = app();
        let action = app
            .world_mut()
            .query_filtered::<Entity, With<CreditsAction>>()
            .iter(app.world())
            .next()
            .unwrap();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: action });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Credits
        );
        assert!(
            app.world_mut()
                .query::<&CreditsRoot>()
                .iter(app.world())
                .next()
                .unwrap()
                .second_page
        );

        app.world_mut()
            .commands()
            .trigger(Activate { entity: action });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
    }
}
