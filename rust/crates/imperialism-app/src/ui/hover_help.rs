use super::retail::RetailTree;
use bevy::picking::hover::DirectlyHovered;
use bevy::prelude::*;
use bevy::scene::SceneComponent;
use imperialism_formats::FourCc;

/// Hover-help string shown in the screen's info bar while this control is the cursor hit.
///
/// Retail stores this on `TView::hoverHelpText58` after `SetHoverHelpText`. `TView::DoSetCursor`
/// then forwards it to `g_pCursorControlPanel` (`TInfoBarText::SetTextAndLayoutRect`).
#[derive(Component, Clone, Debug, Eq, PartialEq)]
#[require(DirectlyHovered)]
pub(crate) struct HoverHelpText(pub String);

/// The retail `curs` / `hot!` info-bar control that displays hover-help text.
///
/// Attached by codegen for `TInfoBarText`; recovered text styles come from Windows deltas.
#[derive(SceneComponent, Default, Clone)]
pub(crate) struct HoverHelpBar;

impl HoverHelpBar {
    fn scene() -> impl Scene {
        bsn! {
            Node {
                flex_direction: FlexDirection::Column,
                justify_content: JustifyContent::Center,
                overflow: Overflow::clip(),
            }
            Text("")
        }
    }
}

pub(crate) fn register_hover_help(app: &mut App) {
    app.add_systems(
        Update,
        (sync_hover_help_bar, sync_hover_help_accessible_labels),
    );
}

pub(crate) fn bind_hover_help_texts(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    texts: impl IntoIterator<Item = (FourCc, String)>,
) {
    for (tag, text) in texts {
        commands
            .entity(tree.find(root, tag))
            .insert(HoverHelpText(text));
    }
}

fn sync_hover_help_bar(
    sources: Query<(Ref<HoverHelpText>, Ref<DirectlyHovered>)>,
    mut bars: Query<&mut Text, With<HoverHelpBar>>,
) {
    let mut changed = false;
    let mut help = String::new();

    for (text, hovered) in &sources {
        changed |= text.is_changed() || hovered.is_changed();
        if hovered.get() {
            help = text.0.clone();
        }
    }

    if changed {
        for mut bar in &mut bars {
            bar.0 = help.clone();
        }
    }
}

fn sync_hover_help_accessible_labels(
    mut commands: Commands,
    sources: Query<(Entity, &HoverHelpText), Changed<HoverHelpText>>,
) {
    for (entity, help) in &sources {
        if help.0.is_empty() {
            commands.entity(entity).remove::<AccessibleLabel>();
        } else {
            commands
                .entity(entity)
                .insert(AccessibleLabel::new(help.0.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;

    fn app() -> App {
        let mut app = App::new();
        app.add_plugins((MinimalPlugins, AssetPlugin::default(), ScenePlugin))
            .add_systems(Update, sync_hover_help_bar);
        app
    }

    fn spawn_bar_and_source(app: &mut App, text: &str) -> (Entity, Entity) {
        let bar = app
            .world_mut()
            .spawn_scene(bsn! { @HoverHelpBar })
            .expect("hover help bar scene")
            .id();
        let source = app.world_mut().spawn(HoverHelpText(text.to_owned())).id();
        (bar, source)
    }

    #[test]
    fn empty_hover_help_clears_the_info_bar() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "");
    }

    #[test]
    fn a_new_directly_hovered_control_replaces_the_info_bar_text() {
        let mut app = app();
        let (bar, first) = spawn_bar_and_source(&mut app, "Random");
        let second = app.world_mut().spawn(HoverHelpText("Quit".to_owned())).id();
        app.world_mut()
            .entity_mut(first)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Random");
        app.world_mut()
            .entity_mut(first)
            .insert(DirectlyHovered(false));
        app.world_mut()
            .entity_mut(second)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Quit");
    }

    #[test]
    fn leaving_a_help_control_keeps_the_previous_info_bar_text() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "Quit");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(false));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "Quit");
    }

    #[test]
    fn changing_help_on_the_same_hovered_control_updates_the_bar() {
        let mut app = app();
        let (bar, source) = spawn_bar_and_source(&mut app, "civilian date");
        app.world_mut()
            .entity_mut(source)
            .insert(DirectlyHovered(true));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "civilian date");
        app.world_mut()
            .entity_mut(source)
            .insert(HoverHelpText("army date".to_owned()));
        app.update();
        assert_eq!(app.world().get::<Text>(bar).unwrap().0, "army date");
    }
}
