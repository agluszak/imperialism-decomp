use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::input_focus::{AutoFocus, FocusCause, FocusedInput, InputFocus};
use bevy::picking::events::{Drag, Pointer, Press};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button};

use super::retail::ancestor_with;

const CAPTION_HEIGHT: f32 = 18.0;
const CLOSE_SIZE: f32 = 14.0;

#[derive(Component, Debug, Default)]
#[require(GlobalZIndex)]
struct UiWindow;

#[derive(Component, Debug, Default)]
#[require(UiWindow, Pickable = Pickable::IGNORE)]
pub struct FloatingWindow;

#[derive(Component, Debug, Default)]
/// Modal interaction rooted at a generated full-viewport `retail_view` entity.
///
/// The root's absolute 640x480 pickable node is the pointer barrier. Custom
/// modals without that generated root must provide equivalent geometry.
#[require(UiWindow, TabGroup = TabGroup::modal(), Pickable, AutoFocus, ModalControls)]
pub struct ModalWindow;

#[derive(Component, Clone, Copy, Debug, Default)]
struct ModalControls {
    default: Option<Entity>,
    cancel: Option<Entity>,
}

#[derive(Component, Debug, Default)]
pub struct CaptionedWindow;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPosition(pub IVec2);

#[derive(Component, Clone, Copy, Debug)]
struct BoundWindow {
    content: Entity,
    caption: Entity,
}

#[derive(Component, Clone, Copy, Debug)]
struct WindowTitleBar {
    root: Entity,
}

#[derive(Component, Clone, Copy, Debug)]
struct WindowClose {
    root: Entity,
}

#[derive(Component, Debug, Default)]
pub struct ModalDefault;

#[derive(Component, Debug, Default)]
pub struct ModalCancel;

#[derive(Component, Debug, Default)]
pub struct DismissWindow;

pub struct UiWindowPlugin;

impl Plugin for UiWindowPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<InputFocus>()
            .add_observer(on_window_added)
            .add_observer(on_floating_window_added)
            .add_observer(on_modal_removed)
            .add_observer(on_window_close)
            .add_observer(on_modal_default_added)
            .add_observer(on_modal_cancel_added)
            .add_observer(on_dismiss_added)
            .add_observer(modal_keyboard)
            .add_systems(Update, (bind_recovered_window_hosts, sync_window_positions));
    }
}

pub fn no_modal(modals: Query<(), With<ModalWindow>>) -> bool {
    modals.is_empty()
}

fn on_window_added(
    added: On<Add, UiWindow>,
    mut windows: Query<(Entity, &mut GlobalZIndex), With<UiWindow>>,
) {
    raise_window(added.entity, &mut windows);
}

fn on_modal_removed(
    removed: On<Remove, ModalWindow>,
    modals: Query<(Entity, &GlobalZIndex), With<ModalWindow>>,
    mut focus: ResMut<InputFocus>,
) {
    if let Some((entity, _)) = modals
        .iter()
        .filter(|(entity, _)| *entity != removed.entity)
        .max_by_key(|(_, z)| z.0)
    {
        focus.set(entity, FocusCause::Navigated);
    }
}

fn on_floating_window_added(added: On<Add, FloatingWindow>, mut commands: Commands) {
    commands
        .entity(added.entity)
        .observe(on_floating_window_pressed);
}

fn on_floating_window_pressed(
    press: On<Pointer<Press>>,
    mut windows: Query<(Entity, &mut GlobalZIndex), With<UiWindow>>,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    raise_window(press.observer(), &mut windows);
}

fn raise_window(entity: Entity, windows: &mut Query<(Entity, &mut GlobalZIndex), With<UiWindow>>) {
    let next = windows.iter_mut().map(|(_, z)| z.0).max().unwrap_or(0) + 1;
    windows
        .get_mut(entity)
        .expect("window being raised remains present")
        .1
        .0 = next;
}

fn bind_recovered_window_hosts(
    mut commands: Commands,
    contents: Query<(Entity, &Node), Added<CaptionedWindow>>,
    parents: Query<&ChildOf>,
    windows: Query<(Entity, Option<&WindowPosition>), With<UiWindow>>,
) {
    for (content, node) in &contents {
        let Some(root) = ancestor_window(content, &parents, &windows) else {
            continue;
        };
        commands.entity(content).insert(Pickable::default());
        let generated_position = node_position(node);
        let saved_position = windows
            .get(root)
            .expect("window root remained present")
            .1
            .map(|position| position.0);
        let position = saved_position.unwrap_or(generated_position);
        if saved_position.is_none() {
            commands.entity(root).insert(WindowPosition(position));
        }
        commands
            .entity(content)
            .entry::<Node>()
            .and_modify(move |mut node| {
                node.left = px(position.x);
                node.top = px(position.y);
            });
        let caption = spawn_caption(&mut commands, root, node.width, position);
        commands
            .entity(root)
            .insert(BoundWindow { content, caption });
    }
}

fn ancestor_window(
    mut entity: Entity,
    parents: &Query<&ChildOf>,
    windows: &Query<(Entity, Option<&WindowPosition>), With<UiWindow>>,
) -> Option<Entity> {
    loop {
        if windows.contains(entity) {
            return Some(entity);
        }
        entity = parents.get(entity).ok()?.parent();
    }
}

fn spawn_caption(commands: &mut Commands, root: Entity, width: Val, position: IVec2) -> Entity {
    let caption = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(position.x),
                top: px(position.y as f32 - CAPTION_HEIGHT),
                width,
                height: px(CAPTION_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::srgb_u8(0, 0, 128)),
            WindowTitleBar { root },
            Pickable::default(),
            Name::new("retail-window-caption"),
            ChildOf(root),
        ))
        .observe(on_window_dragged)
        .id();
    commands.entity(caption).with_children(|parent| {
        parent
            .spawn((
                Button,
                Node {
                    position_type: PositionType::Absolute,
                    right: px(2),
                    top: px(2),
                    width: px(CLOSE_SIZE),
                    height: px(CLOSE_SIZE),
                    align_items: AlignItems::Center,
                    justify_content: JustifyContent::Center,
                    ..default()
                },
                BackgroundColor(Color::srgb_u8(192, 192, 192)),
                DismissWindow,
                WindowClose { root },
                ZIndex(1),
                Name::new("retail-window-close"),
            ))
            .with_child((
                Text::new("×"),
                TextFont {
                    font_size: FontSize::Px(12.0),
                    ..default()
                },
                TextColor(Color::BLACK),
                Pickable::IGNORE,
            ));
    });
    caption
}

fn sync_window_positions(
    windows: Query<(&BoundWindow, &WindowPosition), Changed<WindowPosition>>,
    mut nodes: Query<&mut Node>,
) {
    for (bound, position) in &windows {
        {
            let mut content = nodes
                .get_mut(bound.content)
                .expect("window content has a Node");
            content.left = px(position.0.x);
            content.top = px(position.0.y);
        }
        let mut caption = nodes
            .get_mut(bound.caption)
            .expect("window caption has a Node");
        caption.left = px(position.0.x);
        caption.top = px(position.0.y as f32 - CAPTION_HEIGHT);
    }
}

fn on_modal_default_added(
    added: On<Add, ModalDefault>,
    parents: Query<&ChildOf>,
    modals: Query<(), With<ModalWindow>>,
    mut controls: Query<&mut ModalControls>,
) {
    let Some(root) = ancestor_with(added.entity, &parents, &modals) else {
        return;
    };
    controls
        .get_mut(root)
        .expect("modal keeps ModalControls")
        .default = Some(added.entity);
}

fn on_modal_cancel_added(
    added: On<Add, ModalCancel>,
    parents: Query<&ChildOf>,
    modals: Query<(), With<ModalWindow>>,
    mut controls: Query<&mut ModalControls>,
) {
    let Some(root) = ancestor_with(added.entity, &parents, &modals) else {
        return;
    };
    controls
        .get_mut(root)
        .expect("modal keeps ModalControls")
        .cancel = Some(added.entity);
}

fn on_dismiss_added(
    added: On<Add, DismissWindow>,
    closes: Query<(), With<WindowClose>>,
    parents: Query<&ChildOf>,
    windows: Query<(), With<UiWindow>>,
    mut commands: Commands,
) {
    if closes.contains(added.entity) {
        return;
    }
    let Some(root) = ancestor_with(added.entity, &parents, &windows) else {
        return;
    };
    commands.entity(added.entity).insert(WindowClose { root });
}

fn node_position(node: &Node) -> IVec2 {
    let Val::Px(left) = node.left else {
        panic!("generated window has a non-pixel left position");
    };
    let Val::Px(top) = node.top else {
        panic!("generated window has a non-pixel top position");
    };
    IVec2::new(left.round() as i32, top.round() as i32)
}

fn on_window_dragged(
    drag: On<Pointer<Drag>>,
    captions: Query<&WindowTitleBar>,
    mut positions: Query<&mut WindowPosition>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let Ok(caption) = captions.get(drag.entity) else {
        return;
    };
    let mut position = positions
        .get_mut(caption.root)
        .expect("movable window has a semantic position");
    position.0.x += drag.event.delta.x.round() as i32;
    position.0.y += drag.event.delta.y.round() as i32;
}

fn on_window_close(activate: On<Activate>, closes: Query<&WindowClose>, mut commands: Commands) {
    let Ok(close) = closes.get(activate.entity) else {
        return;
    };
    commands.entity(close.root).try_despawn();
}

fn modal_keyboard(
    mut input: On<FocusedInput<KeyboardInput>>,
    parents: Query<&ChildOf>,
    modals: Query<&ModalControls, With<ModalWindow>>,
    enabled: Query<(), Without<InteractionDisabled>>,
    mut commands: Commands,
) {
    if input.input.state != ButtonState::Pressed || input.input.repeat {
        return;
    }
    let Some(root) = ancestor_with(input.focused_entity, &parents, &modals) else {
        return;
    };
    let controls = modals.get(root).expect("focused modal keeps ModalControls");
    let control = match input.input.key_code {
        KeyCode::Enter | KeyCode::NumpadEnter => controls.default,
        KeyCode::Escape => controls.cancel,
        _ => return,
    };
    input.propagate(false);
    if let Some(control) = control.filter(|&entity| enabled.contains(entity)) {
        commands.trigger(Activate { entity: control });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::input::keyboard::{Key, NativeKey};
    use bevy::input_focus::{InputFocusPlugin, dispatch_focused_input};
    use bevy::window::PrimaryWindow;

    #[derive(Resource, Default)]
    struct Activations {
        default: usize,
        cancel: usize,
    }

    fn test_app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_message::<KeyboardInput>()
            .add_plugins(InputFocusPlugin)
            .add_systems(PreUpdate, dispatch_focused_input::<KeyboardInput>)
            .init_resource::<Activations>()
            .add_plugins(UiWindowPlugin);
        app.world_mut().spawn((Window::default(), PrimaryWindow));
        app
    }

    fn keyboard(key_code: KeyCode) -> KeyboardInput {
        KeyboardInput {
            key_code,
            logical_key: Key::Unidentified(NativeKey::Unidentified),
            state: ButtonState::Pressed,
            text: None,
            repeat: false,
            window: Entity::PLACEHOLDER,
        }
    }

    #[test]
    fn windows_derive_structure_order_and_modal_focus_from_components() {
        let mut app = test_app();
        let floating = app.world_mut().spawn(FloatingWindow).id();
        let first = app.world_mut().spawn(ModalWindow).id();
        let second = app.world_mut().spawn(ModalWindow).id();

        assert!(app.world().get::<UiWindow>(floating).is_some());
        assert_eq!(
            app.world().get::<Pickable>(floating),
            Some(&Pickable::IGNORE)
        );
        assert!(app.world().get::<UiWindow>(first).is_some());
        assert!(app.world().get::<TabGroup>(first).unwrap().modal);
        assert!(app.world().get::<Pickable>(first).is_some());
        assert!(app.world().get::<AutoFocus>(first).is_some());
        assert!(
            app.world().get::<GlobalZIndex>(floating).unwrap().0
                < app.world().get::<GlobalZIndex>(first).unwrap().0
        );
        assert!(
            app.world().get::<GlobalZIndex>(first).unwrap().0
                < app.world().get::<GlobalZIndex>(second).unwrap().0
        );
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(second));
    }

    #[test]
    fn dismissing_nested_modal_restores_keyboard_to_modal_below() {
        let mut app = test_app();
        let first = app.world_mut().spawn(ModalWindow).id();
        app.world_mut()
            .spawn((ModalCancel, ChildOf(first)))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.cancel += 1;
            });
        let second = app.world_mut().spawn(ModalWindow).id();
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(second));

        app.world_mut().despawn(second);
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(first));
        app.world_mut().write_message(keyboard(KeyCode::Escape));
        app.update();

        assert_eq!(app.world().resource::<Activations>().cancel, 1);
    }

    #[test]
    fn modal_keyboard_activates_only_enabled_top_controls() {
        let mut app = test_app();
        let root = app.world_mut().spawn(ModalWindow).id();
        let okay = app
            .world_mut()
            .spawn((ModalDefault, ChildOf(root)))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.default += 1;
            })
            .id();
        let cancel = app
            .world_mut()
            .spawn((ModalCancel, InteractionDisabled, ChildOf(root)))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.cancel += 1;
            })
            .id();

        app.world_mut().write_message(keyboard(KeyCode::Enter));
        app.world_mut().write_message(keyboard(KeyCode::Escape));
        app.update();
        assert_eq!(app.world().resource::<Activations>().default, 1);
        assert_eq!(app.world().resource::<Activations>().cancel, 0);

        app.world_mut()
            .entity_mut(cancel)
            .remove::<InteractionDisabled>();
        app.world_mut().write_message(keyboard(KeyCode::Escape));
        app.update();
        assert_eq!(app.world().resource::<Activations>().cancel, 1);
        assert!(app.world().get_entity(okay).is_ok());
    }

    #[test]
    fn focused_modal_child_routes_enter_to_the_modal_default() {
        let mut app = test_app();
        let root = app.world_mut().spawn(ModalWindow).id();
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(root));

        let field = app.world_mut().spawn((AutoFocus, ChildOf(root))).id();
        app.world_mut()
            .spawn((ModalDefault, ChildOf(root)))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.default += 1;
            });
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(field));

        app.world_mut().write_message(keyboard(KeyCode::Enter));
        app.update();

        assert_eq!(app.world().resource::<Activations>().default, 1);
    }

    #[test]
    fn recovered_caption_host_projects_semantic_position() {
        let mut app = test_app();
        let root = app
            .world_mut()
            .spawn((FloatingWindow, WindowPosition(IVec2::new(12, 34))))
            .id();
        let content = app
            .world_mut()
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(1),
                    top: px(2),
                    ..default()
                },
                CaptionedWindow,
                ChildOf(root),
            ))
            .id();

        app.update();
        app.update();

        let node = app.world().get::<Node>(content).unwrap();
        assert_eq!(node.left, px(12));
        assert_eq!(node.top, px(34));
        let captions = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<WindowTitleBar>>();
            query.iter(world).count()
        };
        let closes = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<DismissWindow>>();
            query.iter(world).count()
        };
        assert_eq!(captions, 1);
        assert_eq!(closes, 1);
        let caption = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<WindowTitleBar>>();
            query.single(world).unwrap()
        };
        assert_eq!(app.world().get::<ChildOf>(caption).unwrap().parent(), root);
        assert_eq!(app.world().get::<ChildOf>(content).unwrap().parent(), root);
        let caption_node = app.world().get::<Node>(caption).unwrap();
        assert_eq!(caption_node.left, px(12));
        assert_eq!(caption_node.top, px(34.0 - CAPTION_HEIGHT));
    }
}
