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
#[require(UiWindow)]
pub struct FloatingWindow;

/// Full-viewport pointer barrier, modal tab group, and restore-on-dismiss focus.
#[derive(Component, Debug, Default)]
#[require(
    UiWindow,
    TabGroup = TabGroup::modal(),
    Pickable,
    AutoFocus,
    Node = modal_barrier_node(),
    ModalControls
)]
pub struct ModalWindow;

#[derive(Component, Clone, Copy, Debug, Default)]
struct ModalControls {
    default: Option<Entity>,
    cancel: Option<Entity>,
}

#[derive(Component, Debug, Default)]
#[require(FloatingWindow, Pickable)]
pub struct CaptionedWindow;

#[derive(Component, Clone, Copy, Debug)]
struct WindowTitleBar {
    window: Entity,
}

#[derive(Component, Clone, Copy, Debug)]
struct WindowClose {
    root: Entity,
}

pub struct UiWindowPlugin;

impl Plugin for UiWindowPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<InputFocus>()
            .add_observer(on_window_added)
            .add_observer(on_floating_window_added)
            .add_observer(on_modal_removed)
            .add_observer(on_window_close)
            .add_observer(modal_keyboard)
            .add_systems(Update, bind_recovered_window_hosts);
    }
}

pub fn no_modal(modals: Query<(), With<ModalWindow>>) -> bool {
    modals.is_empty()
}

pub fn window_position(node: &Node) -> IVec2 {
    IVec2::new(px_coord(node.left), px_coord(node.top))
}

pub fn set_window_position(node: &mut Node, position: IVec2) {
    node.left = px(position.x);
    node.top = px(position.y);
}

pub fn bind_modal_controls(
    commands: &mut Commands,
    root: Entity,
    default: Option<Entity>,
    cancel: Option<Entity>,
) {
    commands
        .entity(root)
        .insert(ModalControls { default, cancel });
}

pub fn bind_window_close(commands: &mut Commands, control: Entity, root: Entity) {
    commands.entity(control).insert(WindowClose { root });
}

fn modal_barrier_node() -> Node {
    Node {
        position_type: PositionType::Absolute,
        left: px(0),
        top: px(0),
        width: px(640),
        height: px(480),
        overflow: Overflow::clip(),
        ..default()
    }
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
    contents: Query<(Entity, &Node, Option<&ChildOf>), Added<CaptionedWindow>>,
    windows: Query<(), With<UiWindow>>,
) {
    for (window, node, parent) in &contents {
        commands
            .entity(window)
            .entry::<Node>()
            .and_modify(|mut node| {
                node.overflow = Overflow::visible();
            });
        let host = parent
            .map(ChildOf::parent)
            .filter(|parent| !windows.contains(*parent))
            .unwrap_or(window);
        if let Some(parent) = parent {
            commands.entity(parent.parent()).insert(Pickable::IGNORE);
        }
        spawn_caption(&mut commands, window, host, node.width);
    }
}

fn spawn_caption(commands: &mut Commands, window: Entity, close_root: Entity, width: Val) {
    let caption = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(-CAPTION_HEIGHT),
                width,
                height: px(CAPTION_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::srgb_u8(0, 0, 128)),
            WindowTitleBar { window },
            Pickable::default(),
            Name::new("retail-window-caption"),
            ChildOf(window),
        ))
        .observe(on_window_dragged)
        .id();
    let close = commands
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
            ZIndex(1),
            Name::new("retail-window-close"),
            ChildOf(caption),
        ))
        .with_child((
            Text::new("×"),
            TextFont {
                font_size: FontSize::Px(12.0),
                ..default()
            },
            TextColor(Color::BLACK),
            Pickable::IGNORE,
        ))
        .id();
    bind_window_close(commands, close, close_root);
}

fn px_coord(value: Val) -> i32 {
    let Val::Px(pixels) = value else {
        panic!("window has a non-pixel position");
    };
    pixels.round() as i32
}

fn on_window_dragged(
    drag: On<Pointer<Drag>>,
    captions: Query<&WindowTitleBar>,
    mut windows: Query<&mut Node, With<FloatingWindow>>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let Ok(caption) = captions.get(drag.entity) else {
        return;
    };
    let mut node = windows
        .get_mut(caption.window)
        .expect("movable window has a Node");
    let position = window_position(&node)
        + IVec2::new(
            drag.event.delta.x.round() as i32,
            drag.event.delta.y.round() as i32,
        );
    set_window_position(&mut node, position);
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

    fn bind_controls(app: &mut App, root: Entity, default: Option<Entity>, cancel: Option<Entity>) {
        app.world_mut()
            .entity_mut(root)
            .insert(ModalControls { default, cancel });
    }

    #[test]
    fn windows_derive_structure_order_and_modal_focus_from_components() {
        let mut app = test_app();
        let floating = app.world_mut().spawn(FloatingWindow).id();
        let first = app.world_mut().spawn(ModalWindow).id();
        let second = app.world_mut().spawn(ModalWindow).id();

        assert!(app.world().get::<UiWindow>(floating).is_some());
        assert!(app.world().get::<UiWindow>(first).is_some());
        assert!(app.world().get::<TabGroup>(first).unwrap().modal);
        assert!(app.world().get::<Pickable>(first).is_some());
        assert!(app.world().get::<AutoFocus>(first).is_some());
        assert_eq!(app.world().get::<Node>(first).unwrap().width, px(640));
        assert_eq!(app.world().get::<Node>(first).unwrap().height, px(480));
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
        let cancel = app
            .world_mut()
            .spawn(ChildOf(first))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.cancel += 1;
            })
            .id();
        bind_controls(&mut app, first, None, Some(cancel));
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
            .spawn(ChildOf(root))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.default += 1;
            })
            .id();
        let cancel = app
            .world_mut()
            .spawn((InteractionDisabled, ChildOf(root)))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.cancel += 1;
            })
            .id();
        bind_controls(&mut app, root, Some(okay), Some(cancel));

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
        let okay = app
            .world_mut()
            .spawn(ChildOf(root))
            .observe(|_: On<Activate>, mut activations: ResMut<Activations>| {
                activations.default += 1;
            })
            .id();
        bind_controls(&mut app, root, Some(okay), None);
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(field));

        app.world_mut().write_message(keyboard(KeyCode::Enter));
        app.update();

        assert_eq!(app.world().resource::<Activations>().default, 1);
    }

    #[test]
    fn recovered_caption_is_a_child_of_the_positioned_window() {
        let mut app = test_app();
        let canvas = app
            .world_mut()
            .spawn(Node {
                position_type: PositionType::Absolute,
                width: px(640),
                height: px(480),
                ..default()
            })
            .id();
        let window = app
            .world_mut()
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(12),
                    top: px(34),
                    width: px(100),
                    ..default()
                },
                CaptionedWindow,
                ChildOf(canvas),
            ))
            .id();

        app.update();

        assert!(app.world().get::<FloatingWindow>(window).is_some());
        assert_eq!(app.world().get::<Pickable>(canvas), Some(&Pickable::IGNORE));
        let node = app.world().get::<Node>(window).unwrap();
        assert_eq!(window_position(node), IVec2::new(12, 34));
        let caption = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<WindowTitleBar>>();
            query.single(world).unwrap()
        };
        assert_eq!(
            app.world().get::<ChildOf>(caption).unwrap().parent(),
            window
        );
        let caption_node = app.world().get::<Node>(caption).unwrap();
        assert_eq!(caption_node.left, px(0));
        assert_eq!(caption_node.top, px(-CAPTION_HEIGHT));

        {
            let mut node = app
                .world_mut()
                .get_mut::<Node>(window)
                .expect("window keeps its Node");
            set_window_position(&mut node, IVec2::new(40, 50));
        }
        let caption_node = app.world().get::<Node>(caption).unwrap();
        assert_eq!(caption_node.left, px(0));
        assert_eq!(caption_node.top, px(-CAPTION_HEIGHT));
        assert_eq!(
            window_position(app.world().get::<Node>(window).unwrap()),
            IVec2::new(40, 50)
        );
    }

    #[test]
    fn dismissing_captioned_window_despawns_the_generated_host() {
        let mut app = test_app();
        let canvas = app.world_mut().spawn(Name::new("canvas")).id();
        app.world_mut().spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(8),
                top: px(16),
                width: px(64),
                ..default()
            },
            CaptionedWindow,
            ChildOf(canvas),
        ));
        app.update();

        let close = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<WindowClose>>();
            query.single(world).unwrap()
        };
        app.world_mut()
            .commands()
            .trigger(Activate { entity: close });
        app.world_mut().flush();
        app.update();

        assert!(app.world().get_entity(canvas).is_err());
    }
}
