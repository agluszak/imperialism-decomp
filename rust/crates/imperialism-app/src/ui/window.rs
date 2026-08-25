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
    Node = modal_barrier_node()
)]
pub struct ModalWindow;

#[derive(Component, Debug, Default)]
#[require(FloatingWindow, Pickable)]
pub struct CaptionedWindow;

#[derive(Component, Debug, Default)]
struct WindowTitleBar;

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
            .add_observer(on_modal_removed)
            .add_observer(on_window_pressed)
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
) {
    for (window, node, parent) in &contents {
        commands
            .entity(window)
            .entry::<Node>()
            .and_modify(|mut node| {
                node.overflow = Overflow::visible();
            });
        if let Some(parent) = parent {
            commands.entity(parent.parent()).insert(Pickable::IGNORE);
        }
        spawn_caption(&mut commands, window, node.width);
    }
}

fn spawn_caption(commands: &mut Commands, window: Entity, width: Val) {
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
            WindowTitleBar,
            Pickable::default(),
            Name::new("retail-window-caption"),
            ChildOf(window),
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
}

fn px_coord(value: Val) -> i32 {
    let Val::Px(pixels) = value else {
        panic!("window has a non-pixel position");
    };
    pixels.round() as i32
}

#[allow(clippy::type_complexity)]
fn on_window_pressed(
    press: On<Pointer<Press>>,
    parents: Query<&ChildOf>,
    mut windows: ParamSet<(
        Query<(), With<FloatingWindow>>,
        Query<(Entity, &mut GlobalZIndex), With<UiWindow>>,
    )>,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let root = {
        let floating = windows.p0();
        ancestor_with(press.original_event_target(), &parents, &floating)
    };
    let Some(root) = root else {
        return;
    };
    raise_window(root, &mut windows.p1());
}

fn on_window_dragged(
    drag: On<Pointer<Drag>>,
    parents: Query<&ChildOf>,
    mut windows: Query<&mut Node, With<FloatingWindow>>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let Some(root) = ancestor_with(drag.entity, &parents, &windows) else {
        return;
    };
    let mut node = windows.get_mut(root).expect("movable window has a Node");
    let position = window_position(&node)
        + IVec2::new(
            drag.event.delta.x.round() as i32,
            drag.event.delta.y.round() as i32,
        );
    set_window_position(&mut *node, position);
}

fn on_window_close(
    activate: On<Activate>,
    close: Query<(), With<DismissWindow>>,
    parents: Query<&ChildOf>,
    windows: Query<(), With<UiWindow>>,
    mut commands: Commands,
) {
    if !close.contains(activate.entity) {
        return;
    }
    let Some(window) = ancestor_with(activate.entity, &parents, &windows) else {
        return;
    };
    let despawn = parents
        .get(window)
        .ok()
        .map(ChildOf::parent)
        .filter(|parent| !windows.contains(*parent))
        .unwrap_or(window);
    commands.entity(despawn).try_despawn();
}

fn modal_keyboard(
    mut input: On<FocusedInput<KeyboardInput>>,
    parents: Query<&ChildOf>,
    modals: Query<(), With<ModalWindow>>,
    defaults: Query<Entity, (With<ModalDefault>, Without<InteractionDisabled>)>,
    cancels: Query<Entity, (With<ModalCancel>, Without<InteractionDisabled>)>,
    mut commands: Commands,
) {
    if input.input.state != ButtonState::Pressed || input.input.repeat {
        return;
    }
    let Some(root) = ancestor_with(input.focused_entity, &parents, &modals) else {
        return;
    };
    let control = match input.input.key_code {
        KeyCode::Enter | KeyCode::NumpadEnter => defaults
            .iter()
            .find(|entity| ancestor_is(*entity, root, &parents)),
        KeyCode::Escape => cancels
            .iter()
            .find(|entity| ancestor_is(*entity, root, &parents)),
        _ => return,
    };
    input.propagate(false);
    if let Some(control) = control {
        commands.trigger(Activate { entity: control });
    }
}

fn ancestor_is(mut entity: Entity, ancestor: Entity, parents: &Query<&ChildOf>) -> bool {
    loop {
        if entity == ancestor {
            return true;
        }
        let Ok(parent) = parents.get(entity) else {
            return false;
        };
        entity = parent.parent();
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

        let mut node = app
            .world_mut()
            .get_mut::<Node>(window)
            .expect("window keeps its Node");
        set_window_position(&mut *node, IVec2::new(40, 50));
        drop(node);
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
            let mut query = world.query_filtered::<Entity, With<DismissWindow>>();
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
