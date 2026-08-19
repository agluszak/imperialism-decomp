use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::input_focus::{AutoFocus, FocusedInput};
use bevy::picking::events::{Drag, Pointer, Press};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button};

const WINDOW_Z_BASE: i32 = 20;
const CAPTION_HEIGHT: f32 = 18.0;
const CLOSE_SIZE: f32 = 14.0;

#[derive(Component, Debug, Default)]
#[require(GlobalZIndex)]
pub struct UiWindow;

#[derive(Component, Debug, Default)]
#[require(UiWindow)]
pub struct FloatingWindow;

#[derive(Component, Debug, Default)]
#[require(UiWindow, TabGroup = TabGroup::modal(), Pickable, AutoFocus)]
pub struct ModalWindow;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailWindowStyle {
    Plain,
    Floating,
    CaptionedFloating,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPosition(pub IVec2);

#[derive(Component, Debug, Default)]
pub struct WindowTitleBar;

#[derive(Component, Debug, Default)]
pub struct WindowClose;

#[derive(Component, Debug, Default)]
pub struct ModalDefault;

#[derive(Component, Debug, Default)]
pub struct ModalCancel;

#[derive(Component, Debug, Default)]
pub struct DismissWindow;

#[derive(Component, Debug, Default)]
struct ModalScrim;

pub struct UiWindowPlugin;

impl Plugin for UiWindowPlugin {
    fn build(&self, app: &mut App) {
        app.add_observer(on_window_added)
            .add_observer(on_modal_added)
            .add_observer(on_window_pressed.run_if(not(any_with_component::<ModalWindow>)))
            .add_observer(on_window_close)
            .add_systems(Update, (bind_recovered_window_hosts, sync_window_positions));
    }
}

fn on_window_added(
    added: On<Add, UiWindow>,
    mut windows: Query<(Entity, &mut GlobalZIndex), With<UiWindow>>,
) {
    raise_window(added.entity, &mut windows);
}

fn on_modal_added(added: On<Add, ModalWindow>, mut commands: Commands) {
    commands
        .entity(added.entity)
        .observe(modal_keyboard)
        .with_child((
            ModalScrim,
            Node {
                position_type: PositionType::Absolute,
                left: px(0),
                top: px(0),
                width: percent(100),
                height: percent(100),
                ..default()
            },
            ZIndex(-1),
            Pickable::default(),
            Name::new("modal-scrim"),
        ));
}

fn raise_window(entity: Entity, windows: &mut Query<(Entity, &mut GlobalZIndex), With<UiWindow>>) {
    let next = windows
        .iter_mut()
        .map(|(_, z)| z.0)
        .max()
        .unwrap_or(WINDOW_Z_BASE)
        + 1;
    windows
        .get_mut(entity)
        .expect("window being raised remains present")
        .1
        .0 = next;
}

fn bind_recovered_window_hosts(
    mut commands: Commands,
    contents: Query<(Entity, &RetailWindowStyle, &Node), Added<RetailWindowStyle>>,
    parents: Query<&ChildOf>,
    windows: Query<(Entity, Option<&WindowPosition>), With<UiWindow>>,
) {
    for (content, style, node) in &contents {
        let Some(root) = ancestor_window(content, &parents, &windows) else {
            continue;
        };
        commands.entity(content).insert(Pickable::default());
        if let Some(position) = windows.get(root).expect("window root remained present").1 {
            let position = position.0;
            commands
                .entity(content)
                .entry::<Node>()
                .and_modify(move |mut node| {
                    node.left = px(position.x as f32);
                    node.top = px(position.y as f32);
                });
        } else {
            commands
                .entity(root)
                .insert(WindowPosition(node_position(node)));
        }
        if *style == RetailWindowStyle::CaptionedFloating {
            spawn_caption(&mut commands, root, node);
        }
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

fn spawn_caption(commands: &mut Commands, root: Entity, content: &Node) {
    let position = node_position(content);
    let caption = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(position.x),
                top: px(position.y as f32 - CAPTION_HEIGHT),
                width: content.width,
                height: px(CAPTION_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::srgb_u8(0, 0, 128)),
            WindowTitleBar,
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
                WindowClose,
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

fn sync_window_positions(
    windows: Query<(Entity, &WindowPosition), Changed<WindowPosition>>,
    parents: Query<&ChildOf>,
    contents: Query<Entity, With<RetailWindowStyle>>,
    captions: Query<Entity, With<WindowTitleBar>>,
    mut nodes: Query<&mut Node>,
) {
    for (root, position) in &windows {
        if let Some(content) = contents
            .iter()
            .find(|entity| ancestor_is(*entity, root, &parents))
        {
            let mut node = nodes.get_mut(content).expect("window content has a Node");
            node.left = px(position.0.x);
            node.top = px(position.0.y);
        }
        if let Some(caption) = captions
            .iter()
            .find(|entity| ancestor_is(*entity, root, &parents))
        {
            let mut node = nodes.get_mut(caption).expect("window caption has a Node");
            node.left = px(position.0.x);
            node.top = px(position.0.y as f32 - CAPTION_HEIGHT);
        }
    }
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
        ancestor_component(press.original_event_target(), &parents, &floating)
    };
    let Some(root) = root else {
        return;
    };
    raise_window(root, &mut windows.p1());
}

fn on_window_dragged(
    drag: On<Pointer<Drag>>,
    parents: Query<&ChildOf>,
    windows: Query<(), With<FloatingWindow>>,
    mut positions: Query<&mut WindowPosition>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let Some(root) = ancestor_component(drag.entity, &parents, &windows) else {
        return;
    };
    let mut position = positions
        .get_mut(root)
        .expect("movable window has a semantic position");
    position.0.x += drag.event.delta.x.round() as i32;
    position.0.y += drag.event.delta.y.round() as i32;
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
    if let Some(root) = ancestor_component(activate.entity, &parents, &windows) {
        commands.entity(root).try_despawn();
    }
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
    let Some(root) = ancestor_component(input.focused_entity, &parents, &modals) else {
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

fn ancestor_component<T: Component>(
    mut entity: Entity,
    parents: &Query<&ChildOf>,
    components: &Query<(), With<T>>,
) -> Option<Entity> {
    loop {
        if components.contains(entity) {
            return Some(entity);
        }
        entity = parents.get(entity).ok()?.parent();
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
    use bevy::input_focus::{InputFocus, InputFocusPlugin, dispatch_focused_input};
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
        assert!(
            app.world().get::<GlobalZIndex>(floating).unwrap().0
                < app.world().get::<GlobalZIndex>(first).unwrap().0
        );
        assert!(
            app.world().get::<GlobalZIndex>(first).unwrap().0
                < app.world().get::<GlobalZIndex>(second).unwrap().0
        );
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(second));
        let scrims = {
            let world = app.world_mut();
            let mut query = world.query_filtered::<Entity, With<ModalScrim>>();
            query.iter(world).count()
        };
        assert_eq!(scrims, 2);
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
                RetailWindowStyle::CaptionedFloating,
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
            let mut query = world.query_filtered::<Entity, With<WindowClose>>();
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
    }
}
