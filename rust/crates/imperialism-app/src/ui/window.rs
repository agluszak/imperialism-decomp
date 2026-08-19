use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::input_focus::{FocusCause, InputFocus};
use bevy::picking::events::{Drag, Pointer, Press};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button};

const WINDOW_Z_BASE: i32 = 20;
const MODAL_Z_BASE: i32 = 100;
const CAPTION_HEIGHT: f32 = 18.0;
const CLOSE_SIZE: f32 = 14.0;

#[derive(Component, Debug, Default)]
pub struct UiWindow;

#[derive(Component, Debug, Default)]
#[require(UiWindow)]
pub struct FloatingWindow;

#[derive(Component, Debug, Default)]
#[require(UiWindow)]
pub struct ModalWindow {
    pub owner: Option<Entity>,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetailWindowStyle {
    Plain,
    Floating,
    CaptionedFloating,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPosition(pub IVec2);

#[derive(Component, Debug)]
struct WindowContent(Entity);

#[derive(Component, Debug)]
struct WindowChrome(Entity);

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

#[derive(Clone, Copy, Debug)]
struct ModalEntry {
    entity: Entity,
    previous_focus: Option<Entity>,
}

#[derive(Resource, Debug, Default)]
pub struct WindowManager {
    active: Option<Entity>,
    order: Vec<Entity>,
    modals: Vec<ModalEntry>,
}

impl WindowManager {
    pub fn has_modal(&self) -> bool {
        !self.modals.is_empty()
    }

    pub fn top_modal(&self) -> Option<Entity> {
        self.modals.last().map(|entry| entry.entity)
    }
}

pub struct UiWindowPlugin;

impl Plugin for UiWindowPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<WindowManager>()
            .init_resource::<InputFocus>()
            .add_message::<KeyboardInput>()
            .add_observer(on_window_added)
            .add_observer(on_window_removed)
            .add_observer(on_modal_added)
            .add_observer(on_modal_removed)
            .add_observer(on_window_pressed)
            .add_observer(on_window_close)
            .add_systems(
                Update,
                (
                    bind_recovered_window_hosts,
                    sync_window_positions,
                    route_modal_keyboard,
                ),
            );
    }
}

fn on_window_added(
    added: On<Add, UiWindow>,
    modals: Query<(), With<ModalWindow>>,
    mut manager: ResMut<WindowManager>,
    mut commands: Commands,
) {
    manager.order.retain(|entity| *entity != added.entity);
    manager.order.push(added.entity);
    if !modals.contains(added.entity) {
        manager.active = Some(added.entity);
    }
    assign_window_z(&manager, &mut commands);
}

fn on_window_removed(
    removed: On<Remove, UiWindow>,
    mut manager: ResMut<WindowManager>,
    mut commands: Commands,
) {
    manager.order.retain(|entity| *entity != removed.entity);
    if manager.active == Some(removed.entity) {
        manager.active = manager
            .order
            .iter()
            .rev()
            .copied()
            .find(|entity| !manager.modals.iter().any(|entry| entry.entity == *entity));
    }
    assign_window_z(&manager, &mut commands);
}

fn on_modal_added(
    added: On<Add, ModalWindow>,
    mut modals: Query<&mut ModalWindow>,
    mut manager: ResMut<WindowManager>,
    mut focus: ResMut<InputFocus>,
    mut commands: Commands,
) {
    let previous = manager.top_modal();
    let mut modal = modals
        .get_mut(added.entity)
        .expect("added modal window remains present");
    if modal.owner.is_none() {
        modal.owner = previous.or(manager.active);
    }
    manager.modals.retain(|entry| entry.entity != added.entity);
    manager.modals.push(ModalEntry {
        entity: added.entity,
        previous_focus: focus.get(),
    });
    focus.set(added.entity, FocusCause::Navigated);
    commands
        .entity(added.entity)
        .insert((TabGroup::modal(), Pickable::default()));
    assign_window_z(&manager, &mut commands);
}

fn on_modal_removed(
    removed: On<Remove, ModalWindow>,
    windows: Query<(), With<UiWindow>>,
    mut manager: ResMut<WindowManager>,
    mut focus: ResMut<InputFocus>,
    mut commands: Commands,
) {
    let Some(index) = manager
        .modals
        .iter()
        .position(|entry| entry.entity == removed.entity)
    else {
        return;
    };
    let removed_entry = manager.modals.remove(index);
    for entry in &mut manager.modals[index..] {
        if entry.previous_focus == Some(removed.entity) {
            entry.previous_focus = removed_entry.previous_focus;
        }
    }
    if index == manager.modals.len() {
        if let Some(entity) = removed_entry
            .previous_focus
            .filter(|entity| windows.contains(*entity))
        {
            focus.set(entity, FocusCause::Navigated);
        } else {
            focus.clear();
        }
    }
    assign_window_z(&manager, &mut commands);
}

fn assign_window_z(manager: &WindowManager, commands: &mut Commands) {
    let mut ordinary = 0;
    let mut modal = 0;
    for entity in &manager.order {
        let is_modal = manager.modals.iter().any(|entry| entry.entity == *entity);
        let z = if is_modal {
            modal += 1;
            MODAL_Z_BASE + modal
        } else {
            ordinary += 1;
            WINDOW_Z_BASE + ordinary
        };
        if let Ok(mut entity_commands) = commands.get_entity(*entity) {
            entity_commands.insert(GlobalZIndex(z));
        }
    }
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
        commands.entity(root).insert(WindowContent(content));
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
            let chrome = spawn_caption(&mut commands, root, node);
            commands.entity(root).insert(WindowChrome(chrome));
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

fn spawn_caption(commands: &mut Commands, root: Entity, content: &Node) -> Entity {
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
    caption
}

fn sync_window_positions(
    windows: Query<
        (&WindowPosition, &WindowContent, Option<&WindowChrome>),
        Changed<WindowPosition>,
    >,
    mut nodes: Query<&mut Node>,
) {
    for (position, content, chrome) in &windows {
        {
            let mut node = nodes
                .get_mut(content.0)
                .expect("window content retains its generated Node");
            node.left = px(position.0.x);
            node.top = px(position.0.y);
        }
        if let Some(chrome) = chrome {
            let mut node = nodes
                .get_mut(chrome.0)
                .expect("window chrome remains attached to its host");
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

fn on_window_pressed(
    press: On<Pointer<Press>>,
    parents: Query<&ChildOf>,
    windows: Query<(), With<UiWindow>>,
    mut manager: ResMut<WindowManager>,
    mut commands: Commands,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let Some(root) = ancestor_component(press.original_event_target(), &parents, &windows) else {
        return;
    };
    if manager.top_modal().is_some_and(|top| top != root) {
        return;
    }
    manager.active = Some(root);
    if !manager.has_modal() {
        manager.order.retain(|entity| *entity != root);
        manager.order.push(root);
    }
    assign_window_z(&manager, &mut commands);
}

fn on_window_dragged(
    drag: On<Pointer<Drag>>,
    parents: Query<&ChildOf>,
    windows: Query<(), With<UiWindow>>,
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

fn route_modal_keyboard(
    mut input: MessageReader<KeyboardInput>,
    manager: Res<WindowManager>,
    parents: Query<&ChildOf>,
    defaults: Query<Entity, (With<ModalDefault>, Without<InteractionDisabled>)>,
    cancels: Query<Entity, (With<ModalCancel>, Without<InteractionDisabled>)>,
    mut commands: Commands,
) {
    let Some(root) = manager.top_modal() else {
        return;
    };
    for event in input.read() {
        if event.state != ButtonState::Pressed || event.repeat {
            continue;
        }
        let control = match event.key_code {
            KeyCode::Enter | KeyCode::NumpadEnter => defaults
                .iter()
                .find(|entity| ancestor_is(*entity, root, &parents)),
            KeyCode::Escape => cancels
                .iter()
                .find(|entity| ancestor_is(*entity, root, &parents)),
            _ => continue,
        };
        if let Some(control) = control {
            commands.trigger(Activate { entity: control });
        }
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

    #[derive(Resource, Default)]
    struct Activations {
        default: usize,
        cancel: usize,
    }

    fn test_app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .init_resource::<Activations>()
            .add_plugins(UiWindowPlugin);
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
    fn nested_modal_stack_restores_owner_and_focus() {
        let mut app = test_app();
        let owner = app.world_mut().spawn(FloatingWindow).id();
        app.world_mut()
            .resource_mut::<InputFocus>()
            .set(owner, FocusCause::Navigated);
        let first = app.world_mut().spawn(ModalWindow::default()).id();
        let second = app.world_mut().spawn(ModalWindow::default()).id();

        assert_eq!(
            app.world().get::<ModalWindow>(first).unwrap().owner,
            Some(owner)
        );
        assert_eq!(
            app.world().get::<ModalWindow>(second).unwrap().owner,
            Some(first)
        );
        assert_eq!(
            app.world().resource::<WindowManager>().top_modal(),
            Some(second)
        );

        app.world_mut().despawn(second);
        assert_eq!(
            app.world().resource::<WindowManager>().top_modal(),
            Some(first)
        );
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(first));

        app.world_mut().despawn(first);
        assert!(!app.world().resource::<WindowManager>().has_modal());
        assert_eq!(app.world().resource::<InputFocus>().get(), Some(owner));
    }

    #[test]
    fn modal_keyboard_activates_only_enabled_top_controls() {
        let mut app = test_app();
        let root = app.world_mut().spawn(ModalWindow::default()).id();
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
        let chrome = app.world().get::<WindowChrome>(root).unwrap().0;
        assert_eq!(app.world().get::<ChildOf>(chrome).unwrap().parent(), root);
        assert_eq!(app.world().get::<ChildOf>(content).unwrap().parent(), root);
    }
}
