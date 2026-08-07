use crate::session::GameLoopSet;
use bevy::prelude::*;
use bevy::ui::{FocusPolicy, InteractionDisabled};
use imperialism_formats::{
    FourCc, ScopedViewId, UiCatalogError, UiCatalogV1, UiNode as CatalogNode, UiNodeId,
    UiView as CatalogView, WidgetKind,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Resource)]
pub struct UiCatalogResource(UiCatalogV1);

impl UiCatalogResource {
    pub fn new(catalog: UiCatalogV1) -> Result<Self, UiCatalogError> {
        catalog.validate()?;
        Ok(Self(catalog))
    }

    pub const fn catalog(&self) -> &UiCatalogV1 {
        &self.0
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ViewInstanceId(pub u64);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub struct PresentedViewId(pub ScopedViewId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentedUiNode(pub UiNodeId);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub struct WidgetTag(pub FourCc);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub struct LegacyWidgetClass(pub Option<String>);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiWidgetFlags {
    pub enabled: bool,
    pub input_gate: bool,
    pub child_hit_test: bool,
}

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UiViewRoot;

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InteractiveUiWidget;

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PreviousUiInteraction(Interaction);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct SpawnUiView(pub ScopedViewId);

#[derive(Message, Clone, Copy, Debug, Eq, PartialEq)]
pub struct DespawnUiView(pub ViewInstanceId);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct UiViewSpawned {
    pub instance: ViewInstanceId,
    pub view: ScopedViewId,
    pub root: Entity,
}

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct UiViewSpawnFailed {
    pub view: ScopedViewId,
    pub error: UiSpawnError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiSpawnError {
    ViewNotFound(ScopedViewId),
}

impl fmt::Display for UiSpawnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ViewNotFound(view) => write!(
                formatter,
                "normalized UI view {}:{} is absent from the catalog",
                view.resource_file, view.resource_id
            ),
        }
    }
}

impl Error for UiSpawnError {}

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub enum UiIntent {
    Activated {
        view: ViewInstanceId,
        tag: FourCc,
    },
    ValueChanged {
        view: ViewInstanceId,
        tag: FourCc,
        value: i32,
    },
    TextChanged {
        view: ViewInstanceId,
        tag: FourCc,
        value: String,
    },
}

#[derive(Resource)]
struct NextViewInstance(u64);

impl Default for NextViewInstance {
    fn default() -> Self {
        Self(1)
    }
}

pub struct UiRuntimePlugin;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SystemSet)]
pub enum UiRuntimeSet {
    EmitIntents,
    SpawnViews,
    DespawnViews,
}

impl Plugin for UiRuntimePlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<NextViewInstance>()
            .add_message::<SpawnUiView>()
            .add_message::<DespawnUiView>()
            .add_message::<UiViewSpawned>()
            .add_message::<UiViewSpawnFailed>()
            .add_message::<UiIntent>()
            .add_systems(
                Update,
                emit_ui_intents
                    .in_set(GameLoopSet::TranslateUiIntents)
                    .in_set(UiRuntimeSet::EmitIntents),
            )
            .add_systems(
                Update,
                (
                    spawn_requested_views.in_set(UiRuntimeSet::SpawnViews),
                    despawn_requested_views.in_set(UiRuntimeSet::DespawnViews),
                )
                    .chain()
                    .in_set(GameLoopSet::UpdatePresentation),
            );
    }
}

fn spawn_requested_views(
    mut commands: Commands,
    catalog: Option<Res<UiCatalogResource>>,
    mut requests: MessageReader<SpawnUiView>,
    mut spawned: MessageWriter<UiViewSpawned>,
    mut failed: MessageWriter<UiViewSpawnFailed>,
    mut next_instance: ResMut<NextViewInstance>,
) {
    let Some(catalog) = catalog else {
        return;
    };
    for SpawnUiView(view_id) in requests.read() {
        let Some(view) = catalog.catalog().view(view_id) else {
            let error = UiSpawnError::ViewNotFound(view_id.clone());
            failed.write(UiViewSpawnFailed {
                view: view_id.clone(),
                error,
            });
            continue;
        };
        let instance = ViewInstanceId(next_instance.0);
        next_instance.0 = next_instance.0.wrapping_add(1);
        let root = spawn_view(
            &mut commands,
            catalog.catalog().logical_resolution,
            view,
            instance,
        );
        spawned.write(UiViewSpawned {
            instance,
            view: view_id.clone(),
            root,
        });
    }
}

fn spawn_view(
    commands: &mut Commands,
    logical_resolution: [u32; 2],
    view: &CatalogView,
    instance: ViewInstanceId,
) -> Entity {
    let root = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(0.0),
                width: Val::Px(logical_resolution[0] as f32),
                height: Val::Px(logical_resolution[1] as f32),
                ..default()
            },
            UiViewRoot,
            instance,
            PresentedViewId(view.id.clone()),
        ))
        .id();

    let mut entities = HashMap::with_capacity(view.nodes.len());
    for node in &view.nodes {
        let entity = spawn_node(commands, view, node, instance);
        entities.insert(node.id, entity);
    }
    for node in &view.nodes {
        let entity = entities[&node.id];
        let parent = node.parent.map_or(root, |parent| entities[&parent]);
        commands.entity(entity).insert(ChildOf(parent));
    }
    root
}

fn spawn_node(
    commands: &mut Commands,
    view: &CatalogView,
    node: &CatalogNode,
    instance: ViewInstanceId,
) -> Entity {
    let mut entity = commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(node.rect.x as f32),
            top: Val::Px(node.rect.y as f32),
            width: Val::Px(node.rect.width as f32),
            height: Val::Px(node.rect.height as f32),
            ..default()
        },
        instance,
        PresentedViewId(view.id.clone()),
        PresentedUiNode(node.id),
        WidgetTag(node.tag.clone()),
        LegacyWidgetClass(node.legacy_class.clone()),
        UiWidgetFlags {
            enabled: node.enabled,
            input_gate: node.input_gate,
            child_hit_test: node.child_hit_test,
        },
        if node.child_hit_test {
            FocusPolicy::Block
        } else {
            FocusPolicy::Pass
        },
    ));
    if is_interactive(node) {
        entity.insert((
            Button,
            InteractiveUiWidget,
            PreviousUiInteraction::default(),
        ));
        if !node.enabled || !node.input_gate {
            entity.insert(InteractionDisabled);
        }
    }
    if let Some(text) = node
        .properties
        .text
        .as_ref()
        .and_then(|binding| binding.value.as_ref())
    {
        entity.insert(Text::new(text.clone()));
        if let Some(point_size) = node
            .properties
            .text
            .as_ref()
            .map(|binding| binding.point_size)
            .filter(|point_size| *point_size > 0)
        {
            entity.insert(TextFont::from_font_size(point_size as f32));
        }
    }
    entity.id()
}

fn is_interactive(node: &CatalogNode) -> bool {
    match node.legacy_type.0.as_str() {
        "cntl" | "edit" | "nmbr" | "radb" | "chkb" => true,
        "pict" => node.resolved_class.contains("Button"),
        "stat" => node.resolved_class.contains("Radio"),
        _ => matches!(node.kind, WidgetKind::Toggle | WidgetKind::Checkbox),
    }
}

type UiInteractionQuery<'w, 's> = Query<
    'w,
    's,
    (
        &'static Interaction,
        &'static mut PreviousUiInteraction,
        &'static ViewInstanceId,
        &'static PresentedUiNode,
        &'static WidgetTag,
        &'static UiWidgetFlags,
    ),
    With<InteractiveUiWidget>,
>;

fn emit_ui_intents(mut widgets: UiInteractionQuery, mut intents: MessageWriter<UiIntent>) {
    let mut activated = Vec::new();
    for (interaction, mut previous, instance, node, tag, flags) in &mut widgets {
        if *interaction == Interaction::Pressed
            && previous.0 != Interaction::Pressed
            && flags.enabled
            && flags.input_gate
        {
            activated.push((*instance, node.0.0, tag.0.clone()));
        }
        previous.0 = *interaction;
    }
    activated.sort_by_key(|item| (item.0, item.1));
    for (view, _, tag) in activated {
        intents.write(UiIntent::Activated { view, tag });
    }
}

fn despawn_requested_views(
    mut commands: Commands,
    mut requests: MessageReader<DespawnUiView>,
    roots: Query<(Entity, &ViewInstanceId), With<UiViewRoot>>,
) {
    for DespawnUiView(instance) in requests.read() {
        for (entity, candidate) in &roots {
            if candidate == instance {
                commands.entity(entity).despawn();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::ecs::message::Messages;
    use std::collections::{HashMap, HashSet};

    const CATALOG_JSON: &str =
        include_str!("../../../imperialism-formats/assets/ui_catalog_v1.json");

    fn catalog() -> UiCatalogV1 {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn app() -> App {
        let mut app = App::new();
        app.insert_resource(UiCatalogResource::new(catalog()).unwrap())
            .add_plugins(UiRuntimePlugin);
        app
    }

    fn px(value: Val) -> f32 {
        match value {
            Val::Px(value) => value,
            other => panic!("expected pixel value, found {other:?}"),
        }
    }

    #[derive(Resource)]
    struct PressedEntities(Vec<Entity>);

    fn press_entities(pressed: Res<PressedEntities>, mut interactions: Query<&mut Interaction>) {
        for entity in &pressed.0 {
            *interactions.get_mut(*entity).unwrap() = Interaction::Pressed;
        }
    }

    #[test]
    fn all_launch_views_spawn_with_exact_catalog_hierarchy() {
        let mut app = app();
        let view_ids = app
            .world()
            .resource::<UiCatalogResource>()
            .catalog()
            .views
            .iter()
            .map(|view| view.id.clone())
            .collect::<Vec<_>>();
        for view in &view_ids {
            app.world_mut()
                .write_message(SpawnUiView(view.clone()))
                .unwrap();
        }
        app.update();

        let world = app.world_mut();
        let roots = world
            .query_filtered::<(Entity, &ViewInstanceId, &PresentedViewId, &Node), With<UiViewRoot>>(
            )
            .iter(world)
            .map(|(entity, instance, view, node)| {
                assert_eq!(px(node.width), 640.0);
                assert_eq!(px(node.height), 480.0);
                (instance.0, (entity, view.0.clone()))
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(roots.len(), view_ids.len());

        let catalog = catalog();
        for (index, view) in catalog.views.iter().enumerate() {
            let instance = ViewInstanceId(index as u64 + 1);
            let (root, spawned_view) = &roots[&instance.0];
            assert_eq!(spawned_view, &view.id);
            let presented = world
                .query::<(
                    Entity,
                    &ViewInstanceId,
                    &PresentedViewId,
                    &PresentedUiNode,
                    &WidgetTag,
                    &LegacyWidgetClass,
                    &UiWidgetFlags,
                    &FocusPolicy,
                    &Node,
                    &ChildOf,
                )>()
                .iter(world)
                .filter(|(_, candidate, _, _, _, _, _, _, _, _)| **candidate == instance)
                .map(|row| (row.3.0, row))
                .collect::<HashMap<_, _>>();
            assert_eq!(presented.len(), view.nodes.len());
            assert_eq!(
                presented
                    .values()
                    .filter(|row| row.9.parent() == *root)
                    .count(),
                1
            );
            for node in &view.nodes {
                let (
                    entity,
                    _,
                    presented_view,
                    node_id,
                    tag,
                    legacy_class,
                    flags,
                    focus_policy,
                    ui,
                    parent,
                ) = presented[&node.id];
                assert_eq!(presented_view.0, view.id);
                assert_eq!(node_id.0, node.id);
                assert_eq!(tag.0, node.tag);
                assert_eq!(legacy_class.0, node.legacy_class);
                assert_eq!(
                    *flags,
                    UiWidgetFlags {
                        enabled: node.enabled,
                        input_gate: node.input_gate,
                        child_hit_test: node.child_hit_test,
                    }
                );
                assert_eq!(px(ui.left), node.rect.x as f32);
                assert_eq!(px(ui.top), node.rect.y as f32);
                assert_eq!(px(ui.width), node.rect.width as f32);
                assert_eq!(px(ui.height), node.rect.height as f32);
                assert_eq!(
                    *focus_policy,
                    if node.child_hit_test {
                        FocusPolicy::Block
                    } else {
                        FocusPolicy::Pass
                    }
                );
                let expected_parent = node.parent.map_or(*root, |id| presented[&id].0);
                assert_eq!(parent.parent(), expected_parent, "node {entity:?}");
            }
        }
    }

    #[test]
    fn enabled_controls_emit_ordered_tag_intents_and_disabled_controls_do_not() {
        let mut app = app();
        let confirmation = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 953,
        };
        let map = ScopedViewId {
            resource_file: "MapView.rsrc".to_owned(),
            resource_id: 2013,
        };
        app.world_mut()
            .write_message(SpawnUiView(confirmation))
            .unwrap();
        app.world_mut().write_message(SpawnUiView(map)).unwrap();
        app.update();

        let mut by_tag = app
            .world_mut()
            .query::<(Entity, &ViewInstanceId, &WidgetTag, &InteractiveUiWidget)>()
            .iter(app.world())
            .map(|(entity, instance, tag, _)| ((instance.0, tag.0.0.clone()), entity))
            .collect::<HashMap<_, _>>();
        let mut pressed = Vec::new();
        for tag in ["cncl", "okay"] {
            let entity = by_tag.remove(&(1, tag.to_owned())).unwrap();
            pressed.push(entity);
        }
        for tag in ["Flag", "quer"] {
            let entity = by_tag.remove(&(2, tag.to_owned())).unwrap();
            assert!(app.world().get::<InteractionDisabled>(entity).is_some());
            pressed.push(entity);
        }
        app.insert_resource(PressedEntities(pressed))
            .add_systems(PreUpdate, press_entities);
        app.update();

        for entity in &app.world().resource::<PressedEntities>().0 {
            assert_eq!(
                app.world().get::<Interaction>(*entity),
                Some(&Interaction::Pressed)
            );
            assert_eq!(
                app.world().get::<PreviousUiInteraction>(*entity),
                Some(&PreviousUiInteraction(Interaction::Pressed))
            );
        }

        let intents = app
            .world_mut()
            .resource_mut::<Messages<UiIntent>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(
            intents,
            vec![
                UiIntent::Activated {
                    view: ViewInstanceId(1),
                    tag: FourCc("okay".to_owned()),
                },
                UiIntent::Activated {
                    view: ViewInstanceId(1),
                    tag: FourCc("cncl".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn teardown_removes_only_the_requested_view_instance() {
        let mut app = app();
        let view = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 953,
        };
        app.world_mut()
            .write_message(SpawnUiView(view.clone()))
            .unwrap();
        app.world_mut().write_message(SpawnUiView(view)).unwrap();
        app.update();
        app.world_mut()
            .write_message(DespawnUiView(ViewInstanceId(1)))
            .unwrap();
        app.update();

        let remaining = app
            .world_mut()
            .query::<&ViewInstanceId>()
            .iter(app.world())
            .map(|instance| instance.0)
            .collect::<HashSet<_>>();
        assert_eq!(remaining, HashSet::from([2]));
    }
}
