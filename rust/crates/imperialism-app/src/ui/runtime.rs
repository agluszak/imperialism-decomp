use crate::launcher::RetailAssetPackResource;
use crate::session::GameLoopSet;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::prelude::*;
use bevy::ui::{FocusPolicy, InteractionDisabled};
use imperialism_formats::{
    FourCc, PictureLibrary, ResourceIdentifier, ScopedViewId, UiCatalogError, UiCatalogV1,
    UiNode as CatalogNode, UiNodeId, UiView as CatalogView, WidgetKind,
};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

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

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub struct PresentedRetailPicture {
    pub picture_id: i16,
    pub picture_library: Option<PictureLibrary>,
    pub resource_name: ResourceIdentifier,
    pub source_path: String,
    pub object_sha256: String,
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UiPictureLookup {
    pub world_variant: u8,
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

#[derive(Message, Debug)]
pub struct UiPictureBindingFailed {
    pub instance: ViewInstanceId,
    pub view: ScopedViewId,
    pub node: UiNodeId,
    pub picture_id: i32,
    pub error: UiPictureBindingError,
}

#[derive(Debug, thiserror::Error)]
pub enum UiPictureBindingError {
    #[error("retail asset pack is unavailable")]
    RetailAssetPackUnavailable,
    #[error("catalog picture ID {0} does not fit the retail 16-bit resource ID")]
    InvalidPictureId(i32),
    #[error("retail picture {picture_id} is absent for world slot {world_variant}")]
    PictureNotFound { picture_id: i16, world_variant: u8 },
    #[error("could not read normalized retail picture object {}: {source}", path.display())]
    ObjectIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not decode normalized retail BMP object {}: {source}", path.display())]
    BmpDecode {
        path: PathBuf,
        #[source]
        source: TextureError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UiSpawnError {
    #[error(
        "normalized UI view {}:{} is absent from the catalog",
        .0.resource_file,
        .0.resource_id
    )]
    ViewNotFound(ScopedViewId),
}

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

#[derive(Resource, Default)]
struct RetailPictureHandles(HashMap<PathBuf, Handle<Image>>);

#[derive(SystemParam)]
struct UiPictureResources<'w> {
    retail_assets: Option<Res<'w, RetailAssetPackResource>>,
    lookup: Res<'w, UiPictureLookup>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    failed: MessageWriter<'w, UiPictureBindingFailed>,
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
            .init_resource::<Assets<Image>>()
            .init_resource::<RetailPictureHandles>()
            .init_resource::<UiPictureLookup>()
            .add_message::<SpawnUiView>()
            .add_message::<DespawnUiView>()
            .add_message::<UiViewSpawned>()
            .add_message::<UiViewSpawnFailed>()
            .add_message::<UiPictureBindingFailed>()
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
    mut pictures: UiPictureResources,
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
            &mut pictures,
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
    pictures: &mut UiPictureResources,
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
        let entity = spawn_node(commands, view, node, instance, pictures);
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
    pictures: &mut UiPictureResources,
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
    if let Some(picture_id) = node.properties.picture_id {
        match load_retail_picture(
            picture_id,
            pictures.retail_assets.as_deref(),
            pictures.lookup.world_variant,
            &mut pictures.images,
            &mut pictures.handles,
        ) {
            Ok((picture, handle)) => {
                entity.insert((picture, ImageNode::new(handle)));
            }
            Err(error) => {
                pictures.failed.write(UiPictureBindingFailed {
                    instance,
                    view: view.id.clone(),
                    node: node.id,
                    picture_id,
                    error,
                });
            }
        }
    }
    entity.id()
}

fn load_retail_picture(
    catalog_picture_id: i32,
    retail_assets: Option<&RetailAssetPackResource>,
    world_variant: u8,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<(PresentedRetailPicture, Handle<Image>), UiPictureBindingError> {
    let picture_id = i16::try_from(catalog_picture_id)
        .map_err(|_| UiPictureBindingError::InvalidPictureId(catalog_picture_id))?;
    let retail_assets = retail_assets.ok_or(UiPictureBindingError::RetailAssetPackUnavailable)?;
    let asset = retail_assets
        .manifest()
        .resolve_picture(picture_id, world_variant)
        .ok_or(UiPictureBindingError::PictureNotFound {
            picture_id,
            world_variant,
        })?;
    let path = retail_assets.object_path(&asset.object);
    let object_key = asset.object.relative_path();
    let handle = match picture_handles.0.get(&object_key) {
        Some(handle) => handle.clone(),
        None => {
            let bytes = fs::read(&path).map_err(|source| UiPictureBindingError::ObjectIo {
                path: path.clone(),
                source,
            })?;
            let image = Image::from_buffer(
                &bytes,
                ImageType::Format(ImageFormat::Bmp),
                CompressedImageFormats::NONE,
                true,
                ImageSampler::nearest(),
                RenderAssetUsages::default(),
            )
            .map_err(|source| UiPictureBindingError::BmpDecode {
                path: path.clone(),
                source,
            })?;
            let handle = images.add(image);
            picture_handles.0.insert(object_key, handle.clone());
            handle
        }
    };
    Ok((
        PresentedRetailPicture {
            picture_id,
            picture_library: asset.picture_library,
            resource_name: asset.resource_name.clone(),
            source_path: asset.source_path.clone(),
            object_sha256: asset.object.sha256.clone(),
        },
        handle,
    ))
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
    use imperialism_formats::{
        CachedRetailObject, ImportedRetailAssets, RETAIL_ASSET_PACK_SCHEMA,
        RetailAssetPackManifestV1, RetailResourceAsset,
    };
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct RetailPictureFixture {
        root: PathBuf,
        imported: ImportedRetailAssets,
    }

    impl RetailPictureFixture {
        fn new(resources: Vec<RetailResourceAsset>) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "imperialism-app-ui-picture-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(root.join("objects/sha256")).unwrap();
            for asset in &resources {
                let path = root.join(asset.object.relative_path());
                fs::write(path, one_pixel_bmp()).unwrap();
            }
            Self {
                imported: ImportedRetailAssets {
                    cache_root: root.clone(),
                    pack_dir: root.join("packs/v1/test"),
                    manifest: RetailAssetPackManifestV1 {
                        schema: RETAIL_ASSET_PACK_SCHEMA.to_owned(),
                        cache_key: "0".repeat(64),
                        logical_resolution: [640, 480],
                        bitmap_lookup_is_name_then_numeric: true,
                        sources: Vec::new(),
                        resources,
                        strings: Vec::new(),
                        fonts: Vec::new(),
                        music: Vec::new(),
                    },
                },
                root,
            }
        }

        fn app(&self) -> App {
            let mut app = app();
            app.insert_resource(RetailAssetPackResource::new(self.imported.clone()));
            app
        }
    }

    impl Drop for RetailPictureFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn picture_asset(
        picture_id: i16,
        library: PictureLibrary,
        named: bool,
        identity: &str,
    ) -> RetailResourceAsset {
        RetailResourceAsset {
            source_path: identity.to_owned(),
            picture_library: Some(library),
            resource_type: ResourceIdentifier::Numeric(2),
            resource_name: if named {
                ResourceIdentifier::Named(format!("{picture_id}.BMP"))
            } else {
                ResourceIdentifier::Numeric(u32::from(picture_id as u16))
            },
            language: 1033,
            retail_byte_length: 4,
            retail_sha256: identity.to_owned(),
            object: CachedRetailObject {
                sha256: identity.to_owned(),
                byte_length: 58,
                extension: "bmp".to_owned(),
            },
        }
    }

    fn one_pixel_bmp() -> Vec<u8> {
        let mut bmp = Vec::with_capacity(58);
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&58_u32.to_le_bytes());
        bmp.extend_from_slice(&[0; 4]);
        bmp.extend_from_slice(&54_u32.to_le_bytes());
        bmp.extend_from_slice(&40_u32.to_le_bytes());
        bmp.extend_from_slice(&1_i32.to_le_bytes());
        bmp.extend_from_slice(&1_i32.to_le_bytes());
        bmp.extend_from_slice(&1_u16.to_le_bytes());
        bmp.extend_from_slice(&24_u16.to_le_bytes());
        bmp.extend_from_slice(&0_u32.to_le_bytes());
        bmp.extend_from_slice(&4_u32.to_le_bytes());
        bmp.extend_from_slice(&[0; 16]);
        bmp.extend_from_slice(&[0, 0, 0xff, 0]);
        assert_eq!(bmp.len(), 58);
        bmp
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

    #[test]
    fn startup_views_bind_catalog_pictures_to_nearest_sampled_retail_images() {
        let launch_views = [1500, 1501];
        let catalog = catalog();
        let expected = catalog
            .views
            .iter()
            .filter(|view| launch_views.contains(&view.id.resource_id))
            .flat_map(|view| {
                view.nodes.iter().filter_map(|node| {
                    node.properties
                        .picture_id
                        .map(|picture_id| (view.id.clone(), node.id, picture_id as i16))
                })
            })
            .collect::<HashSet<_>>();
        let resources = expected
            .iter()
            .map(|(_, _, picture_id)| {
                picture_asset(
                    *picture_id,
                    PictureLibrary::Localized,
                    true,
                    &format!("picture-{picture_id}"),
                )
            })
            .collect();
        let fixture = RetailPictureFixture::new(resources);
        let mut app = fixture.app();
        for resource_id in launch_views {
            app.world_mut()
                .write_message(SpawnUiView(ScopedViewId {
                    resource_file: "Startup.rsrc".to_owned(),
                    resource_id,
                }))
                .unwrap();
        }

        app.update();

        let bound = app
            .world_mut()
            .query::<(
                &PresentedViewId,
                &PresentedUiNode,
                &PresentedRetailPicture,
                &ImageNode,
            )>()
            .iter(app.world())
            .filter(|(view, _, _, _)| launch_views.contains(&view.0.resource_id))
            .map(|(view, node, picture, image_node)| {
                assert_eq!(picture.picture_library, Some(PictureLibrary::Localized));
                let image = app
                    .world()
                    .resource::<Assets<Image>>()
                    .get(&image_node.image)
                    .unwrap();
                assert_eq!(image.sampler, ImageSampler::nearest());
                (view.0.clone(), node.0, picture.picture_id)
            })
            .collect::<HashSet<_>>();
        assert_eq!(bound, expected);
        assert!(
            bound
                .iter()
                .any(|(view, _, picture_id)| { view.resource_id == 1500 && *picture_id == 4500 })
        );
        assert!(bound.iter().any(|(view, _, _)| view.resource_id == 1501));
    }

    #[test]
    fn picture_binding_uses_manifest_name_then_library_slot_precedence() {
        let resources = vec![
            picture_asset(4500, PictureLibrary::Universal, true, "named-universal"),
            picture_asset(4500, PictureLibrary::Localized, false, "numeric-localized"),
            picture_asset(4500, PictureLibrary::Localized, true, "named-localized"),
        ];
        let fixture = RetailPictureFixture::new(resources);
        let mut app = fixture.app();
        app.world_mut()
            .write_message(SpawnUiView(ScopedViewId {
                resource_file: "Startup.rsrc".to_owned(),
                resource_id: 1500,
            }))
            .unwrap();

        app.update();

        let picture = app
            .world_mut()
            .query::<&PresentedRetailPicture>()
            .single(app.world())
            .unwrap();
        assert_eq!(picture.source_path, "named-localized");
        assert_eq!(
            picture.resource_name,
            ResourceIdentifier::Named("4500.BMP".to_owned())
        );
        assert_eq!(picture.picture_library, Some(PictureLibrary::Localized));
    }

    #[test]
    fn missing_catalog_picture_reports_a_typed_failure_without_panicking() {
        let fixture = RetailPictureFixture::new(Vec::new());
        let mut app = fixture.app();
        let view = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1500,
        };
        app.world_mut()
            .write_message(SpawnUiView(view.clone()))
            .unwrap();

        app.update();

        let failures = app
            .world_mut()
            .resource_mut::<Messages<UiPictureBindingFailed>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 1);
        let failure = &failures[0];
        assert_eq!(failure.view, view);
        assert_eq!(failure.picture_id, 4500);
        assert!(matches!(
            failure.error,
            UiPictureBindingError::PictureNotFound {
                picture_id: 4500,
                world_variant: 0,
            }
        ));
        let picture_node = catalog()
            .view(&view)
            .unwrap()
            .nodes
            .iter()
            .find(|node| node.properties.picture_id == Some(4500))
            .unwrap()
            .id;
        assert_eq!(failure.node, picture_node);
        assert!(
            app.world_mut()
                .query::<(&PresentedViewId, &PresentedUiNode, Option<&ImageNode>)>()
                .iter(app.world())
                .any(|(presented_view, node, image)| {
                    presented_view.0 == view && node.0 == picture_node && image.is_none()
                })
        );
    }
}
