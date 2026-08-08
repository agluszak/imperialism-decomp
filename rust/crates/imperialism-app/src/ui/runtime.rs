use crate::launcher::RetailAssetsResource;
use crate::session::GameLoopSet;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::log::warn;
use bevy::prelude::*;
use bevy::ui::{FocusPolicy, InteractionDisabled};
use imperialism_formats::{
    FourCc, RetailAssetError, RetailFontFace, RetailTextAlignment, RetailTextStyleError,
    RetailTextStylePreset, ScopedViewId, UiCatalog, UiNode as CatalogNode, UiNodeId, UiTextBinding,
    UiView as CatalogView, resolve_retail_text_style,
};
use std::collections::HashMap;

#[derive(Resource)]
pub(crate) struct UiCatalogResource(UiCatalog);

impl UiCatalogResource {
    pub(crate) const fn new(catalog: UiCatalog) -> Self {
        Self(catalog)
    }

    pub(crate) const fn catalog(&self) -> &UiCatalog {
        &self.0
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ViewInstanceId(pub(crate) u64);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct PresentedViewId(pub(crate) ScopedViewId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PresentedUiNode(pub(crate) UiNodeId);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct WidgetTag(pub(crate) FourCc);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UiWidgetFlags {
    pub(crate) enabled: bool,
    pub(crate) input_gate: bool,
    pub(crate) child_hit_test: bool,
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiPictureLookup {
    pub(crate) world_variant: u8,
}

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiViewRoot;

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InteractiveUiWidget;

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PreviousUiInteraction(Interaction);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpawnUiView(pub(crate) ScopedViewId);

#[derive(Message, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DespawnUiView(pub(crate) ViewInstanceId);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) struct UiViewSpawned {
    pub(crate) instance: ViewInstanceId,
    pub(crate) view: ScopedViewId,
    pub(crate) root: Entity,
}

#[derive(Debug, thiserror::Error)]
enum UiTextBindingError {
    #[error("retail assets are unavailable")]
    RetailAssetsUnavailable,
    #[error(transparent)]
    Style(#[from] RetailTextStyleError),
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
}

#[derive(Debug, thiserror::Error)]
enum UiPictureBindingError {
    #[error("retail assets are unavailable")]
    RetailAssetsUnavailable,
    #[error("catalog picture ID {0} does not fit the retail 16-bit resource ID")]
    InvalidPictureId(i32),
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
    #[error("could not decode retail picture {picture_id}: {source}")]
    BmpDecode {
        picture_id: i16,
        #[source]
        source: TextureError,
    },
}

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) enum UiIntent {
    Activated {
        view: ViewInstanceId,
        tag: FourCc,
    },
    #[allow(dead_code)] // Value controls have not been presented by the recovered views yet.
    ValueChanged {
        view: ViewInstanceId,
        tag: FourCc,
        value: i32,
    },
    #[allow(dead_code)] // Text controls have not been presented by the recovered views yet.
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
struct RetailPictureHandles(HashMap<(i16, u8), Handle<Image>>);

#[derive(Resource, Default)]
struct RetailFontHandles(HashMap<RetailFontFace, Handle<Font>>);

#[derive(SystemParam)]
struct UiPictureResources<'w> {
    retail_assets: Option<Res<'w, RetailAssetsResource>>,
    lookup: Res<'w, UiPictureLookup>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    fonts: ResMut<'w, Assets<Font>>,
    font_handles: ResMut<'w, RetailFontHandles>,
}

pub(crate) struct UiRuntimePlugin;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SystemSet)]
pub(crate) enum UiRuntimeSet {
    EmitIntents,
    SpawnViews,
    DespawnViews,
}

impl Plugin for UiRuntimePlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<NextViewInstance>()
            .init_resource::<Assets<Image>>()
            .init_resource::<Assets<Font>>()
            .init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .init_resource::<UiPictureLookup>()
            .add_message::<SpawnUiView>()
            .add_message::<DespawnUiView>()
            .add_message::<UiViewSpawned>()
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
    mut next_instance: ResMut<NextViewInstance>,
) {
    let Some(catalog) = catalog else {
        return;
    };
    for SpawnUiView(view_id) in requests.read() {
        let Some(view) = catalog
            .catalog()
            .views
            .iter()
            .find(|view| &view.id == view_id)
        else {
            warn!(
                "could not spawn normalized UI view {}:{}: absent from catalog",
                view_id.resource_file, view_id.resource_id
            );
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
    let [inset_left, inset_top, inset_right, inset_bottom] = catalog_content_insets(node);
    let mut entity = commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(node.rect.x as f32),
            top: Val::Px(node.rect.y as f32),
            width: Val::Px(node.rect.width as f32),
            height: Val::Px(node.rect.height as f32),
            padding: UiRect {
                left: Val::Px(inset_left as f32),
                top: Val::Px(inset_top as f32),
                right: Val::Px(inset_right as f32),
                bottom: Val::Px(inset_bottom as f32),
            },
            ..default()
        },
        instance,
        PresentedViewId(view.id.clone()),
        PresentedUiNode(node.id),
        WidgetTag(node.tag.clone()),
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
    if node.interactive {
        entity.insert((
            Button,
            InteractiveUiWidget,
            PreviousUiInteraction::default(),
        ));
        if !node.enabled || !node.input_gate {
            entity.insert(InteractionDisabled);
        }
    }
    if let Some(binding) = node.properties.text.as_ref() {
        match load_retail_text(
            binding,
            pictures.retail_assets.as_deref(),
            &mut pictures.fonts,
            &mut pictures.font_handles,
        ) {
            Ok((font, layout, underline)) => {
                entity.insert((
                    Text::new(binding.value.clone().unwrap_or_default()),
                    font,
                    layout,
                ));
                if underline {
                    entity.insert(Underline);
                }
            }
            Err(error) => {
                warn!(
                    "could not bind retail text for UI view {}:{} node {}: {error}",
                    view.id.resource_file, view.id.resource_id, node.id.0
                );
            }
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
            Ok(handle) => {
                entity.insert(ImageNode::new(handle));
            }
            Err(error) => {
                warn!(
                    "could not bind retail picture {picture_id} for UI view {}:{} node {}: {error}",
                    view.id.resource_file, view.id.resource_id, node.id.0
                );
            }
        }
    }
    entity.id()
}

fn catalog_content_insets(node: &CatalogNode) -> [i32; 4] {
    node.properties.content_insets.unwrap_or([0; 4])
}

#[cfg(test)]
fn catalog_text_content_box(node: &CatalogNode) -> ([i32; 2], [i32; 2]) {
    let [left, top, right, bottom] = catalog_content_insets(node);
    (
        [node.rect.x + left, node.rect.y + top],
        [
            (node.rect.width - left - right).max(0),
            (node.rect.height - top - bottom).max(0),
        ],
    )
}

fn load_retail_text(
    binding: &UiTextBinding,
    retail_assets: Option<&RetailAssetsResource>,
    fonts: &mut Assets<Font>,
    font_handles: &mut RetailFontHandles,
) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family: binding.font_family,
        face_flags: binding.face_flags,
        point_size: binding.point_size,
        alignment: binding.alignment,
    })?;
    let retail_assets = retail_assets.ok_or(UiTextBindingError::RetailAssetsUnavailable)?;
    let bytes = retail_assets.assets().font_bytes(style.face)?;
    let handle = match font_handles.0.get(&style.face) {
        Some(handle) => handle.clone(),
        None => {
            let handle = fonts.add(Font::from_bytes(bytes.to_vec()));
            font_handles.0.insert(style.face, handle.clone());
            handle
        }
    };
    let mut font = TextFont::from_font_size(style.logical_pixel_height as f32)
        .with_font(handle)
        .with_font_smoothing(FontSmoothing::None);
    if style.italic {
        font.style = FontStyle::Italic;
    }
    let justify = match style.alignment {
        RetailTextAlignment::Left => Justify::Left,
        RetailTextAlignment::Center => Justify::Center,
        RetailTextAlignment::Right => Justify::Right,
    };
    Ok((font, TextLayout::justify(justify), style.underline))
}

fn load_retail_picture(
    catalog_picture_id: i32,
    retail_assets: Option<&RetailAssetsResource>,
    world_variant: u8,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, UiPictureBindingError> {
    let picture_id = i16::try_from(catalog_picture_id)
        .map_err(|_| UiPictureBindingError::InvalidPictureId(catalog_picture_id))?;
    let retail_assets = retail_assets.ok_or(UiPictureBindingError::RetailAssetsUnavailable)?;
    let key = (picture_id, world_variant);
    let handle = match picture_handles.0.get(&key) {
        Some(handle) => handle.clone(),
        None => {
            let bytes = retail_assets.assets().picture(picture_id, world_variant)?;
            let image = Image::from_buffer(
                &bytes,
                ImageType::Format(ImageFormat::Bmp),
                CompressedImageFormats::NONE,
                true,
                ImageSampler::nearest(),
                RenderAssetUsages::default(),
            )
            .map_err(|source| UiPictureBindingError::BmpDecode { picture_id, source })?;
            let handle = images.add(image);
            picture_handles.0.insert(key, handle.clone());
            handle
        }
    };
    Ok(handle)
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
    use imperialism_formats::{RetailAssets, UiCatalog};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn app() -> App {
        let mut app = App::new();
        app.insert_resource(UiCatalogResource::new(catalog()))
            .add_plugins(UiRuntimePlugin);
        app
    }

    fn catalog_view<'a>(catalog: &'a UiCatalog, id: &ScopedViewId) -> &'a CatalogView {
        catalog.views.iter().find(|view| &view.id == id).unwrap()
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
                    &UiWidgetFlags,
                    &FocusPolicy,
                    &Node,
                    &ChildOf,
                    Option<&InteractiveUiWidget>,
                )>()
                .iter(world)
                .filter(|(_, candidate, _, _, _, _, _, _, _, _)| **candidate == instance)
                .map(|row| (row.3.0, row))
                .collect::<HashMap<_, _>>();
            assert_eq!(presented.len(), view.nodes.len());
            assert_eq!(
                presented
                    .values()
                    .filter(|row| row.8.parent() == *root)
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
                    flags,
                    focus_policy,
                    ui,
                    parent,
                    interactive,
                ) = presented[&node.id];
                assert_eq!(presented_view.0, view.id);
                assert_eq!(node_id.0, node.id);
                assert_eq!(tag.0, node.tag);
                assert_eq!(interactive.is_some(), node.interactive);
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
                let [left, top, right, bottom] = catalog_content_insets(node);
                assert_eq!(px(ui.padding.left), left as f32);
                assert_eq!(px(ui.padding.top), top as f32);
                assert_eq!(px(ui.padding.right), right as f32);
                assert_eq!(px(ui.padding.bottom), bottom as f32);
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
    fn catalog_content_insets_define_bevy_padding_and_text_content_box() {
        let catalog = catalog();
        let view = catalog_view(
            &catalog,
            &ScopedViewId {
                resource_file: "Startup.rsrc".to_owned(),
                resource_id: 1501,
            },
        );
        let country = view.nodes.iter().find(|node| node.tag.0 == "coun").unwrap();
        assert_eq!(catalog_content_insets(country), [0, 3, 3, 3]);
        assert_eq!(catalog_text_content_box(country), ([23, 252], [303, 16]));

        let mut app = app();
        app.world_mut()
            .write_message(SpawnUiView(view.id.clone()))
            .unwrap();
        app.update();
        let padding = app
            .world_mut()
            .query::<(&PresentedUiNode, &Node)>()
            .iter(app.world())
            .find_map(|(node, ui)| (node.0 == country.id).then_some(ui.padding))
            .unwrap();
        assert_eq!(px(padding.left), 0.0);
        assert_eq!(px(padding.top), 3.0);
        assert_eq!(px(padding.right), 3.0);
        assert_eq!(px(padding.bottom), 3.0);
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
    fn picture_binding_does_not_fallback_when_retail_assets_are_unavailable() {
        let mut app = app();
        let view = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1500,
        };
        app.world_mut()
            .write_message(SpawnUiView(view.clone()))
            .unwrap();

        app.update();

        let catalog = catalog();
        let picture_node = catalog_view(&catalog, &view)
            .nodes
            .iter()
            .find(|node| node.properties.picture_id == Some(4500))
            .unwrap()
            .id;
        assert!(
            app.world_mut()
                .query::<(&PresentedViewId, &PresentedUiNode, Option<&ImageNode>)>()
                .iter(app.world())
                .any(|(presented_view, node, image)| {
                    presented_view.0 == view && node.0 == picture_node && image.is_none()
                })
        );
    }

    #[test]
    fn text_binding_does_not_fallback_when_retail_assets_are_unavailable() {
        let mut app = app();
        let view = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1501,
        };
        app.world_mut()
            .write_message(SpawnUiView(view.clone()))
            .unwrap();

        app.update();

        assert_eq!(
            app.world_mut()
                .query::<(&PresentedViewId, &TextFont)>()
                .iter(app.world())
                .filter(|(presented, _)| presented.0 == view)
                .count(),
            0
        );
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR and IMPERIALISM_TEXT_EVIDENCE_PATH"]
    fn real_retail_random_setup_text_renders_deterministic_640x480_evidence() {
        let retail_dir = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let output = PathBuf::from(
            std::env::var_os("IMPERIALISM_TEXT_EVIDENCE_PATH")
                .expect("IMPERIALISM_TEXT_EVIDENCE_PATH must name the output PPM"),
        );
        let retail_assets = RetailAssetsResource::new(RetailAssets::open(&retail_dir).unwrap());
        let catalog = catalog();
        let view = catalog_view(
            &catalog,
            &ScopedViewId {
                resource_file: "Startup.rsrc".to_owned(),
                resource_id: 1501,
            },
        );

        let first = render_text_evidence(view, &retail_assets);
        let second = render_text_evidence(view, &retail_assets);
        assert_eq!(first, second);
        const PPM_HEADER: &[u8] = b"P6\n640 480\n255\n";
        assert_eq!(&first[..PPM_HEADER.len()], PPM_HEADER);
        let pixels = &first[PPM_HEADER.len()..];
        assert_eq!(pixels.len(), 640 * 480 * 3);
        assert!(pixels.iter().any(|byte| *byte != 0));
        fs::write(output, first).unwrap();
    }

    fn render_text_evidence(view: &CatalogView, retail_assets: &RetailAssetsResource) -> Vec<u8> {
        use bevy::text::{
            ComputedTextBlock, FontAtlasSet, FontCx, FontHinting, LayoutCx, LetterSpacing,
            LineHeight, ScaleCx, TextBounds, TextLayoutInfo, TextPipeline,
        };

        let mut fonts = Assets::<Font>::default();
        let mut handles = RetailFontHandles::default();
        let mut prepared = Vec::new();
        let mut unresolved = Vec::new();
        for node in &view.nodes {
            let Some(binding) = node.properties.text.as_ref() else {
                continue;
            };
            if binding.value.as_deref().unwrap_or_default().is_empty() {
                continue;
            }
            match load_retail_text(binding, Some(retail_assets), &mut fonts, &mut handles) {
                Ok((font, layout, _)) => {
                    prepared.push((node, binding.value.as_deref().unwrap(), font, layout));
                }
                Err(UiTextBindingError::Style(RetailTextStyleError::UnresolvedFontFamily {
                    effective_family: 0,
                    ..
                })) => unresolved.push((node.id, node.tag.0.as_str())),
                Err(error) => panic!(
                    "could not prepare visible nonempty text node {} tag {:?}: {error}",
                    node.id.0, node.tag.0
                ),
            }
        }
        assert_eq!(unresolved, vec![(UiNodeId(2406), "auto")]);
        assert_eq!(prepared.len(), 9);

        let mut font_registration = App::new();
        font_registration
            .insert_resource(fonts)
            .init_resource::<FontCx>()
            .add_systems(Update, bevy::text::load_font_assets_into_font_collection);
        font_registration.update();
        let fonts = font_registration
            .world_mut()
            .remove_resource::<Assets<Font>>()
            .unwrap();
        let mut font_cx = font_registration
            .world_mut()
            .remove_resource::<FontCx>()
            .unwrap();
        let mut pipeline = TextPipeline::default();
        let mut layout_cx = LayoutCx::default();
        let mut scale_cx = ScaleCx::default();
        let mut atlases = FontAtlasSet::default();
        let mut textures = Assets::<Image>::default();
        let mut canvas = vec![0_u8; 640 * 480 * 3];
        for (node, text, font, layout) in prepared {
            let (content_origin, content_size) = catalog_text_content_box(node);
            let text_bounds = TextBounds::new(content_size[0] as f32, content_size[1] as f32);
            let mut computed = ComputedTextBlock::default();
            pipeline
                .update_buffer(
                    &fonts,
                    std::iter::once((
                        Entity::PLACEHOLDER,
                        0,
                        text,
                        &font,
                        Color::WHITE,
                        LineHeight::default(),
                        LetterSpacing::default(),
                    )),
                    layout.linebreak,
                    layout.justify,
                    text_bounds,
                    1.0,
                    &mut computed,
                    &mut font_cx,
                    &mut layout_cx,
                    Vec2::new(640.0, 480.0),
                    20.0,
                )
                .unwrap();
            let mut layout_info = TextLayoutInfo::default();
            pipeline
                .update_text_layout_info(
                    &mut layout_info,
                    &mut atlases,
                    &mut textures,
                    &mut computed,
                    &mut scale_cx,
                    text_bounds,
                    layout.justify,
                    FontHinting::Enabled,
                )
                .unwrap();
            for glyph in &layout_info.glyphs {
                let atlas = textures.get(glyph.atlas_info.texture).unwrap();
                let atlas_data = atlas.data.as_ref().unwrap();
                let atlas_width = atlas.texture_descriptor.size.width as usize;
                let source_x = glyph.atlas_info.rect.min.x as usize;
                let source_y = glyph.atlas_info.rect.min.y as usize;
                let width = glyph.atlas_info.rect.width() as usize;
                let height = glyph.atlas_info.rect.height() as usize;
                let destination_x = content_origin[0]
                    + (glyph.position.x - glyph.atlas_info.rect.width() / 2.0) as i32;
                let destination_y = content_origin[1]
                    + (glyph.position.y - glyph.atlas_info.rect.height() / 2.0) as i32;
                for y in 0..height {
                    for x in 0..width {
                        let alpha =
                            atlas_data[((source_y + y) * atlas_width + source_x + x) * 4 + 3];
                        let target_x = destination_x + x as i32;
                        let target_y = destination_y + y as i32;
                        if alpha == 0
                            || !(0..640).contains(&target_x)
                            || !(0..480).contains(&target_y)
                        {
                            continue;
                        }
                        let target = (target_y as usize * 640 + target_x as usize) * 3;
                        canvas[target..target + 3].fill(255);
                    }
                }
            }
        }
        let mut ppm = b"P6\n640 480\n255\n".to_vec();
        ppm.extend(canvas);
        ppm
    }
}
