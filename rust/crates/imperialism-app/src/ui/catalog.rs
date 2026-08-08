use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::log::warn;
use bevy::prelude::*;
use bevy::scene::ScenePlugin;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Button as UiButton, Checkbox};
use imperialism_formats::{
    RetailAssetError, RetailFontFace, RetailTextAlignment, RetailTextStyleError,
    RetailTextStylePreset, UiCatalog, UiNode as CatalogNode, UiNodeId, UiTextBinding,
    UiView as CatalogView, WidgetKind, resolve_retail_text_style,
};
use std::collections::HashMap;

/// Marks a spawned catalog node so hierarchy queries can recover [`UiNodeId`] after BSN spawn.
#[derive(Component, Clone, Copy, Debug, Default)]
struct UiCatalogNode(u32);

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

#[derive(Debug, Clone)]
pub(crate) struct SpawnedView {
    pub root: Entity,
    pub nodes: HashMap<UiNodeId, Entity>,
}

impl SpawnedView {
    pub(crate) fn tagged(&self, view: &CatalogView, tag: &str) -> Option<Entity> {
        view.nodes
            .iter()
            .find(|node| node.tag.0 == tag)
            .map(|node| self.nodes[&node.id])
    }
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiPictureLookup {
    pub(crate) world_variant: u8,
}

#[derive(Debug, thiserror::Error)]
enum UiTextBindingError {
    #[error(transparent)]
    Style(#[from] RetailTextStyleError),
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UiPictureBindingError {
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

#[derive(Resource, Default)]
struct RetailPictureHandles(HashMap<(i16, u8), Handle<Image>>);

#[derive(Resource, Default)]
struct RetailFontHandles(HashMap<RetailFontFace, Handle<Font>>);

#[derive(SystemParam)]
pub(crate) struct UiPictureResources<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    lookup: Res<'w, UiPictureLookup>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
}

impl UiPictureResources<'_> {
    pub(crate) fn picture(
        &mut self,
        picture_id: i16,
    ) -> Result<Handle<Image>, UiPictureBindingError> {
        load_retail_picture(
            picture_id,
            &self.retail_assets,
            self.lookup.world_variant,
            &mut self.images,
            &mut self.handles,
        )
    }

    pub(crate) fn with_picture_image_mut<R>(
        &mut self,
        picture_id: i16,
        f: impl FnOnce(&mut Image) -> R,
    ) -> Result<R, UiPictureBindingError> {
        let handle = self.picture(picture_id)?;
        let mut image = self
            .images
            .get_mut(&handle)
            .expect("picture handle was just resolved against Assets<Image>");
        Ok(f(&mut image))
    }
}

/// Initializes retail picture/font caches and ensures BSN scene spawning works under
/// `MinimalPlugins` test harnesses (DefaultPlugins already include [`ScenePlugin`]).
pub(crate) struct UiCatalogPlugin;

impl Plugin for UiCatalogPlugin {
    fn build(&self, app: &mut App) {
        if !app.is_plugin_added::<AssetPlugin>() {
            app.add_plugins(AssetPlugin::default());
        }
        if !app.is_plugin_added::<ScenePlugin>() {
            app.add_plugins(ScenePlugin);
        }
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .init_resource::<UiPictureLookup>();
    }
}

pub(crate) fn spawn_view(world: &mut World, view: &CatalogView) -> SpawnedView {
    let logical_resolution = world
        .resource::<UiCatalogResource>()
        .catalog()
        .logical_resolution;
    let spawned = spawn_view_nodes(world, logical_resolution, view);
    bind_view_assets(world, view, &spawned);
    spawned
}

/// Spawns catalog node hierarchy without binding retail pictures/fonts.
pub(crate) fn spawn_view_nodes(
    world: &mut World,
    logical_resolution: [u32; 2],
    view: &CatalogView,
) -> SpawnedView {
    let root = world
        .spawn_scene(view_root_scene(logical_resolution, view))
        .expect("catalog view scenes have no unloaded asset dependencies")
        .id();
    SpawnedView {
        root,
        nodes: collect_catalog_nodes(world, root),
    }
}

fn view_root_scene(logical_resolution: [u32; 2], view: &CatalogView) -> impl Scene {
    let name = format!("ui:{}:{}", view.id.resource_file, view.id.resource_id);
    let children = catalog_child_scenes(view, None);
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(logical_resolution[0] as f32),
            height: px(logical_resolution[1] as f32),
        }
        Name({name})
        Pickable
        Children [{children}]
    }
}

fn catalog_child_scenes(view: &CatalogView, parent: Option<UiNodeId>) -> Vec<Box<dyn Scene>> {
    view.nodes
        .iter()
        .filter(|node| node.parent == parent)
        .map(|node| catalog_node_scene(view, node))
        .collect()
}

fn catalog_node_scene(view: &CatalogView, node: &CatalogNode) -> Box<dyn Scene> {
    let [inset_left, inset_top, inset_right, inset_bottom] = catalog_content_insets(node);
    let name = format!("ui-node:{}:{}", node.id.0, node.tag.0);
    let children = catalog_child_scenes(view, Some(node.id));
    let widget = catalog_widget_scene(node);
    let node_id = node.id.0;
    let left = node.rect.x as f32;
    let top = node.rect.y as f32;
    let width = node.rect.width as f32;
    let height = node.rect.height as f32;
    Box::new(bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(top),
            width: px(width),
            height: px(height),
            padding: UiRect {
                left: px(inset_left as f32),
                top: px(inset_top as f32),
                right: px(inset_right as f32),
                bottom: px(inset_bottom as f32),
            },
        }
        Name({name})
        UiCatalogNode({node_id})
        {widget}
        Children [{children}]
    })
}

fn catalog_widget_scene(node: &CatalogNode) -> Box<dyn Scene> {
    let disabled = !node.enabled || !node.input_gate;
    match node.kind {
        WidgetKind::PictureButton if disabled => Box::new(bsn! {
            UiButton
            InteractionDisabled
        }),
        WidgetKind::PictureButton => Box::new(bsn! { UiButton }),
        WidgetKind::Checkbox if disabled => Box::new(bsn! {
            Checkbox
            InteractionDisabled
        }),
        WidgetKind::Checkbox => Box::new(bsn! { Checkbox }),
        WidgetKind::Toggle
        | WidgetKind::EditControl
        | WidgetKind::Container
        | WidgetKind::Window
        | WidgetKind::FloatingWindow
        | WidgetKind::Picture
        | WidgetKind::StaticText
        | WidgetKind::NumericValue
        | WidgetKind::ListOrScrollingPane
        | WidgetKind::RadioOrClusterControl
        | WidgetKind::CustomCanvas
        | WidgetKind::Specialized => Box::new(()),
    }
}

fn collect_catalog_nodes(world: &World, root: Entity) -> HashMap<UiNodeId, Entity> {
    let mut nodes = HashMap::new();
    let mut stack = vec![root];
    while let Some(entity) = stack.pop() {
        if let Some(UiCatalogNode(id)) = world.get::<UiCatalogNode>(entity) {
            nodes.insert(UiNodeId(*id), entity);
        }
        if let Some(children) = world.get::<Children>(entity) {
            stack.extend(children.iter());
        }
    }
    nodes
}

fn bind_view_assets(world: &mut World, view: &CatalogView, spawned: &SpawnedView) {
    for node in &view.nodes {
        let entity = spawned.nodes[&node.id];
        if let Some(binding) = node.properties.text.as_ref() {
            match load_retail_text_world(world, binding) {
                Ok((font, layout, underline)) => match node.kind {
                    WidgetKind::EditControl => {
                        let initial = binding.value.clone().unwrap_or_default();
                        let mut editable = EditableText::new(initial);
                        editable.allow_newlines = false;
                        if let Some(max_chars) = node.properties.max_characters() {
                            editable.max_characters = Some(max_chars as usize);
                        }
                        let mut entity = world.entity_mut(entity);
                        entity.insert((
                            editable,
                            font,
                            layout,
                            TextColor(Color::BLACK),
                            TextCursorStyle::default(),
                            EditableTextFilter::new(|character| !character.is_control()),
                        ));
                        if underline {
                            entity.insert(Underline);
                        }
                    }
                    _ => {
                        let mut entity = world.entity_mut(entity);
                        entity.insert((
                            Text::new(binding.value.clone().unwrap_or_default()),
                            font,
                            layout,
                            TextColor(Color::BLACK),
                        ));
                        if underline {
                            entity.insert(Underline);
                        }
                    }
                },
                Err(error) => {
                    warn!(
                        "could not bind retail text for UI view {}:{} node {}: {error}",
                        view.id.resource_file, view.id.resource_id, node.id.0
                    );
                }
            }
        }
        if let Some(picture_id) = node.properties.picture_id {
            match i16::try_from(picture_id)
                .map_err(|_| UiPictureBindingError::InvalidPictureId(picture_id))
                .and_then(|picture_id| load_picture_from_world(world, picture_id))
            {
                Ok(handle) => {
                    world.entity_mut(entity).insert(ImageNode::new(handle));
                }
                Err(error) => {
                    warn!(
                        "could not bind retail picture {picture_id} for UI view {}:{} node {}: {error}",
                        view.id.resource_file, view.id.resource_id, node.id.0
                    );
                }
            }
        }
    }
}

fn load_picture_from_world(
    world: &mut World,
    picture_id: i16,
) -> Result<Handle<Image>, UiPictureBindingError> {
    let world_variant = world.resource::<UiPictureLookup>().world_variant;
    let key = (picture_id, world_variant);
    if let Some(handle) = world.resource::<RetailPictureHandles>().0.get(&key) {
        return Ok(handle.clone());
    }
    let bytes = world
        .resource::<RetailAssetsResource>()
        .assets()
        .picture(picture_id, world_variant)?;
    let image = Image::from_buffer(
        &bytes,
        ImageType::Format(ImageFormat::Bmp),
        CompressedImageFormats::NONE,
        true,
        ImageSampler::nearest(),
        RenderAssetUsages::default(),
    )
    .map_err(|source| UiPictureBindingError::BmpDecode { picture_id, source })?;
    let handle = world.resource_mut::<Assets<Image>>().add(image);
    world
        .resource_mut::<RetailPictureHandles>()
        .0
        .insert(key, handle.clone());
    Ok(handle)
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

fn load_retail_text_world(
    world: &mut World,
    binding: &UiTextBinding,
) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family: binding.font_family,
        face_flags: binding.face_flags,
        point_size: binding.point_size,
        alignment: binding.alignment,
    })?;
    let handle = if let Some(handle) = world.resource::<RetailFontHandles>().0.get(&style.face) {
        handle.clone()
    } else {
        let bytes = world
            .resource::<RetailAssetsResource>()
            .assets()
            .font_bytes(style.face)
            .to_vec();
        let handle = world
            .resource_mut::<Assets<Font>>()
            .add(Font::from_bytes(bytes));
        world
            .resource_mut::<RetailFontHandles>()
            .0
            .insert(style.face, handle.clone());
        handle
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
    picture_id: i16,
    retail_assets: &RetailAssetsResource,
    world_variant: u8,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, UiPictureBindingError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{ScopedViewId, UiCatalog};
    use std::collections::HashMap;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .init_resource::<Assets<Image>>()
            .init_resource::<Assets<Font>>()
            .insert_resource(UiCatalogResource::new(catalog()))
            .add_plugins(UiCatalogPlugin);
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

    fn spawn_structure(app: &mut App, view_id: &ScopedViewId) -> SpawnedView {
        let catalog = app
            .world()
            .resource::<UiCatalogResource>()
            .catalog()
            .clone();
        let view = catalog
            .views
            .iter()
            .find(|view| &view.id == view_id)
            .unwrap()
            .clone();
        let logical_resolution = catalog.logical_resolution;
        spawn_view_nodes(app.world_mut(), logical_resolution, &view)
    }

    #[test]
    fn all_launch_views_spawn_with_exact_catalog_hierarchy() {
        let mut app = app();
        let catalog = catalog();
        let mut roots = HashMap::new();
        for view in &catalog.views {
            let spawned = spawn_structure(&mut app, &view.id);
            roots.insert(view.id.clone(), spawned);
        }

        let world = app.world_mut();
        for view in &catalog.views {
            let spawned = &roots[&view.id];
            let root_node = world.get::<Node>(spawned.root).unwrap();
            assert_eq!(px(root_node.width), 640.0);
            assert_eq!(px(root_node.height), 480.0);
            assert_eq!(spawned.nodes.len(), view.nodes.len());
            assert_eq!(
                view.nodes
                    .iter()
                    .filter(|node| node.parent.is_none())
                    .count(),
                1
            );
            for node in &view.nodes {
                let entity = spawned.nodes[&node.id];
                let ui = world.get::<Node>(entity).unwrap();
                let parent = world.get::<ChildOf>(entity).unwrap();
                assert_eq!(px(ui.left), node.rect.x as f32);
                assert_eq!(px(ui.top), node.rect.y as f32);
                assert_eq!(px(ui.width), node.rect.width as f32);
                assert_eq!(px(ui.height), node.rect.height as f32);
                let [left, top, right, bottom] = catalog_content_insets(node);
                assert_eq!(px(ui.padding.left), left as f32);
                assert_eq!(px(ui.padding.top), top as f32);
                assert_eq!(px(ui.padding.right), right as f32);
                assert_eq!(px(ui.padding.bottom), bottom as f32);
                let expected_parent = node.parent.map_or(spawned.root, |id| spawned.nodes[&id]);
                assert_eq!(parent.parent(), expected_parent, "node {entity:?}");
                let has_button = world.get::<UiButton>(entity).is_some();
                assert_eq!(
                    has_button,
                    node.kind == WidgetKind::PictureButton,
                    "node {} tag {} should only auto-map PictureButton",
                    node.id.0,
                    node.tag.0
                );
                if node.kind == WidgetKind::PictureButton {
                    assert_eq!(
                        world.get::<InteractionDisabled>(entity).is_some(),
                        !node.enabled || !node.input_gate
                    );
                }
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
        let spawned = spawn_structure(&mut app, &view.id);
        let padding = app
            .world()
            .get::<Node>(spawned.nodes[&country.id])
            .unwrap()
            .padding;
        assert_eq!(px(padding.left), 0.0);
        assert_eq!(px(padding.top), 3.0);
        assert_eq!(px(padding.right), 3.0);
        assert_eq!(px(padding.bottom), 3.0);
    }

    #[test]
    fn specialized_and_ambiguous_nodes_stay_passive() {
        let mut app = app();
        let menu = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1500,
        };
        let setup = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1501,
        };
        let menu_view = spawn_structure(&mut app, &menu);
        let setup_view = spawn_structure(&mut app, &setup);
        let catalog = catalog();
        let menu_catalog = catalog_view(&catalog, &menu);
        let setup_catalog = catalog_view(&catalog, &setup);

        for tag in ["rand", "quit", "load"] {
            let entity = menu_view.tagged(menu_catalog, tag).unwrap();
            assert!(app.world().get::<UiButton>(entity).is_none());
        }
        for tag in ["dif0", "hist", "key ", "cncl", "glob", "map "] {
            let entity = setup_view.tagged(setup_catalog, tag).unwrap();
            assert!(app.world().get::<UiButton>(entity).is_none());
        }
        let okay = setup_view.tagged(setup_catalog, "okay").unwrap();
        assert!(app.world().get::<UiButton>(okay).is_some());
    }
}
