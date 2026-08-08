use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::log::warn;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Button as UiButton;
use imperialism_formats::{
    RetailAssetError, RetailFontFace, RetailTextAlignment, RetailTextStyleError,
    RetailTextStylePreset, ScopedViewId, UiCatalog, UiNode as CatalogNode, UiNodeId, UiTextBinding,
    UiView as CatalogView, WidgetKind, resolve_retail_text_style,
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
    fonts: ResMut<'w, Assets<Font>>,
    font_handles: ResMut<'w, RetailFontHandles>,
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

/// Initializes retail picture/font caches. Widget plugins come from Bevy's `ui` profile.
pub(crate) struct UiCatalogPlugin;

impl Plugin for UiCatalogPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .init_resource::<UiPictureLookup>();
    }
}

pub(crate) fn find_view<'a>(
    catalog: &'a UiCatalog,
    view_id: &ScopedViewId,
) -> Option<&'a CatalogView> {
    catalog.views.iter().find(|view| &view.id == view_id)
}

/// Spawns a catalog view and binds retail pictures/fonts.
pub(crate) fn spawn_view(
    commands: &mut Commands,
    catalog: &UiCatalog,
    view: &CatalogView,
    pictures: &mut UiPictureResources,
) -> SpawnedView {
    let spawned = spawn_view_nodes(commands, catalog.logical_resolution, view);
    bind_view_assets(commands, view, &spawned, pictures);
    spawned
}

/// Spawns catalog node hierarchy without binding retail pictures/fonts.
pub(crate) fn spawn_view_nodes(
    commands: &mut Commands,
    logical_resolution: [u32; 2],
    view: &CatalogView,
) -> SpawnedView {
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
            Name::new(format!(
                "ui:{}:{}",
                view.id.resource_file, view.id.resource_id
            )),
            Pickable::default(),
        ))
        .id();

    let mut nodes = HashMap::with_capacity(view.nodes.len());
    for node in &view.nodes {
        let entity = spawn_node(commands, node);
        nodes.insert(node.id, entity);
    }
    for node in &view.nodes {
        let entity = nodes[&node.id];
        let parent = node.parent.map_or(root, |parent| nodes[&parent]);
        commands.entity(entity).insert(ChildOf(parent));
    }
    SpawnedView { root, nodes }
}

fn spawn_node(commands: &mut Commands, node: &CatalogNode) -> Entity {
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
        Name::new(format!("ui-node:{}:{}", node.id.0, node.tag.0)),
    ));

    match node.kind {
        WidgetKind::PictureButton => {
            entity.insert(UiButton);
            if !node.enabled || !node.input_gate {
                entity.insert(InteractionDisabled);
            }
        }
        WidgetKind::Checkbox => {
            entity.insert(bevy::ui_widgets::Checkbox);
            if !node.enabled || !node.input_gate {
                entity.insert(InteractionDisabled);
            }
        }
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
        | WidgetKind::Specialized => {
            // Passive or screen-classified. Do not invent button/toggle behavior.
        }
    }

    entity.id()
}

fn bind_view_assets(
    commands: &mut Commands,
    view: &CatalogView,
    spawned: &SpawnedView,
    pictures: &mut UiPictureResources,
) {
    for node in &view.nodes {
        let entity = spawned.nodes[&node.id];
        if let Some(binding) = node.properties.text.as_ref() {
            match load_retail_text(
                binding,
                &pictures.retail_assets,
                &mut pictures.fonts,
                &mut pictures.font_handles,
            ) {
                Ok((font, layout, underline)) => match node.kind {
                    WidgetKind::EditControl => {
                        let initial = binding.value.clone().unwrap_or_default();
                        let mut editable = EditableText::new(initial);
                        editable.allow_newlines = false;
                        if let Some(max_chars) = node.properties.max_characters() {
                            editable.max_characters = Some(max_chars as usize);
                        }
                        let mut entity = commands.entity(entity);
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
                        let mut entity = commands.entity(entity);
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
                .and_then(|picture_id| pictures.picture(picture_id))
            {
                Ok(handle) => {
                    commands.entity(entity).insert(ImageNode::new(handle));
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
    retail_assets: &RetailAssetsResource,
    fonts: &mut Assets<Font>,
    font_handles: &mut RetailFontHandles,
) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
    let style = resolve_retail_text_style(RetailTextStylePreset {
        font_family: binding.font_family,
        face_flags: binding.face_flags,
        point_size: binding.point_size,
        alignment: binding.alignment,
    })?;
    let bytes = retail_assets.assets().font_bytes(style.face);
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
    use imperialism_formats::UiCatalog;
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
        let world = app.world_mut();
        let mut commands = world.commands();
        let spawned = spawn_view_nodes(&mut commands, logical_resolution, &view);
        world.flush();
        spawned
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
