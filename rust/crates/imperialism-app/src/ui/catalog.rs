use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::ecs::system::SystemParam;
use bevy::image::{CompressedImageFormats, ImageSampler, ImageType, TextureError};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::log::warn;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::{Checked, InteractionDisabled, Pressed, RelativeCursorPosition};
use bevy::ui_widgets::{Button as UiButton, Checkbox, RadioButton, RadioGroup};
use imperialism_formats::*;
use imperialism_formats::{UiNode as CatalogNode, UiView as CatalogView};
use std::collections::HashMap;

#[derive(Resource)]
pub(crate) struct UiCatalogResource {
    catalog: UiCatalog,
    by_id: HashMap<ScopedViewId, usize>,
    indexes: Vec<UiViewIndex>,
}

impl UiCatalogResource {
    pub(crate) fn new(catalog: UiCatalog) -> Self {
        let by_id = catalog
            .views
            .iter()
            .enumerate()
            .map(|(index, view)| (view.id.clone(), index))
            .collect();
        let indexes = catalog.views.iter().map(UiViewIndex::build).collect();
        Self {
            catalog,
            by_id,
            indexes,
        }
    }

    pub(crate) const fn catalog(&self) -> &UiCatalog {
        &self.catalog
    }

    pub(crate) fn required_view(&self, view_id: &ScopedViewId) -> &CatalogView {
        self.by_id
            .get(view_id)
            .map(|&index| &self.catalog.views[index])
            .unwrap_or_else(|| {
                panic!(
                    "required UI view {}:{} is missing",
                    view_id.resource_file, view_id.resource_id
                )
            })
    }

    fn index(&self, view_id: &ScopedViewId) -> &UiViewIndex {
        let index = self.by_id.get(view_id).unwrap_or_else(|| {
            panic!(
                "required UI view {}:{} is missing",
                view_id.resource_file, view_id.resource_id
            )
        });
        &self.indexes[*index]
    }
}

#[derive(Component, Debug, Clone)]
pub(crate) struct SpawnedView {
    pub root: Entity,
    pub view_id: ScopedViewId,
    pub nodes: HashMap<UiNodeId, Entity>,
    tags: HashMap<FourCc, Vec<Entity>>,
}

impl SpawnedView {
    pub(crate) fn unique(&self, tag: FourCc) -> Entity {
        let matches = self.tags.get(&tag).map(Vec::as_slice).unwrap_or(&[]);
        match matches {
            [] => panic!(
                "required UI binding {}:{} tag {:?} is missing",
                self.view_id.resource_file, self.view_id.resource_id, tag
            ),
            [entity] => *entity,
            matches => panic!(
                "required UI binding {}:{} tag {:?} is ambiguous ({} matches)",
                self.view_id.resource_file,
                self.view_id.resource_id,
                tag,
                matches.len()
            ),
        }
    }

    pub(crate) fn under(
        &self,
        catalog: &UiCatalogResource,
        ancestor_tag: FourCc,
        tag: FourCc,
    ) -> Entity {
        let view = catalog.required_view(&self.view_id);
        let index = catalog.index(&self.view_id);
        let ancestors = index.tagged(ancestor_tag);
        if ancestors.is_empty() {
            panic!(
                "required UI binding {}:{} ancestor tag {:?} is missing",
                view.id.resource_file, view.id.resource_id, ancestor_tag
            );
        }
        let mut matches = Vec::new();
        for candidate in index.tagged(tag) {
            let Some(node) = index.node(view, *candidate) else {
                continue;
            };
            let mut parent = node.parent;
            while let Some(parent_id) = parent {
                if ancestors.contains(&parent_id) {
                    matches.push(*candidate);
                    break;
                }
                parent = index.node(view, parent_id).and_then(|node| node.parent);
            }
        }
        match matches.as_slice() {
            [] => panic!(
                "required UI binding {}:{} tag {:?} is missing under ancestor {:?}",
                view.id.resource_file, view.id.resource_id, tag, ancestor_tag
            ),
            [id] => self.nodes[id],
            matches => panic!(
                "required UI binding {}:{} tag {:?} is ambiguous under ancestor {:?} ({} matches)",
                view.id.resource_file,
                view.id.resource_id,
                tag,
                ancestor_tag,
                matches.len()
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UiTextBindingError {
    #[error(transparent)]
    Style(#[from] RetailTextStyleError),
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UiPictureBindingError {
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
    #[error("could not decode retail picture {picture_id}: {source}")]
    BmpDecode {
        picture_id: PictureId,
        #[source]
        source: TextureError,
    },
}

#[derive(Resource, Default)]
struct RetailPictureHandles(HashMap<PictureId, Handle<Image>>);

#[derive(Resource, Default)]
struct RetailFontHandles(HashMap<RetailFontFace, Handle<Font>>);

/// Single asset-loading path for retail pictures and fonts.
#[derive(SystemParam)]
pub(crate) struct UiAssetResources<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    fonts: ResMut<'w, Assets<Font>>,
    font_handles: ResMut<'w, RetailFontHandles>,
}

impl UiAssetResources<'_> {
    pub(crate) fn default_dib_palette(&self) -> &DibPalette {
        self.retail_assets.assets().default_dib_palette()
    }

    pub(crate) fn add_image(&mut self, image: Image) -> Handle<Image> {
        self.images.add(image)
    }

    pub(crate) fn replace_image(&mut self, handle: &Handle<Image>, image: Image) {
        *self
            .images
            .get_mut(handle)
            .expect("application-owned image handle remains loaded") = image;
    }

    pub(crate) fn palette_color(&self, index: u8) -> Color {
        let [red, green, blue] =
            self.retail_assets.assets().default_dib_palette()[index].to_array();
        Color::srgb_u8(red, green, blue)
    }

    pub(crate) fn string(&self, group: i16, direct_index: i16) -> Result<String, RetailAssetError> {
        self.retail_assets.assets().string(group, direct_index)
    }

    pub(crate) fn picture(
        &mut self,
        picture_id: PictureId,
    ) -> Result<Handle<Image>, UiPictureBindingError> {
        load_retail_picture(
            picture_id,
            &self.retail_assets,
            &mut self.images,
            &mut self.handles,
        )
    }

    pub(crate) fn with_picture_image_mut<R>(
        &mut self,
        picture_id: PictureId,
        f: impl FnOnce(&mut Image) -> R,
    ) -> Result<R, UiPictureBindingError> {
        let handle = self.picture(picture_id)?;
        let mut image = self
            .images
            .get_mut(&handle)
            .expect("picture handle was just resolved against Assets<Image>");
        Ok(f(&mut image))
    }

    pub(crate) fn transformed_picture(
        &mut self,
        picture_id: PictureId,
        transform: impl FnOnce(&mut Image),
    ) -> Result<Handle<Image>, UiPictureBindingError> {
        let handle = self.picture(picture_id)?;
        let mut image = self
            .images
            .get(&handle)
            .expect("picture handle was just resolved against Assets<Image>")
            .clone();
        transform(&mut image);
        Ok(self.images.add(image))
    }

    pub(crate) fn indexed_picture(
        &self,
        picture_id: PictureId,
    ) -> Result<IndexedPicture, RetailAssetError> {
        self.retail_assets.assets().indexed_picture(picture_id)
    }

    pub(crate) fn text_style(
        &mut self,
        preset: RetailTextStylePreset,
    ) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
        load_retail_text_style(
            preset,
            &self.retail_assets,
            &mut self.fonts,
            &mut self.font_handles,
        )
    }
}

/// Marks a modal dialog root with standard z-order and pointer blocking.
#[derive(Component, Debug, Default)]
pub(crate) struct ModalDialog;

/// Immutable resting picture ID plus the retail press/check swap rule.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogPictureVisual {
    base_id: PictureId,
    rule: PictureVisual,
    shown_id: PictureId,
}

/// Initializes retail picture/font caches and picture-state presentation.
pub(crate) struct UiCatalogPlugin;

impl Plugin for UiCatalogPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .add_systems(
                Update,
                sync_catalog_picture_visuals.run_if(resource_exists::<Assets<Image>>),
            );
    }
}

/// Thin convenience API for spawning catalog views from ordinary systems.
#[derive(SystemParam)]
pub(crate) struct UiSpawner<'w, 's> {
    pub(crate) commands: Commands<'w, 's>,
    catalog: Res<'w, UiCatalogResource>,
    assets: UiAssetResources<'w>,
}

impl UiSpawner<'_, '_> {
    pub(crate) fn picture(
        &mut self,
        picture_id: PictureId,
    ) -> Result<Handle<Image>, UiPictureBindingError> {
        self.assets.picture(picture_id)
    }

    pub(crate) fn indexed_picture(
        &self,
        picture_id: PictureId,
    ) -> Result<IndexedPicture, RetailAssetError> {
        self.assets.indexed_picture(picture_id)
    }

    pub(crate) fn transformed_picture(
        &mut self,
        picture_id: PictureId,
        transform: impl FnOnce(&mut Image),
    ) -> Result<Handle<Image>, UiPictureBindingError> {
        self.assets.transformed_picture(picture_id, transform)
    }

    pub(crate) fn palette_color(&self, index: u8) -> Color {
        self.assets.palette_color(index)
    }

    pub(crate) fn string(&self, group: i16, direct_index: i16) -> Result<String, RetailAssetError> {
        self.assets.string(group, direct_index)
    }
    pub(crate) fn text_style(
        &mut self,
        preset: RetailTextStylePreset,
    ) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
        self.assets.text_style(preset)
    }

    pub(crate) fn spawn(&mut self, view_id: ScopedViewId) -> SpawnedView {
        let view = self.catalog.required_view(&view_id);
        spawn_view(
            &mut self.commands,
            self.catalog.catalog(),
            view,
            &mut self.assets,
        )
    }

    pub(crate) fn spawn_modal(&mut self, view_id: ScopedViewId) -> SpawnedView {
        let spawned = self.spawn(view_id);
        self.commands.entity(spawned.root).insert((
            ModalDialog,
            TabGroup::modal(),
            GlobalZIndex(20),
            Pickable::default(),
        ));
        spawned
    }

    pub(crate) fn attach<C: Component>(
        &mut self,
        spawned: &SpawnedView,
        tag: FourCc,
        component: C,
    ) {
        let entity = spawned.unique(tag);
        self.commands
            .entity(entity)
            .insert(component)
            .remove::<InteractionDisabled>();
    }
}

pub(crate) fn spawn_view(
    commands: &mut Commands,
    catalog: &UiCatalog,
    view: &CatalogView,
    pictures: &mut UiAssetResources,
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
    let mut tags: HashMap<FourCc, Vec<Entity>> = HashMap::with_capacity(view.nodes.len());
    for node in &view.nodes {
        let entity = spawn_node(commands, node);
        nodes.insert(node.id, entity);
        tags.entry(node.tag).or_default().push(entity);
    }
    for node in &view.nodes {
        let entity = nodes[&node.id];
        let parent = node.parent.map_or(root, |parent| nodes[&parent]);
        commands.entity(entity).insert(ChildOf(parent));
    }
    SpawnedView {
        root,
        view_id: view.id.clone(),
        nodes,
        tags,
    }
}

fn spawn_node(commands: &mut Commands, node: &CatalogNode) -> Entity {
    let [inset_left, inset_top, inset_right, inset_bottom] = node.content_insets;
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
        Name::new(format!("ui-node:{}:{}", node.id.0, node.tag)),
    ));

    apply_behavior_components(&mut entity, node);
    entity.id()
}

fn apply_behavior_components(entity: &mut EntityCommands, node: &CatalogNode) {
    match node.behavior {
        UiBehavior::Passive => {}
        UiBehavior::Activate => {
            entity.insert(UiButton);
        }
        UiBehavior::Checkbox => {
            entity.insert(Checkbox);
            if node.checked {
                entity.insert(Checked);
            }
        }
        UiBehavior::Toggle => {
            // Bevy has no separate Toggle widget; reuse Checkbox presentation.
            entity.insert(Checkbox);
            if node.checked {
                entity.insert(Checked);
            }
        }
        UiBehavior::RadioGroup => {
            entity.insert(RadioGroup);
        }
        UiBehavior::RadioButton => {
            entity.insert(RadioButton);
            if node.checked {
                entity.insert(Checked);
            }
        }
        UiBehavior::TextEdit => {
            // EditableText content is bound with retail text assets.
        }
        UiBehavior::ScrollArea => {
            // Scroll projection lands with list ports; keep the node passive for now.
        }
        UiBehavior::PointerCanvas => {
            entity.insert(RelativeCursorPosition::default());
        }
    }
    if node.disabled {
        entity.insert(InteractionDisabled);
    }
}

fn bind_view_assets(
    commands: &mut Commands,
    view: &CatalogView,
    spawned: &SpawnedView,
    pictures: &mut UiAssetResources,
) {
    for node in &view.nodes {
        let entity = spawned.nodes[&node.id];
        if let Some(binding) = node.text.as_ref() {
            match load_retail_text(
                binding,
                &pictures.retail_assets,
                &mut pictures.fonts,
                &mut pictures.font_handles,
            ) {
                Ok((font, layout, underline)) => {
                    if node.behavior == UiBehavior::TextEdit {
                        let mut editable = EditableText::new(binding.value.clone());
                        editable.allow_newlines = false;
                        editable.max_characters = binding.max_chars;
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
                    } else {
                        let mut entity = commands.entity(entity);
                        entity.insert((
                            Text::new(binding.value.clone()),
                            font,
                            layout,
                            TextColor(Color::BLACK),
                        ));
                        if underline {
                            entity.insert(Underline);
                        }
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
        if let Some(picture_id) = node.picture_id {
            let shown_id = node
                .picture_visual
                .active_picture_id(picture_id, node.checked);
            match pictures.picture(shown_id) {
                Ok(handle) => {
                    let mut entity = commands.entity(entity);
                    entity.insert(ImageNode::new(handle));
                    if node.picture_visual != PictureVisual::Static {
                        entity.insert(CatalogPictureVisual {
                            base_id: picture_id,
                            rule: node.picture_visual,
                            shown_id,
                        });
                    }
                }
                Err(error) => {
                    warn!(
                        "could not bind retail picture {} for UI view {}:{} node {}: {error}",
                        picture_id, view.id.resource_file, view.id.resource_id, node.id.0
                    );
                }
            }
        }
    }
}

fn sync_catalog_picture_visuals(
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut handles: ResMut<RetailPictureHandles>,
    mut nodes: Query<(
        &mut CatalogPictureVisual,
        &mut ImageNode,
        Has<Pressed>,
        Has<Checked>,
    )>,
) {
    for (mut visual, mut image, pressed, checked) in &mut nodes {
        let Some(picture_id) =
            sync_cached_catalog_picture(&mut visual, &mut image, pressed || checked, &handles)
        else {
            continue;
        };
        match load_retail_picture(picture_id, &retail_assets, &mut images, &mut handles) {
            Ok(handle) => {
                image.image = handle;
                visual.shown_id = picture_id;
            }
            Err(error) => {
                warn!(
                    "could not update retail picture {} for pressed/checked state: {error}",
                    picture_id
                );
            }
        }
    }
}

/// Applies a cached state picture and returns the ID only when it still needs loading.
fn sync_cached_catalog_picture(
    visual: &mut CatalogPictureVisual,
    image: &mut ImageNode,
    active: bool,
    handles: &RetailPictureHandles,
) -> Option<PictureId> {
    let picture_id = visual.rule.active_picture_id(visual.base_id, active);
    if picture_id == visual.shown_id {
        return None;
    }
    let Some(handle) = handles.0.get(&picture_id) else {
        return Some(picture_id);
    };
    image.image = handle.clone();
    visual.shown_id = picture_id;
    None
}

fn load_retail_text(
    binding: &UiTextBinding,
    retail_assets: &RetailAssetsResource,
    fonts: &mut Assets<Font>,
    font_handles: &mut RetailFontHandles,
) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
    load_retail_text_style(
        RetailTextStylePreset {
            font_family: binding.font_family,
            face_flags: binding.face_flags,
            point_size: binding.point_size,
            alignment: binding.alignment,
        },
        retail_assets,
        fonts,
        font_handles,
    )
}

fn load_retail_text_style(
    preset: RetailTextStylePreset,
    retail_assets: &RetailAssetsResource,
    fonts: &mut Assets<Font>,
    font_handles: &mut RetailFontHandles,
) -> Result<(TextFont, TextLayout, bool), UiTextBindingError> {
    let style = resolve_retail_text_style(preset)?;
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
    picture_id: PictureId,
    retail_assets: &RetailAssetsResource,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, UiPictureBindingError> {
    let handle = match picture_handles.0.get(&picture_id) {
        Some(handle) => handle.clone(),
        None => {
            let bytes = retail_assets.assets().picture(picture_id)?;
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
            picture_handles.0.insert(picture_id, handle.clone());
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
            .init_resource::<RetailPictureHandles>()
            .insert_resource(UiCatalogResource::new(catalog()));
        app
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
    fn all_catalog_views_spawn_with_exact_catalog_hierarchy() {
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
                let [left, top, right, bottom] = node.content_insets;
                assert_eq!(px(ui.padding.left), left as f32);
                assert_eq!(px(ui.padding.top), top as f32);
                assert_eq!(px(ui.padding.right), right as f32);
                assert_eq!(px(ui.padding.bottom), bottom as f32);
                let expected_parent = node.parent.map_or(spawned.root, |id| spawned.nodes[&id]);
                assert_eq!(parent.parent(), expected_parent, "node {entity:?}");
                let has_button = world.get::<UiButton>(entity).is_some();
                assert_eq!(
                    has_button,
                    node.behavior == UiBehavior::Activate,
                    "node {} tag {} behavior {:?}",
                    node.id.0,
                    node.tag,
                    node.behavior
                );
                if node.behavior.is_interactive() {
                    assert_eq!(
                        world.get::<InteractionDisabled>(entity).is_some(),
                        node.disabled
                    );
                }
                assert_eq!(
                    world.get::<RadioButton>(entity).is_some(),
                    node.behavior == UiBehavior::RadioButton
                );
                assert_eq!(
                    world.get::<RadioGroup>(entity).is_some(),
                    node.behavior == UiBehavior::RadioGroup
                );
                assert_eq!(
                    world.get::<RelativeCursorPosition>(entity).is_some(),
                    node.behavior == UiBehavior::PointerCanvas
                );
            }
        }
    }

    #[test]
    fn sync_swaps_picture_when_pressed() {
        let mut app = app();
        let base_id = PictureId::new(4512);
        let active_id = PictureId::new(4513);
        let base_handle = app
            .world_mut()
            .resource_mut::<Assets<Image>>()
            .add(Image::default());
        let active_handle = app
            .world_mut()
            .resource_mut::<Assets<Image>>()
            .add(Image::default());
        {
            let mut handles = app.world_mut().resource_mut::<RetailPictureHandles>();
            handles.0.insert(base_id, base_handle.clone());
            handles.0.insert(active_id, active_handle.clone());
        }
        let mut visual = CatalogPictureVisual {
            base_id,
            rule: PictureVisual::UpDown,
            shown_id: base_id,
        };
        let mut image = ImageNode::new(base_handle.clone());
        let handles = app.world().resource::<RetailPictureHandles>();

        assert_eq!(
            sync_cached_catalog_picture(&mut visual, &mut image, false, handles),
            None
        );
        assert_eq!(visual.shown_id, base_id);
        assert_eq!(image.image, base_handle);

        assert_eq!(
            sync_cached_catalog_picture(&mut visual, &mut image, true, handles),
            None
        );
        assert_eq!(visual.shown_id, active_id);
        assert_eq!(image.image, active_handle);

        assert_eq!(
            sync_cached_catalog_picture(&mut visual, &mut image, false, handles),
            None
        );
        assert_eq!(visual.shown_id, base_id);
        assert_eq!(image.image, base_handle);
    }
}
