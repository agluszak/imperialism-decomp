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
use imperialism_formats::{
    FourCc, PictureVisual, RetailAssetError, RetailFontFace, RetailTextAlignment,
    RetailTextStyleError, RetailTextStylePreset, ScopedViewId, UiBehavior, UiCatalog,
    UiNode as CatalogNode, UiNodeId, UiTextBinding, UiView as CatalogView, UiViewIndex,
    resolve_retail_text_style,
};
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

    pub(crate) fn view(&self, view_id: &ScopedViewId) -> Option<&CatalogView> {
        self.by_id
            .get(view_id)
            .map(|&index| &self.catalog.views[index])
    }

    pub(crate) fn index(&self, view_id: &ScopedViewId) -> Option<&UiViewIndex> {
        self.by_id.get(view_id).map(|&index| &self.indexes[index])
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SpawnedView {
    pub root: Entity,
    pub view_id: ScopedViewId,
    pub nodes: HashMap<UiNodeId, Entity>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UiBindError {
    #[error("UI view {0}:{1} is not in the catalog")]
    MissingView(String, i16),
    #[error("tag {0:?} not found in view {1}:{2}")]
    MissingTag(String, String, i16),
    #[error("tag {0:?} is ambiguous in view {1}:{2} ({3} matches)")]
    AmbiguousTag(String, String, i16, usize),
    #[error("tag {0:?} not found under ancestor {1:?} in view {2}:{3}")]
    MissingUnder(String, String, String, i16),
    #[error("tag {0:?} is ambiguous under ancestor {1:?} in view {2}:{3}")]
    AmbiguousUnder(String, String, String, i16),
    #[error("path {0:?} not found in view {1}:{2}")]
    MissingPath(String, String, i16),
}

impl SpawnedView {
    pub(crate) fn require_unique(
        &self,
        catalog: &UiCatalogResource,
        tag: FourCc,
    ) -> Result<Entity, UiBindError> {
        let view = catalog
            .view(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        let index = catalog
            .index(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        match index.tagged(tag) {
            [] => Err(UiBindError::MissingTag(
                tag.to_string(),
                view.id.resource_file.clone(),
                view.id.resource_id,
            )),
            [id] => Ok(self.nodes[id]),
            matches => Err(UiBindError::AmbiguousTag(
                tag.to_string(),
                view.id.resource_file.clone(),
                view.id.resource_id,
                matches.len(),
            )),
        }
    }

    pub(crate) fn require_under(
        &self,
        catalog: &UiCatalogResource,
        ancestor_tag: FourCc,
        tag: FourCc,
    ) -> Result<Entity, UiBindError> {
        let view = catalog
            .view(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        let index = catalog
            .index(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        let ancestors = index.tagged(ancestor_tag);
        if ancestors.is_empty() {
            return Err(UiBindError::MissingTag(
                ancestor_tag.to_string(),
                view.id.resource_file.clone(),
                view.id.resource_id,
            ));
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
            [] => Err(UiBindError::MissingUnder(
                tag.to_string(),
                ancestor_tag.to_string(),
                view.id.resource_file.clone(),
                view.id.resource_id,
            )),
            [id] => Ok(self.nodes[id]),
            _ => Err(UiBindError::AmbiguousUnder(
                tag.to_string(),
                ancestor_tag.to_string(),
                view.id.resource_file.clone(),
                view.id.resource_id,
            )),
        }
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn require_path(
        &self,
        catalog: &UiCatalogResource,
        path: &[FourCc],
    ) -> Result<Entity, UiBindError> {
        let view = catalog
            .view(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        let index = catalog
            .index(&self.view_id)
            .ok_or_else(|| missing_view(&self.view_id))?;
        let path_label = path
            .iter()
            .map(FourCc::as_str)
            .collect::<Vec<_>>()
            .join("/");
        let mut current_parents: Option<Vec<UiNodeId>> = None;
        for (step, &tag) in path.iter().enumerate() {
            let candidates = index.tagged(tag);
            let matches: Vec<UiNodeId> = match &current_parents {
                None => {
                    if step == 0 {
                        candidates.to_vec()
                    } else {
                        Vec::new()
                    }
                }
                Some(parents) => candidates
                    .iter()
                    .copied()
                    .filter(|id| {
                        index
                            .node(view, *id)
                            .and_then(|node| node.parent)
                            .is_some_and(|parent| parents.contains(&parent))
                    })
                    .collect(),
            };
            match matches.as_slice() {
                [] => {
                    return Err(UiBindError::MissingPath(
                        path_label,
                        view.id.resource_file.clone(),
                        view.id.resource_id,
                    ));
                }
                [id] if step + 1 == path.len() => return Ok(self.nodes[id]),
                many if step + 1 == path.len() => {
                    return Err(UiBindError::AmbiguousTag(
                        tag.to_string(),
                        view.id.resource_file.clone(),
                        view.id.resource_id,
                        many.len(),
                    ));
                }
                many => current_parents = Some(many.to_vec()),
            }
        }
        Err(UiBindError::MissingPath(
            path_label,
            view.id.resource_file.clone(),
            view.id.resource_id,
        ))
    }
}

fn missing_view(view_id: &ScopedViewId) -> UiBindError {
    UiBindError::MissingView(view_id.resource_file.clone(), view_id.resource_id)
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

/// Single asset-loading path for retail pictures and fonts.
#[derive(SystemParam)]
pub(crate) struct UiAssetResources<'w> {
    retail_assets: Res<'w, RetailAssetsResource>,
    lookup: Res<'w, UiPictureLookup>,
    images: ResMut<'w, Assets<Image>>,
    handles: ResMut<'w, RetailPictureHandles>,
    fonts: ResMut<'w, Assets<Font>>,
    font_handles: ResMut<'w, RetailFontHandles>,
}

impl UiAssetResources<'_> {
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

/// Marks a modal dialog root with standard z-order and pointer blocking.
#[derive(Component, Debug, Default)]
pub(crate) struct ModalDialog;

/// Immutable resting picture ID plus the retail press/check swap rule.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogPictureVisual {
    base_id: i16,
    rule: PictureVisual,
    shown_id: i16,
}

/// Initializes retail picture/font caches and picture-state presentation.
pub(crate) struct UiCatalogPlugin;

impl Plugin for UiCatalogPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .init_resource::<UiPictureLookup>()
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
    pub(crate) fn catalog(&self) -> &UiCatalogResource {
        &self.catalog
    }

    pub(crate) fn spawn(&mut self, view_id: ScopedViewId) -> Option<SpawnedView> {
        let view = self.catalog.view(&view_id)?;
        Some(spawn_view(
            &mut self.commands,
            self.catalog.catalog(),
            view,
            &mut self.assets,
        ))
    }

    pub(crate) fn spawn_modal(&mut self, view_id: ScopedViewId) -> Option<SpawnedView> {
        let spawned = self.spawn(view_id)?;
        self.commands.entity(spawned.root).insert((
            ModalDialog,
            TabGroup::modal(),
            ZIndex(10),
            Pickable::default(),
        ));
        Some(spawned)
    }

    pub(crate) fn attach<C: Component>(
        &mut self,
        spawned: &SpawnedView,
        tag: FourCc,
        component: C,
    ) -> Result<Entity, UiBindError> {
        let entity = spawned.require_unique(&self.catalog, tag)?;
        self.commands
            .entity(entity)
            .insert(component)
            .remove::<InteractionDisabled>();
        Ok(entity)
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
    for node in &view.nodes {
        let entity = spawn_node(commands, node);
        nodes.insert(node.id, entity);
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
    }
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
        Name::new(format!("ui-node:{}:{}", node.id.0, node.tag)),
    ));

    apply_behavior_components(&mut entity, node);
    entity.id()
}

fn apply_behavior_components(entity: &mut EntityCommands, node: &CatalogNode) {
    let disabled = node.interaction_disabled();
    match node.behavior {
        UiBehavior::Passive => {}
        UiBehavior::Activate => {
            entity.insert(UiButton);
        }
        UiBehavior::Checkbox => {
            entity.insert(Checkbox);
            if node.state {
                entity.insert(Checked);
            }
        }
        UiBehavior::Toggle => {
            // Bevy has no separate Toggle widget; reuse Checkbox presentation.
            entity.insert(Checkbox);
            if node.state {
                entity.insert(Checked);
            }
        }
        UiBehavior::RadioGroup => {
            entity.insert(RadioGroup);
        }
        UiBehavior::RadioButton => {
            entity.insert(RadioButton);
            if node.state {
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
    if disabled && node.behavior.is_interactive() {
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
        if let Some(binding) = node.properties.text.as_ref() {
            match load_retail_text(
                binding,
                &pictures.retail_assets,
                &mut pictures.fonts,
                &mut pictures.font_handles,
            ) {
                Ok((font, layout, underline)) => {
                    if node.behavior == UiBehavior::TextEdit {
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
                    } else {
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
            match i16::try_from(picture_id)
                .map_err(|_| UiPictureBindingError::InvalidPictureId(picture_id))
                .and_then(|base_id| {
                    let active = picture_visual_active(node);
                    let shown_id = node.picture_visual.active_picture_id(base_id, active);
                    pictures
                        .picture(shown_id)
                        .map(|handle| (base_id, shown_id, handle))
                }) {
                Ok((base_id, shown_id, handle)) => {
                    let mut entity = commands.entity(entity);
                    entity.insert(ImageNode::new(handle));
                    if node.picture_visual != PictureVisual::Static {
                        entity.insert(CatalogPictureVisual {
                            base_id,
                            rule: node.picture_visual,
                            shown_id,
                        });
                    }
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

fn picture_visual_active(node: &CatalogNode) -> bool {
    node.state
        && matches!(
            node.behavior,
            UiBehavior::Checkbox | UiBehavior::Toggle | UiBehavior::RadioButton
        )
}

fn sync_catalog_picture_visuals(
    retail_assets: Option<Res<RetailAssetsResource>>,
    lookup: Res<UiPictureLookup>,
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
        let active = pressed || checked;
        let picture_id = visual.rule.active_picture_id(visual.base_id, active);
        if picture_id == visual.shown_id {
            continue;
        }
        let key = (picture_id, lookup.world_variant);
        if let Some(handle) = handles.0.get(&key) {
            image.image = handle.clone();
            visual.shown_id = picture_id;
            continue;
        }
        let Some(retail_assets) = retail_assets.as_ref() else {
            continue;
        };
        match load_retail_picture(
            picture_id,
            retail_assets,
            lookup.world_variant,
            &mut images,
            &mut handles,
        ) {
            Ok(handle) => {
                image.image = handle;
                visual.shown_id = picture_id;
            }
            Err(error) => {
                warn!(
                    "could not update retail picture {picture_id} for pressed/checked state: {error}"
                );
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
    use imperialism_formats::{UiCatalog, fourcc};
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
                    node.behavior == UiBehavior::Activate,
                    "node {} tag {} behavior {:?}",
                    node.id.0,
                    node.tag,
                    node.behavior
                );
                if node.behavior.is_interactive() {
                    assert_eq!(
                        world.get::<InteractionDisabled>(entity).is_some(),
                        node.interaction_disabled()
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
    fn catalog_content_insets_define_bevy_padding_and_text_content_box() {
        let catalog = catalog();
        let view = catalog_view(
            &catalog,
            &ScopedViewId {
                resource_file: "Startup.rsrc".to_owned(),
                resource_id: 1501,
            },
        );
        let country = view
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("coun"))
            .unwrap();
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
    fn projector_maps_behaviors_for_random_setup_controls() {
        let mut app = app();
        let setup = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1501,
        };
        let menu = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1500,
        };
        let setup_view = spawn_structure(&mut app, &setup);
        let menu_view = spawn_structure(&mut app, &menu);
        let catalog = app.world().resource::<UiCatalogResource>();

        let okay = setup_view.require_unique(catalog, fourcc!("okay")).unwrap();
        assert!(app.world().get::<UiButton>(okay).is_some());
        let globe = setup_view.require_unique(catalog, fourcc!("glob")).unwrap();
        assert!(app.world().get::<UiButton>(globe).is_some());
        let dif0 = setup_view.require_unique(catalog, fourcc!("dif0")).unwrap();
        assert!(app.world().get::<RadioButton>(dif0).is_some());
        let diff = setup_view.require_unique(catalog, fourcc!("diff")).unwrap();
        assert!(app.world().get::<RadioGroup>(diff).is_some());
        let map = setup_view.require_unique(catalog, fourcc!("map ")).unwrap();
        assert!(app.world().get::<RelativeCursorPosition>(map).is_some());

        let rand = menu_view.require_unique(catalog, fourcc!("rand")).unwrap();
        assert!(app.world().get::<UiButton>(rand).is_some());
    }

    #[test]
    fn require_under_distinguishes_duplicate_tags() {
        let mut app = app();
        let diplomacy = ScopedViewId {
            resource_file: "Diplo.rsrc".to_owned(),
            resource_id: 2008,
        };
        let spawned = spawn_structure(&mut app, &diplomacy);
        let catalog = app.world().resource::<UiCatalogResource>();
        let toolbar = spawned
            .require_under(catalog, fourcc!("topB"), fourcc!("trad"))
            .unwrap();
        assert!(
            spawned.require_unique(catalog, fourcc!("trad")).is_err(),
            "trad is ambiguous without an ancestor"
        );
        let leave = spawned
            .require_under(catalog, fourcc!("too3"), fourcc!("end "))
            .unwrap();
        assert_ne!(toolbar, leave);
    }

    #[test]
    fn require_path_walks_direct_parent_tags() {
        let mut app = app();
        let setup = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 1501,
        };
        let spawned = spawn_structure(&mut app, &setup);
        let catalog = app.world().resource::<UiCatalogResource>();
        let dif0 = spawned
            .require_path(catalog, &[fourcc!("diff"), fourcc!("dif0")])
            .unwrap();
        assert_eq!(
            dif0,
            spawned.require_unique(catalog, fourcc!("dif0")).unwrap()
        );
    }

    #[test]
    fn picture_visual_metadata_marks_up_down_okay_controls() {
        let catalog = catalog();
        for (resource_file, resource_id) in [("Startup.rsrc", 1501i16), ("Linger.rsrc", 954)] {
            let view = catalog_view(
                &catalog,
                &ScopedViewId {
                    resource_file: resource_file.to_owned(),
                    resource_id,
                },
            );
            let okay = view
                .nodes
                .iter()
                .find(|node| node.tag == fourcc!("okay"))
                .unwrap();
            assert_eq!(okay.picture_visual, PictureVisual::UpDown);
            assert!(okay.properties.picture_id.is_some());
        }
    }

    #[test]
    fn sync_swaps_picture_when_pressed() {
        let mut app = app();
        let base_id = 4512i16;
        let active_id = 4513i16;
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
            handles.0.insert((base_id, 0), base_handle.clone());
            handles.0.insert((active_id, 0), active_handle.clone());
        }
        let entity = app
            .world_mut()
            .spawn((
                CatalogPictureVisual {
                    base_id,
                    rule: PictureVisual::UpDown,
                    shown_id: base_id,
                },
                ImageNode::new(base_handle.clone()),
            ))
            .id();

        app.update();
        assert_eq!(
            app.world()
                .get::<CatalogPictureVisual>(entity)
                .unwrap()
                .shown_id,
            base_id
        );
        assert_eq!(
            app.world().get::<ImageNode>(entity).unwrap().image,
            base_handle
        );

        app.world_mut().entity_mut(entity).insert(Pressed);
        app.update();
        assert_eq!(
            app.world()
                .get::<CatalogPictureVisual>(entity)
                .unwrap()
                .shown_id,
            active_id
        );
        assert_eq!(
            app.world().get::<ImageNode>(entity).unwrap().image,
            active_handle
        );

        app.world_mut().entity_mut(entity).remove::<Pressed>();
        app.update();
        assert_eq!(
            app.world()
                .get::<CatalogPictureVisual>(entity)
                .unwrap()
                .shown_id,
            base_id
        );
        assert_eq!(
            app.world().get::<ImageNode>(entity).unwrap().image,
            base_handle
        );
    }
}
