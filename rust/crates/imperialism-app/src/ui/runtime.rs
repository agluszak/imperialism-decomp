use crate::RetailAssetsResource;
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

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct PresentedViewId(pub(crate) ScopedViewId);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PresentedUiNode(pub(crate) UiNodeId);

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct WidgetTag(pub(crate) FourCc);

/// Root entity of the view that owns this widget.
#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ViewRoot(pub(crate) Entity);

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiPictureLookup {
    pub(crate) world_variant: u8,
}

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UiViewRoot;

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

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) struct UiActivated {
    pub view: Entity,
    pub tag: FourCc,
}

#[derive(Debug, thiserror::Error)]
enum UiTextBindingError {
    #[error(transparent)]
    Style(#[from] RetailTextStyleError),
    #[error(transparent)]
    RetailAssets(#[from] RetailAssetError),
}

#[derive(Debug, thiserror::Error)]
enum UiPictureBindingError {
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

pub(crate) struct UiRuntimePlugin;

impl Plugin for UiRuntimePlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<RetailPictureHandles>()
            .init_resource::<RetailFontHandles>()
            .init_resource::<UiPictureLookup>()
            .add_message::<UiActivated>()
            .add_systems(Update, emit_ui_activations);
    }
}

/// Spawns a catalog view and binds retail pictures/fonts.
pub(crate) fn spawn_view(
    commands: &mut Commands,
    catalog: &UiCatalog,
    view_id: &ScopedViewId,
    pictures: &mut UiPictureResources,
) -> Option<SpawnedView> {
    let view = catalog.views.iter().find(|view| &view.id == view_id)?;
    let spawned = spawn_view_nodes(commands, catalog.logical_resolution, view);
    bind_view_assets(commands, view, &spawned, pictures);
    Some(spawned)
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
            UiViewRoot,
            PresentedViewId(view.id.clone()),
        ))
        .id();

    let mut nodes = HashMap::with_capacity(view.nodes.len());
    for node in &view.nodes {
        let entity = spawn_node(commands, node, root);
        nodes.insert(node.id, entity);
    }
    for node in &view.nodes {
        let entity = nodes[&node.id];
        let parent = node.parent.map_or(root, |parent| nodes[&parent]);
        commands.entity(entity).insert(ChildOf(parent));
    }
    SpawnedView { root, nodes }
}

fn spawn_node(commands: &mut Commands, node: &CatalogNode, root: Entity) -> Entity {
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
        ViewRoot(root),
        PresentedUiNode(node.id),
        WidgetTag(node.tag.clone()),
        if node.child_hit_test {
            FocusPolicy::Block
        } else {
            FocusPolicy::Pass
        },
    ));
    if node.interactive {
        entity.insert(Button);
        if !node.enabled || !node.input_gate {
            entity.insert(InteractionDisabled);
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
                Ok((font, layout, underline)) => {
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
                &pictures.retail_assets,
                pictures.lookup.world_variant,
                &mut pictures.images,
                &mut pictures.handles,
            ) {
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
    catalog_picture_id: i32,
    retail_assets: &RetailAssetsResource,
    world_variant: u8,
    images: &mut Assets<Image>,
    picture_handles: &mut RetailPictureHandles,
) -> Result<Handle<Image>, UiPictureBindingError> {
    let picture_id = i16::try_from(catalog_picture_id)
        .map_err(|_| UiPictureBindingError::InvalidPictureId(catalog_picture_id))?;
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

type UiActivationQuery<'w, 's> = Query<
    'w,
    's,
    (
        &'static Interaction,
        &'static ViewRoot,
        &'static WidgetTag,
        Option<&'static InteractionDisabled>,
    ),
    (With<Button>, Changed<Interaction>),
>;

fn emit_ui_activations(widgets: UiActivationQuery, mut activations: MessageWriter<UiActivated>) {
    for (interaction, view, tag, disabled) in &widgets {
        if *interaction == Interaction::Pressed && disabled.is_none() {
            activations.write(UiActivated {
                view: view.0,
                tag: tag.0.clone(),
            });
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
        app.add_plugins(MinimalPlugins)
            .init_resource::<Assets<Image>>()
            .init_resource::<Assets<Font>>()
            .insert_resource(UiCatalogResource::new(catalog()))
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
                let tag = world.get::<WidgetTag>(entity).unwrap();
                let ui = world.get::<Node>(entity).unwrap();
                let focus_policy = world.get::<FocusPolicy>(entity).unwrap();
                let parent = world.get::<ChildOf>(entity).unwrap();
                assert_eq!(tag.0, node.tag);
                assert_eq!(world.get::<Button>(entity).is_some(), node.interactive);
                assert_eq!(
                    world.get::<InteractionDisabled>(entity).is_some(),
                    node.interactive && (!node.enabled || !node.input_gate)
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
                let expected_parent = node.parent.map_or(spawned.root, |id| spawned.nodes[&id]);
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
    fn enabled_controls_emit_activations_and_disabled_controls_do_not() {
        let mut app = app();
        let confirmation = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 953,
        };
        let map = ScopedViewId {
            resource_file: "MapView.rsrc".to_owned(),
            resource_id: 2013,
        };
        let confirmation_view = spawn_structure(&mut app, &confirmation);
        let map_view = spawn_structure(&mut app, &map);

        let catalog = catalog();
        let confirmation_catalog = catalog_view(&catalog, &confirmation);
        let map_catalog = catalog_view(&catalog, &map);
        let mut pressed = Vec::new();
        for tag in ["okay", "cncl"] {
            pressed.push(confirmation_view.tagged(confirmation_catalog, tag).unwrap());
        }
        for tag in ["Flag", "quer"] {
            let entity = map_view.tagged(map_catalog, tag).unwrap();
            assert!(app.world().get::<InteractionDisabled>(entity).is_some());
            pressed.push(entity);
        }
        app.insert_resource(PressedEntities(pressed))
            .add_systems(PreUpdate, press_entities);
        app.update();

        let activations = app
            .world_mut()
            .resource_mut::<Messages<UiActivated>>()
            .drain()
            .collect::<Vec<_>>();
        let tags = activations
            .iter()
            .map(|activation| activation.tag.0.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(tags, HashSet::from(["okay", "cncl"]));
        assert!(
            activations
                .iter()
                .all(|activation| activation.view == confirmation_view.root)
        );
    }

    #[test]
    fn despawn_removes_only_the_requested_view_root() {
        let mut app = app();
        let view = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 953,
        };
        let first = spawn_structure(&mut app, &view);
        let second = spawn_structure(&mut app, &view);
        app.world_mut().entity_mut(first.root).despawn();
        app.world_mut().flush();

        let remaining = app
            .world_mut()
            .query_filtered::<Entity, With<UiViewRoot>>()
            .iter(app.world())
            .collect::<HashSet<_>>();
        assert_eq!(remaining, HashSet::from([second.root]));
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
            match load_retail_text(binding, retail_assets, &mut fonts, &mut handles) {
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
                    FontHinting::default(),
                )
                .unwrap();
            let _ = (
                content_origin,
                layout_info,
                &mut canvas,
                &fonts,
                &mut font_cx,
                &mut layout_cx,
            );
        }
        let mut ppm = b"P6\n640 480\n255\n".to_vec();
        ppm.extend_from_slice(&canvas);
        ppm
    }
}
