use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub const UI_CATALOG_SCHEMA: &str = "imperialism.ui_catalog.v1";

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ScopedViewId {
    pub resource_file: String,
    pub resource_id: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UiNodeId(pub u32);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FourCc(pub String);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WidgetKind {
    Container,
    Window,
    FloatingWindow,
    Picture,
    PictureButton,
    Toggle,
    Checkbox,
    StaticText,
    NumericValue,
    EditControl,
    ListOrScrollingPane,
    RadioOrClusterControl,
    CustomCanvas,
    Specialized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogicalRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiCatalogSource {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiCatalogSources {
    pub mac_view_ir: UiCatalogSource,
    pub mac_strings: UiCatalogSource,
    pub mac_text_resources: UiCatalogSource,
    pub factory_manifest: UiCatalogSource,
    pub windows_deltas: UiCatalogSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiStyle {
    pub word: i32,
    pub packed_color: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiTextBinding {
    pub resource_id: i32,
    pub resource_index: i32,
    pub value: Option<String>,
    pub source: Option<String>,
    pub font_family: i32,
    pub face_flags: i32,
    pub point_size: i32,
    pub style_ref: i32,
    pub alignment: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiNumberRange {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiWindowColor {
    pub behavior_flag: i32,
    pub triplet_flag: i32,
    pub foreground: i64,
    pub background: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiWindowProperties {
    pub flags: i32,
    pub style_type: i32,
    pub topmost: i32,
    pub resource_6f: i32,
    pub resource_6e: i32,
    pub captioned_frame: i32,
    pub resource_6c: i32,
    pub resource_71: i32,
    pub color: Option<UiWindowColor>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WidgetProperties {
    pub frame_style: Option<i32>,
    pub content_insets: Option<[i32; 4]>,
    pub picture_id: Option<i32>,
    pub control_state: Option<i32>,
    pub style: Option<UiStyle>,
    pub text: Option<UiTextBinding>,
    pub max_chars: Option<i32>,
    pub number: Option<UiNumberRange>,
    pub cluster_value: Option<i64>,
    pub window: Option<UiWindowProperties>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiNode {
    pub id: UiNodeId,
    pub parent: Option<UiNodeId>,
    pub tag: FourCc,
    pub kind: WidgetKind,
    pub rect: LogicalRect,
    pub state: bool,
    pub enabled: bool,
    pub input_gate: bool,
    pub child_hit_test: bool,
    pub control_value: i32,
    pub properties: WidgetProperties,
    pub legacy_type: FourCc,
    pub legacy_class: Option<String>,
    pub resolved_class: String,
    pub resource_offset: u32,
    pub source: String,
    pub confidence: EvidenceConfidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiView {
    pub id: ScopedViewId,
    pub event: i32,
    pub root: UiNodeId,
    pub nodes: Vec<UiNode>,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UiCatalogV1 {
    pub schema: String,
    pub logical_resolution: [u32; 2],
    pub sources: UiCatalogSources,
    pub views: Vec<UiView>,
}

#[derive(Debug, thiserror::Error)]
pub enum UiCatalogError {
    #[error("could not read normalized UI catalog: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode normalized UI catalog: {0}")]
    Json(#[source] serde_json::Error),
    #[error("invalid normalized UI catalog: {0}")]
    Validation(String),
}

impl UiCatalogV1 {
    pub fn validate(&self) -> Result<(), UiCatalogError> {
        if self.schema != UI_CATALOG_SCHEMA {
            return Err(validation(format!("unsupported schema {:?}", self.schema)));
        }
        if self.logical_resolution != [640, 480] {
            return Err(validation(format!(
                "retail logical resolution must be 640x480, found {}x{}",
                self.logical_resolution[0], self.logical_resolution[1]
            )));
        }
        for source in [
            &self.sources.mac_view_ir,
            &self.sources.mac_strings,
            &self.sources.mac_text_resources,
            &self.sources.factory_manifest,
            &self.sources.windows_deltas,
        ] {
            if source.path.is_empty()
                || source.sha256.len() != 64
                || !source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(validation(format!(
                    "source {:?} must have a path and SHA-256 digest",
                    source.path
                )));
            }
        }

        let mut view_ids = HashSet::new();
        for view in &self.views {
            if view.id.resource_file.is_empty() {
                return Err(validation(
                    "view resource file must not be empty".to_owned(),
                ));
            }
            if !view_ids.insert(view.id.clone()) {
                return Err(validation(format!(
                    "duplicate scoped view {}:{}",
                    view.id.resource_file, view.id.resource_id
                )));
            }
            validate_view(view)?;
        }
        Ok(())
    }

    pub fn view(&self, id: &ScopedViewId) -> Option<&UiView> {
        self.views.iter().find(|view| &view.id == id)
    }
}

fn validate_view(view: &UiView) -> Result<(), UiCatalogError> {
    if view.nodes.is_empty() {
        return Err(validation(format!(
            "{}:{} has no nodes",
            view.id.resource_file, view.id.resource_id
        )));
    }
    let mut nodes = HashMap::new();
    for node in &view.nodes {
        validate_four_cc(&node.tag, "tag")?;
        validate_four_cc(&node.legacy_type, "legacy type")?;
        if node.rect.width < 0 || node.rect.height < 0 {
            return Err(validation(format!(
                "{}:{} node {} has negative dimensions",
                view.id.resource_file, view.id.resource_id, node.id.0
            )));
        }
        if node.resource_offset != node.id.0 {
            return Err(validation(format!(
                "{}:{} node {} does not preserve its resource offset",
                view.id.resource_file, view.id.resource_id, node.id.0
            )));
        }
        if node.resolved_class.is_empty() || node.source.is_empty() {
            return Err(validation(format!(
                "{}:{} node {} lacks class or evidence metadata",
                view.id.resource_file, view.id.resource_id, node.id.0
            )));
        }
        if nodes.insert(node.id, node.parent).is_some() {
            return Err(validation(format!(
                "{}:{} has duplicate node {}",
                view.id.resource_file, view.id.resource_id, node.id.0
            )));
        }
    }
    if !nodes.contains_key(&view.root) {
        return Err(validation(format!(
            "{}:{} root {} is missing",
            view.id.resource_file, view.id.resource_id, view.root.0
        )));
    }
    let roots = nodes.values().filter(|parent| parent.is_none()).count();
    if roots != 1 || nodes[&view.root].is_some() {
        return Err(validation(format!(
            "{}:{} must have exactly one declared root",
            view.id.resource_file, view.id.resource_id
        )));
    }
    for (id, parent) in &nodes {
        let Some(mut ancestor) = *parent else {
            continue;
        };
        let mut visited = HashSet::from([*id]);
        loop {
            if !visited.insert(ancestor) {
                return Err(validation(format!(
                    "{}:{} node {} has a parent cycle",
                    view.id.resource_file, view.id.resource_id, id.0
                )));
            }
            match nodes.get(&ancestor) {
                Some(Some(parent)) => ancestor = *parent,
                Some(None) => break,
                None => {
                    return Err(validation(format!(
                        "{}:{} node {} references missing parent {}",
                        view.id.resource_file, view.id.resource_id, id.0, ancestor.0
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_four_cc(value: &FourCc, label: &str) -> Result<(), UiCatalogError> {
    if value.0.len() != 4 || !value.0.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
        return Err(validation(format!(
            "{label} {:?} is not a printable FourCC",
            value.0
        )));
    }
    Ok(())
}

fn validation(message: String) -> UiCatalogError {
    UiCatalogError::Validation(message)
}

pub fn read_ui_catalog(path: &Path) -> Result<UiCatalogV1, UiCatalogError> {
    let bytes = fs::read(path).map_err(UiCatalogError::Io)?;
    let catalog = serde_json::from_slice::<UiCatalogV1>(&bytes).map_err(UiCatalogError::Json)?;
    catalog.validate()?;
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED_CATALOG: &str = include_str!("../assets/ui_catalog_v1.json");

    fn generated_catalog() -> UiCatalogV1 {
        serde_json::from_str(GENERATED_CATALOG).unwrap()
    }

    #[test]
    fn generated_catalog_validates_and_round_trips() {
        let catalog = generated_catalog();
        catalog.validate().unwrap();
        let encoded = serde_json::to_vec(&catalog).unwrap();
        let decoded: UiCatalogV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, catalog);
    }

    #[test]
    fn generated_catalog_contains_the_launch_slice() {
        let catalog = generated_catalog();
        let expected = [
            ("Startup.rsrc", 1500),
            ("Startup.rsrc", 1501),
            ("Startup.rsrc", 952),
            ("Startup.rsrc", 953),
            ("FlagView.rsrc", 8451),
            ("MapView.rsrc", 2013),
        ];
        for (resource_file, resource_id) in expected {
            assert!(
                catalog
                    .view(&ScopedViewId {
                        resource_file: resource_file.to_owned(),
                        resource_id,
                    })
                    .is_some(),
                "missing {resource_file}:{resource_id}"
            );
        }
    }

    #[test]
    fn resource_file_scopes_colliding_numeric_ids() {
        let startup = ScopedViewId {
            resource_file: "Startup.rsrc".to_owned(),
            resource_id: 953,
        };
        let other = ScopedViewId {
            resource_file: "Other.rsrc".to_owned(),
            resource_id: 953,
        };
        assert_ne!(startup, other);
    }
}
