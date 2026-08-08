use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct LogicalRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiStyle {
    pub word: i32,
    pub packed_color: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiTextBinding {
    pub resource_id: i32,
    pub resource_index: i32,
    pub value: Option<String>,
    pub font_family: i32,
    pub face_flags: i32,
    pub point_size: i32,
    pub style_ref: i32,
    pub alignment: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiNumberRange {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiWindowColor {
    pub behavior_flag: i32,
    pub triplet_flag: i32,
    pub foreground: i64,
    pub background: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct UiNode {
    pub id: UiNodeId,
    pub parent: Option<UiNodeId>,
    pub tag: FourCc,
    pub kind: WidgetKind,
    pub rect: LogicalRect,
    pub state: bool,
    pub enabled: bool,
    pub interactive: bool,
    pub input_gate: bool,
    pub child_hit_test: bool,
    pub control_value: i32,
    pub properties: WidgetProperties,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiView {
    pub id: ScopedViewId,
    pub event: i32,
    pub root: UiNodeId,
    pub nodes: Vec<UiNode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiCatalog {
    pub logical_resolution: [u32; 2],
    pub views: Vec<UiView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED_CATALOG: &str = include_str!("../assets/ui_catalog.json");

    fn generated_catalog() -> UiCatalog {
        serde_json::from_str(GENERATED_CATALOG).unwrap()
    }

    #[test]
    fn generated_catalog_round_trips() {
        let catalog = generated_catalog();
        let encoded = serde_json::to_vec(&catalog).unwrap();
        let decoded: UiCatalog = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, catalog);
    }

    #[test]
    fn generated_catalog_contains_the_launch_slice() {
        let catalog = generated_catalog();
        let expected = [
            ("Linger.rsrc", 954),
            ("Startup.rsrc", 1500),
            ("Startup.rsrc", 1501),
            ("Startup.rsrc", 952),
            ("Startup.rsrc", 953),
            ("FlagView.rsrc", 8451),
            ("MapView.rsrc", 2013),
            ("Trade.rsrc", 2009),
            ("Citymain.rsrc", 2011),
            ("Transport.rsrc", 2014),
            ("Diplo.rsrc", 2008),
        ];
        for (resource_file, resource_id) in expected {
            assert!(
                catalog.views.iter().any(|view| {
                    view.id.resource_file == resource_file && view.id.resource_id == resource_id
                }),
                "missing {resource_file}:{resource_id}"
            );
        }
    }

    #[test]
    fn generated_catalog_uses_explicit_interaction_semantics() {
        let catalog = generated_catalog();
        let random_setup = catalog
            .views
            .iter()
            .find(|view| view.id.resource_file == "Startup.rsrc" && view.id.resource_id == 1501)
            .unwrap();
        let difficulty = random_setup
            .nodes
            .iter()
            .find(|node| node.tag.0 == "dif0")
            .unwrap();
        let heading = random_setup
            .nodes
            .iter()
            .find(|node| node.tag.0 == "dift")
            .unwrap();
        let globe = random_setup
            .nodes
            .iter()
            .find(|node| node.tag.0 == "glob")
            .unwrap();
        assert!(difficulty.interactive);
        assert!(!heading.interactive);
        assert!(globe.interactive);
    }

    #[test]
    fn generated_catalog_contains_the_retail_planet_seed_dialog() {
        let catalog = generated_catalog();
        let dialog = catalog
            .views
            .iter()
            .find(|view| view.id.resource_file == "Linger.rsrc" && view.id.resource_id == 954)
            .unwrap();
        let nodes = dialog
            .nodes
            .iter()
            .map(|node| (node.tag.0.as_str(), node))
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(dialog.event, 0x03ba);
        assert_eq!(nodes["plan"].kind, WidgetKind::EditControl);
        assert!(nodes["plan"].interactive);
        assert_eq!(nodes["plan"].properties.max_chars, Some(32));
        assert!(!nodes["1or2"].state);
        assert!(!nodes["1or2"].enabled);
        assert!(nodes["okay"].interactive);
        assert!(!nodes["canc"].state);
        assert!(!nodes["canc"].enabled);
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
