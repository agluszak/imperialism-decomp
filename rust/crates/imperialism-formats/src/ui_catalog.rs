use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedViewId {
    pub resource_file: String,
    pub resource_id: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UiNodeId(pub u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PictureId(i16);
impl PictureId {
    pub const fn new(value: i16) -> Self {
        Self(value)
    }
    pub const fn get(self) -> i16 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FourCc([u8; 4]);

pub const OKAY: FourCc = FourCc(*b"okay");
pub const TRADE: FourCc = FourCc(*b"trad");

impl FourCc {
    pub const fn new(value: &str) -> Self {
        assert!(
            value.len() == 4,
            "FourCc tags must be exactly four characters (pad with spaces)"
        );
        let bytes = value.as_bytes();
        Self([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    pub const fn from_bytes(value: [u8; 4]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(self) -> [u8; 4] {
        self.0
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("FourCc must be UTF-8")
    }
}

impl fmt::Debug for FourCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FourCc").field(&self.as_str()).finish()
    }
}

impl fmt::Display for FourCc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for FourCc {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for FourCc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FourCc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "FourCc tags must be exactly four characters, got {value:?}"
            )));
        }
        Ok(Self::new(&value))
    }
}

/// Compile-time four-character-code helper that rejects mistyped tags such as `"key"`.
#[macro_export]
macro_rules! fourcc {
    ($lit:literal) => {{
        const TAG: $crate::FourCc = $crate::FourCc::new($lit);
        TAG
    }};
}

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

/// Interaction semantics independent from [`WidgetKind`] visual representation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiBehavior {
    #[default]
    Passive,
    Activate,
    Checkbox,
    Toggle,
    RadioGroup,
    RadioButton,
    TextEdit,
    ScrollArea,
    PointerCanvas,
}

impl UiBehavior {
    pub const fn is_interactive(self) -> bool {
        !matches!(self, Self::Passive)
    }
}

/// How retail picture art reacts to Pressed / Checked.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PictureVisual {
    /// Single resting picture; no interaction swap.
    #[default]
    Static,
    /// `TUpDownPictureButton` / `TRadioPictureButton`: pressed/checked uses `picture_id + 1`.
    UpDown,
    /// `TCzechBox`: odd ID when checked/pressed, even when idle.
    CzechBox,
}

impl PictureVisual {
    pub fn active_picture_id(self, base: i16, active: bool) -> i16 {
        match self {
            Self::Static => base,
            Self::UpDown => {
                if active {
                    base.saturating_add(1)
                } else {
                    base
                }
            }
            Self::CzechBox => {
                if active {
                    base | 1
                } else {
                    base & !1
                }
            }
        }
    }
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
    pub picture_id: Option<PictureId>,
    pub control_state: Option<i32>,
    pub style: Option<UiStyle>,
    pub text: Option<UiTextBinding>,
    pub max_chars: Option<i32>,
    pub number: Option<UiNumberRange>,
    pub cluster_value: Option<i64>,
    pub window: Option<UiWindowProperties>,
}

impl WidgetProperties {
    /// Non-negative edit limit from the catalog. Negative retail values are rejected.
    pub fn max_characters(&self) -> Option<u32> {
        self.max_chars.and_then(|value| u32::try_from(value).ok())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiNode {
    pub id: UiNodeId,
    pub parent: Option<UiNodeId>,
    pub tag: FourCc,
    pub kind: WidgetKind,
    pub behavior: UiBehavior,
    #[serde(default)]
    pub picture_visual: PictureVisual,
    pub rect: LogicalRect,
    pub state: bool,
    pub enabled: bool,
    pub input_gate: bool,
    pub child_hit_test: bool,
    pub control_value: i32,
    pub properties: WidgetProperties,
}

impl UiNode {
    pub const fn interaction_disabled(&self) -> bool {
        !self.enabled || !self.input_gate
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiView {
    pub id: ScopedViewId,
    pub event: i32,
    pub root: UiNodeId,
    pub nodes: Vec<UiNode>,
}

/// Precomputed lookups over a catalog view hierarchy.
#[derive(Clone, Debug)]
pub struct UiViewIndex {
    by_id: HashMap<UiNodeId, usize>,
    by_tag: HashMap<FourCc, Vec<UiNodeId>>,
    children: HashMap<Option<UiNodeId>, Vec<UiNodeId>>,
}

impl UiViewIndex {
    pub fn build(view: &UiView) -> Self {
        let mut by_id = HashMap::with_capacity(view.nodes.len());
        let mut by_tag: HashMap<FourCc, Vec<UiNodeId>> = HashMap::new();
        let mut children: HashMap<Option<UiNodeId>, Vec<UiNodeId>> = HashMap::new();
        for (index, node) in view.nodes.iter().enumerate() {
            by_id.insert(node.id, index);
            by_tag.entry(node.tag).or_default().push(node.id);
            children.entry(node.parent).or_default().push(node.id);
        }
        Self {
            by_id,
            by_tag,
            children,
        }
    }

    pub fn node<'a>(&self, view: &'a UiView, id: UiNodeId) -> Option<&'a UiNode> {
        self.by_id.get(&id).map(|&index| &view.nodes[index])
    }

    pub fn children_of(&self, parent: Option<UiNodeId>) -> &[UiNodeId] {
        self.children.get(&parent).map_or(&[], Vec::as_slice)
    }

    pub fn tagged(&self, tag: FourCc) -> &[UiNodeId] {
        self.by_tag.get(&tag).map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiCatalog {
    pub logical_resolution: [u32; 2],
    pub views: Vec<UiView>,
}

impl UiCatalog {
    pub fn view(&self, id: &ScopedViewId) -> Option<&UiView> {
        self.views.iter().find(|view| &view.id == id)
    }
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
        assert!(
            catalog.views.len() >= 81,
            "expected all resource-backed factory views, found {}",
            catalog.views.len()
        );
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
            .find(|node| node.tag == fourcc!("dif0"))
            .unwrap();
        let heading = random_setup
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("dift"))
            .unwrap();
        let globe = random_setup
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("glob"))
            .unwrap();
        let group = random_setup
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("diff"))
            .unwrap();
        assert_eq!(difficulty.behavior, UiBehavior::RadioButton);
        assert_eq!(heading.behavior, UiBehavior::Passive);
        assert_eq!(globe.behavior, UiBehavior::Activate);
        assert_eq!(group.behavior, UiBehavior::RadioGroup);
        assert_eq!(globe.kind, WidgetKind::Picture);
        assert_eq!(globe.picture_visual, PictureVisual::Static);
        let okay = random_setup
            .nodes
            .iter()
            .find(|node| node.tag == fourcc!("okay"))
            .unwrap();
        assert_eq!(okay.picture_visual, PictureVisual::UpDown);
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
            .map(|node| (node.tag, node))
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(dialog.event, 0x03ba);
        assert_eq!(nodes[&fourcc!("plan")].kind, WidgetKind::EditControl);
        assert_eq!(nodes[&fourcc!("plan")].behavior, UiBehavior::TextEdit);
        assert_eq!(nodes[&fourcc!("plan")].properties.max_chars, Some(32));
        assert_eq!(
            nodes[&fourcc!("plan")].properties.max_characters(),
            Some(32)
        );
        assert_eq!(
            WidgetProperties {
                max_chars: Some(-1),
                ..Default::default()
            }
            .max_characters(),
            None
        );
        assert!(!nodes[&fourcc!("1or2")].state);
        assert!(!nodes[&fourcc!("1or2")].enabled);
        assert_eq!(nodes[&fourcc!("okay")].behavior, UiBehavior::Activate);
        assert_eq!(
            nodes[&fourcc!("okay")].picture_visual,
            PictureVisual::UpDown
        );
        assert!(!nodes[&fourcc!("canc")].state);
        assert!(!nodes[&fourcc!("canc")].enabled);
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

    #[test]
    fn fourcc_preserves_trailing_spaces() {
        assert_eq!(fourcc!("key ").as_str(), "key ");
        assert_eq!(fourcc!("end ").as_str(), "end ");
        assert_eq!(FourCc::new("map ").as_str(), "map ");
        const PLANET_KEY: FourCc = fourcc!("key ");
        assert_eq!(PLANET_KEY.as_str(), "key ");
    }

    #[test]
    fn picture_visual_selects_retail_active_ids() {
        assert_eq!(PictureVisual::UpDown.active_picture_id(4512, false), 4512);
        assert_eq!(PictureVisual::UpDown.active_picture_id(4512, true), 4513);
        assert_eq!(PictureVisual::CzechBox.active_picture_id(100, false), 100);
        assert_eq!(PictureVisual::CzechBox.active_picture_id(100, true), 101);
        assert_eq!(PictureVisual::CzechBox.active_picture_id(101, false), 100);
    }
}
