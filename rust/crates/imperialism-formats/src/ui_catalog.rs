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
    pub(crate) const fn get(self) -> i16 {
        self.0
    }
}

impl fmt::Display for PictureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
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

/// Interaction semantics needed by the Rust UI runtime.
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
    pub fn active_picture_id(self, base: PictureId, active: bool) -> PictureId {
        match self {
            Self::Static => base,
            Self::UpDown => {
                if active {
                    PictureId::new(base.get() + 1)
                } else {
                    base
                }
            }
            Self::CzechBox => {
                if active {
                    PictureId::new(base.get() | 1)
                } else {
                    PictureId::new(base.get() & !1)
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
pub struct UiTextBinding {
    pub value: String,
    pub font_family: i32,
    pub face_flags: i32,
    pub point_size: i32,
    pub alignment: i32,
    pub max_chars: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiNode {
    pub id: UiNodeId,
    #[serde(default)]
    pub parent: Option<UiNodeId>,
    pub tag: FourCc,
    #[serde(default)]
    pub behavior: UiBehavior,
    #[serde(default)]
    pub picture_visual: PictureVisual,
    pub rect: LogicalRect,
    #[serde(default)]
    pub checked: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub content_insets: [i32; 4],
    #[serde(default)]
    pub picture_id: Option<PictureId>,
    #[serde(default)]
    pub text: Option<UiTextBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UiView {
    pub id: ScopedViewId,
    pub nodes: Vec<UiNode>,
}

/// Precomputed lookups over a catalog view hierarchy.
#[derive(Clone, Debug)]
pub struct UiViewIndex {
    by_id: HashMap<UiNodeId, usize>,
    by_tag: HashMap<FourCc, Vec<UiNodeId>>,
}

impl UiViewIndex {
    pub fn build(view: &UiView) -> Self {
        let mut by_id = HashMap::with_capacity(view.nodes.len());
        let mut by_tag: HashMap<FourCc, Vec<UiNodeId>> = HashMap::new();
        for (index, node) in view.nodes.iter().enumerate() {
            by_id.insert(node.id, index);
            by_tag.entry(node.tag).or_default().push(node.id);
        }
        Self { by_id, by_tag }
    }

    pub fn node<'a>(&self, view: &'a UiView, id: UiNodeId) -> Option<&'a UiNode> {
        self.by_id.get(&id).map(|&index| &view.nodes[index])
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

        assert_eq!(nodes[&fourcc!("plan")].behavior, UiBehavior::TextEdit);
        assert_eq!(
            nodes[&fourcc!("plan")].text.as_ref().unwrap().max_chars,
            Some(32)
        );
        assert!(nodes[&fourcc!("1or2")].disabled);
        assert_eq!(nodes[&fourcc!("okay")].behavior, UiBehavior::Activate);
        assert_eq!(
            nodes[&fourcc!("okay")].picture_visual,
            PictureVisual::UpDown
        );
        assert!(nodes[&fourcc!("canc")].disabled);
    }

    #[test]
    fn removed_generator_provenance_is_rejected_at_the_runtime_boundary() {
        let mut value = serde_json::from_str::<serde_json::Value>(GENERATED_CATALOG).unwrap();
        value["views"][0]["event"] = serde_json::Value::from(0x1234);
        assert!(serde_json::from_value::<UiCatalog>(value).is_err());
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
        assert_eq!(
            PictureVisual::UpDown.active_picture_id(PictureId::new(4512), false),
            PictureId::new(4512)
        );
        assert_eq!(
            PictureVisual::UpDown.active_picture_id(PictureId::new(4512), true),
            PictureId::new(4513)
        );
        assert_eq!(
            PictureVisual::CzechBox.active_picture_id(PictureId::new(100), false),
            PictureId::new(100)
        );
        assert_eq!(
            PictureVisual::CzechBox.active_picture_id(PictureId::new(100), true),
            PictureId::new(101)
        );
        assert_eq!(
            PictureVisual::CzechBox.active_picture_id(PictureId::new(101), false),
            PictureId::new(100)
        );
    }
}
