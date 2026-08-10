use crate::color::DibPalette;
use crate::retail_resources::*;
use crate::{PictureId, RetailFontFace};
use pelite::pe32::{Pe, PeFile};
use pelite::resources::{FindError, Name};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

const ENGLISH_LANGUAGE: u32 = 1033;
const STRING_RESOURCE_TYPE: u32 = 6;
const STRINGS_ARCHIVE_PATH: &str = "Data/STR#ENU.GOB";

const PICTURE_ARCHIVE_PATHS: [&str; 4] = [
    "Data/pictenu.gob",
    "Data/pictpaid.gob",
    "Data/pictwv0.gob",
    "Data/pictuniv.gob",
];

/// Direct access to the retail files needed by the current application.
///
/// The object owns raw archive/font bytes and indexes English PE resource ranges during opening.
/// It deliberately retains no borrowed PE views.
#[derive(Debug)]
pub struct RetailAssets {
    pictures: [ResourceArchive; 4],
    strings: ResourceArchive,
    fonts: RetailFonts,
    default_dib_palette: DibPalette,
}

impl RetailAssets {
    /// Opens the current English GOG input files and indexes their English resources.
    pub fn open(retail_dir: impl AsRef<Path>) -> Result<Self, RetailAssetError> {
        let root = retail_dir.as_ref().to_owned();
        let pictures = [
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[0])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[1])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[2])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[3])?,
        ];
        let default_dib_palette = {
            let archive = &pictures[0];
            let dib = archive
                .find(
                    ResourceName::Id(2),
                    ResourceName::Text("950.BMP".to_owned()),
                )
                .ok_or(RetailAssetError::DefaultDibPaletteNotFound)?;
            bitmap_palette_rgb(dib).map_err(|error| resource_error(&archive.path, error))?
        };
        let strings = ResourceArchive::read(&root, STRINGS_ARCHIVE_PATH)?;
        let fonts = RetailFonts::read(&root)?;

        Ok(Self {
            pictures,
            strings,
            fonts,
            default_dib_palette,
        })
    }

    /// Resolves a retail picture using name-before-numeric and library-slot precedence.
    ///
    /// The returned bytes are a BMP file assembled from the retail DIB resource.
    pub fn picture(&self, picture_id: PictureId) -> Result<Vec<u8>, RetailAssetError> {
        let (path, dib) = self.picture_resource(picture_id)?;
        bitmap_resource_to_bmp(dib).map_err(|error| resource_error(path, error))
    }

    /// Resolves a 1-bpp or 8-bpp retail picture as unpacked palette indexes.
    pub fn indexed_picture(
        &self,
        picture_id: PictureId,
    ) -> Result<IndexedPicture, RetailAssetError> {
        let (path, dib) = self.picture_resource(picture_id)?;
        bitmap_resource_to_indexed_picture(dib).map_err(|error| resource_error(path, error))
    }

    /// Loads one direct `LoadStringA` index from the English retail string library.
    pub fn string(&self, group: i16, direct_index: i16) -> Result<String, RetailAssetError> {
        let string_id = group.wrapping_mul(100).wrapping_add(direct_index) as u16;
        let block_id = u32::from((string_id >> 4) + 1);
        let slot = usize::from(string_id & 0xf);
        let block = self
            .strings
            .find(
                ResourceName::Id(STRING_RESOURCE_TYPE),
                ResourceName::Id(block_id),
            )
            .ok_or(RetailAssetError::StringNotFound {
                group,
                direct_index,
            })?;
        decode_string_table_entry(&self.strings.path, block, slot)
    }

    fn picture_resource(&self, picture_id: PictureId) -> Result<(&Path, &[u8]), RetailAssetError> {
        let named = format!("{picture_id}.BMP");
        let names = [
            ResourceName::Text(named),
            ResourceName::Id(u32::from(picture_id.get() as u16)),
        ];
        for name in &names {
            for archive in &self.pictures {
                if let Some(dib) = archive.find(ResourceName::Id(2), name.clone()) {
                    return Ok((&archive.path, dib));
                }
            }
        }
        Err(RetailAssetError::PictureNotFound(picture_id))
    }

    /// Returns the RGB palette carried by the retail default DIB, `950.BMP`.
    ///
    /// The native UI builds its indexed preview surfaces with this named bitmap
    /// from the localized picture library before it draws the random-map preview.
    pub fn default_dib_palette(&self) -> &DibPalette {
        &self.default_dib_palette
    }

    /// Returns the font bytes consumed by the UI.
    pub fn font_bytes(&self, face: RetailFontFace) -> &[u8] {
        self.fonts.bytes(face)
    }
}

#[derive(Debug)]
struct RetailFonts {
    belwe_bold: Vec<u8>,
    book_antiqua_regular: Vec<u8>,
    book_antiqua_bold: Vec<u8>,
}

impl RetailFonts {
    fn read(root: &Path) -> Result<Self, RetailAssetError> {
        Ok(Self {
            belwe_bold: read_font(root, RetailFontFace::BelweBold.relative_path())?,
            book_antiqua_regular: read_font(
                root,
                RetailFontFace::BookAntiquaRegular.relative_path(),
            )?,
            book_antiqua_bold: read_font(root, RetailFontFace::BookAntiquaBold.relative_path())?,
        })
    }

    fn bytes(&self, face: RetailFontFace) -> &[u8] {
        match face {
            RetailFontFace::BelweBold => &self.belwe_bold,
            RetailFontFace::BookAntiquaRegular => &self.book_antiqua_regular,
            RetailFontFace::BookAntiquaBold => &self.book_antiqua_bold,
        }
    }
}

#[derive(Debug)]
struct ResourceArchive {
    path: PathBuf,
    bytes: Vec<u8>,
    english_resources: BTreeMap<ResourceKey, Range<usize>>,
}

impl ResourceArchive {
    fn read(root: &Path, relative: &str) -> Result<Self, RetailAssetError> {
        let path = root.join(relative);
        let bytes = read_file(&path)?;
        let english_resources = index_english_resources(&path, &bytes)?;
        Ok(Self {
            path,
            bytes,
            english_resources,
        })
    }

    fn find(&self, resource_type: ResourceName, name: ResourceName) -> Option<&[u8]> {
        let key = ResourceKey {
            resource_type,
            name,
        };
        self.english_resources
            .get(&key)
            .map(|range| &self.bytes[range.clone()])
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ResourceName {
    Id(u32),
    Text(String),
}

impl ResourceName {
    fn from_pelite(name: Name<'_>, path: &Path) -> Result<Self, RetailAssetError> {
        match name {
            Name::Id(id) => Ok(Self::Id(id)),
            Name::Wide(words) => String::from_utf16(words)
                .map(Self::Text)
                .map_err(|error| resource_error(path, error)),
            Name::Str(text) => Ok(Self::Text(text.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceKey {
    resource_type: ResourceName,
    name: ResourceName,
}

fn index_english_resources(
    path: &Path,
    bytes: &[u8],
) -> Result<BTreeMap<ResourceKey, Range<usize>>, RetailAssetError> {
    let pe = PeFile::from_bytes(bytes).map_err(|error| resource_error(path, error))?;
    let resources = pe
        .resources()
        .map_err(|error| resource_error(path, error))?;
    let root = resources
        .root()
        .map_err(|error| resource_error(path, error))?;
    let mut index = BTreeMap::new();
    for type_entry in root.entries() {
        let resource_type = ResourceName::from_pelite(
            type_entry
                .name()
                .map_err(|error| resource_error(path, error))?,
            path,
        )?;
        let names = type_entry
            .entry()
            .map_err(|error| resource_error(path, error))?
            .dir()
            .ok_or_else(|| invalid_resource_shape(path, "resource type is not a directory"))?;
        for name_entry in names.entries() {
            let name = ResourceName::from_pelite(
                name_entry
                    .name()
                    .map_err(|error| resource_error(path, error))?,
                path,
            )?;
            let languages = name_entry
                .entry()
                .map_err(|error| resource_error(path, error))?
                .dir()
                .ok_or_else(|| invalid_resource_shape(path, "resource name is not a directory"))?;
            let data = match languages.get_data(Name::Id(ENGLISH_LANGUAGE)) {
                Ok(data) => data,
                Err(FindError::NotFound) => continue,
                Err(error) => return Err(resource_error(path, error)),
            };
            let start = pe
                .rva_to_file_offset(data.image().OffsetToData)
                .map_err(|error| resource_error(path, error))?;
            let end = start
                .checked_add(data.size())
                .ok_or_else(|| invalid_resource_shape(path, "resource range overflows"))?;
            if bytes.get(start..end).is_none() {
                return Err(invalid_resource_shape(
                    path,
                    "resource range is outside the PE file",
                ));
            }
            let key = ResourceKey {
                resource_type: resource_type.clone(),
                name,
            };
            if index.insert(key, start..end).is_some() {
                return Err(invalid_resource_shape(
                    path,
                    "duplicate English resource name",
                ));
            }
        }
    }
    Ok(index)
}

#[derive(Debug, thiserror::Error)]
pub enum RetailAssetError {
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: invalid PE/resource data: {detail}", path.display())]
    Resource { path: PathBuf, detail: String },
    #[error("no English picture {0} is available")]
    PictureNotFound(PictureId),
    #[error("no English string is available for group {group:#06x}, direct index {direct_index}")]
    StringNotFound { group: i16, direct_index: i16 },
    #[error("Data/pictenu.gob has no English BITMAP resource 950.BMP")]
    DefaultDibPaletteNotFound,
}

fn read_font(root: &Path, relative: &str) -> Result<Vec<u8>, RetailAssetError> {
    read_file(&root.join(relative))
}

fn read_file(path: &Path) -> Result<Vec<u8>, RetailAssetError> {
    fs::read(path).map_err(|source| RetailAssetError::Io {
        path: path.to_owned(),
        source,
    })
}

fn resource_error(path: &Path, error: impl Display) -> RetailAssetError {
    RetailAssetError::Resource {
        path: path.to_owned(),
        detail: error.to_string(),
    }
}

fn invalid_resource_shape(path: &Path, detail: &str) -> RetailAssetError {
    RetailAssetError::Resource {
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn decode_string_table_entry(
    path: &Path,
    block: &[u8],
    slot: usize,
) -> Result<String, RetailAssetError> {
    let mut offset = 0;
    for current_slot in 0..=slot {
        let length_bytes = block
            .get(offset..offset + 2)
            .ok_or_else(|| invalid_resource_shape(path, "truncated RT_STRING entry length"))?;
        let length = usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]));
        offset += 2;
        let end = offset
            .checked_add(length * 2)
            .ok_or_else(|| invalid_resource_shape(path, "RT_STRING entry length overflows"))?;
        let encoded = block
            .get(offset..end)
            .ok_or_else(|| invalid_resource_shape(path, "truncated RT_STRING entry text"))?;
        if current_slot == slot {
            let words = encoded
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>();
            return String::from_utf16(&words).map_err(|error| resource_error(path, error));
        }
        offset = end;
    }
    unreachable!("RT_STRING slot loop includes the requested slot")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_OFFSET: usize = PE_OFFSET + 24;
    const SECTION_OFFSET: usize = OPTIONAL_OFFSET + 224;
    const RESOURCE_OFFSET: usize = 0x200;
    const RESOURCE_RVA: u32 = 0x1000;
    const RESOURCE_SIZE: usize = 0x3e00;

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum TestName {
        Id(u32),
        Text(String),
    }

    impl TestName {
        fn id(value: u32) -> Self {
            Self::Id(value)
        }

        fn text(value: &str) -> Self {
            Self::Text(value.to_owned())
        }
    }

    struct TestResource {
        resource_type: TestName,
        name: TestName,
        bytes: Vec<u8>,
    }

    impl TestResource {
        fn new(resource_type: TestName, name: TestName, bytes: Vec<u8>) -> Self {
            Self {
                resource_type,
                name,
                bytes,
            }
        }
    }

    enum TestNode {
        Directory(Vec<(TestName, TestNode)>),
        Data(Vec<u8>),
    }

    #[test]
    fn open_reports_the_first_missing_archive() {
        let root = temporary_root();
        let error = RetailAssets::open(root.path()).unwrap_err();
        let RetailAssetError::Io { path, .. } = error else {
            panic!("expected io error for missing archive, got {error:?}");
        };
        assert!(path.ends_with("Data/pictenu.gob"));
    }

    #[test]
    fn opens_only_current_runtime_files() {
        let root = synthetic_retail_install();
        for unused in [
            "Data/pictwv1.gob",
            "Data/pictwv2.gob",
            "Data/pictwv3.gob",
            "Data/wave.gob",
            "MUSIC/Track06.ogg",
        ] {
            assert!(!root.path().join(unused).exists());
        }
        let assets = RetailAssets::open(root.path()).unwrap();

        assert_eq!(assets.font_bytes(RetailFontFace::BelweBold), b"not a font");
        assert_eq!(assets.string(0x2719, 1).unwrap(), "Textile Mill");

        let bitmap = assets.picture(PictureId::new(4500)).unwrap();
        assert_eq!(bitmap[bitmap.len() - 4], 0x22);
        assert_eq!(
            assets.default_dib_palette()[0x16],
            crate::Rgb::new(0x57, 0x8b, 0xa6)
        );
    }

    #[test]
    fn resource_lookup_uses_the_index_built_at_open() {
        let root = synthetic_retail_install();
        let mut assets = RetailAssets::open(root.path()).unwrap();

        assets.pictures[0].bytes[..2].copy_from_slice(b"NO");

        let bitmap = assets.picture(PictureId::new(4500)).unwrap();
        assert_eq!(bitmap[bitmap.len() - 4], 0x22);
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at the English GOG installation"]
    fn opens_the_english_gog_installation_directly() {
        let root = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let assets = RetailAssets::open(&root).unwrap();

        assert_eq!(assets.string(0x2719, 1).unwrap(), "Textile Mill");
        assert!(
            assets
                .picture(PictureId::new(4500))
                .unwrap()
                .starts_with(b"BM")
        );
        let palette = assets.default_dib_palette();
        assert_eq!(palette[0x13], crate::Rgb::new(0xff, 0xff, 0xff));
        assert_eq!(palette[0x16], crate::Rgb::new(0x57, 0x8b, 0xa6));
    }

    fn temporary_root() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn synthetic_retail_install() -> TempDir {
        let root = temporary_root();
        for (index, relative) in PICTURE_ARCHIVE_PATHS.iter().enumerate() {
            let mut resources = Vec::new();
            if index == 0 {
                resources.push(TestResource::new(
                    TestName::id(2),
                    TestName::id(4500),
                    one_pixel_dib(0x11),
                ));
                resources.push(TestResource::new(
                    TestName::id(2),
                    TestName::text("4500.BMP"),
                    one_pixel_dib(0x22),
                ));
                resources.push(TestResource::new(
                    TestName::id(2),
                    TestName::text("950.BMP"),
                    default_palette_dib(),
                ));
            }
            if index == 3 {
                resources.push(TestResource::new(
                    TestName::id(2),
                    TestName::text("4500.BMP"),
                    one_pixel_dib(0x33),
                ));
            }
            write_retail_file(root.path(), relative, &synthetic_pe(resources));
        }
        write_retail_file(
            root.path(),
            STRINGS_ARCHIVE_PATH,
            &synthetic_pe(vec![TestResource::new(
                TestName::id(STRING_RESOURCE_TYPE),
                TestName::id(1117),
                string_table_block(5, "Textile Mill"),
            )]),
        );

        for relative in ["Data/Antqua.ttf", "Data/Antquab.ttf", "Data/WeBeBd__.ttf"] {
            write_retail_file(root.path(), relative, b"not a font");
        }
        root
    }

    fn write_retail_file(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn one_pixel_dib(marker: u8) -> Vec<u8> {
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&24u16.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&4u32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&[marker, 0, 0, 0]);
        dib
    }

    fn default_palette_dib() -> Vec<u8> {
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1i32.to_le_bytes());
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&8u16.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&4u32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0i32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        dib.extend_from_slice(&0u32.to_le_bytes());
        for index in 0..256u16 {
            let value = index as u8;
            let rgb = if value == 0x16 {
                [0x57, 0x8b, 0xa6]
            } else {
                [value, value, value]
            };
            dib.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
        }
        dib.extend_from_slice(&[0, 0, 0, 0]);
        dib
    }

    fn string_table_block(slot: usize, text: &str) -> Vec<u8> {
        let mut block = Vec::new();
        for current_slot in 0..16 {
            let words = if current_slot == slot {
                text.encode_utf16().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            block.extend_from_slice(&(words.len() as u16).to_le_bytes());
            for word in words {
                block.extend_from_slice(&word.to_le_bytes());
            }
        }
        block
    }

    fn synthetic_pe(resources: Vec<TestResource>) -> Vec<u8> {
        let mut types = BTreeMap::<TestName, BTreeMap<TestName, Vec<u8>>>::new();
        for resource in resources {
            types
                .entry(resource.resource_type)
                .or_default()
                .insert(resource.name, resource.bytes);
        }
        let root = TestNode::Directory(
            types
                .into_iter()
                .map(|(resource_type, names)| {
                    let names = names
                        .into_iter()
                        .map(|(name, bytes)| {
                            (
                                name,
                                TestNode::Directory(vec![(
                                    TestName::id(ENGLISH_LANGUAGE),
                                    TestNode::Data(bytes),
                                )]),
                            )
                        })
                        .collect();
                    (resource_type, TestNode::Directory(names))
                })
                .collect(),
        );

        let mut bytes = vec![0u8; RESOURCE_OFFSET + RESOURCE_SIZE];
        bytes[..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE_OFFSET as u32);
        bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, PE_OFFSET + 4, 0x14c);
        write_u16(&mut bytes, PE_OFFSET + 6, 1);
        write_u16(&mut bytes, PE_OFFSET + 20, 224);
        write_u16(&mut bytes, OPTIONAL_OFFSET, 0x10b);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 32, 0x1000);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 36, 0x200);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 56, 0x5000);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 60, RESOURCE_OFFSET as u32);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 92, 16);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 112, RESOURCE_RVA);
        write_u32(&mut bytes, OPTIONAL_OFFSET + 116, RESOURCE_SIZE as u32);
        bytes[SECTION_OFFSET..SECTION_OFFSET + 8].copy_from_slice(b".rsrc\0\0\0");
        write_u32(&mut bytes, SECTION_OFFSET + 8, RESOURCE_SIZE as u32);
        write_u32(&mut bytes, SECTION_OFFSET + 12, RESOURCE_RVA);
        write_u32(&mut bytes, SECTION_OFFSET + 16, RESOURCE_SIZE as u32);
        write_u32(&mut bytes, SECTION_OFFSET + 20, RESOURCE_OFFSET as u32);

        let mut cursor = 0usize;
        let (root_offset, root_is_directory) = write_node(&mut bytes, &mut cursor, &root);
        assert_eq!(root_offset, 0);
        assert!(root_is_directory);
        bytes
    }

    fn write_node(bytes: &mut [u8], cursor: &mut usize, node: &TestNode) -> (u32, bool) {
        match node {
            TestNode::Data(payload) => {
                let data_entry = allocate(cursor, 16, 4);
                let data = allocate(cursor, payload.len(), 1);
                let base = RESOURCE_OFFSET;
                bytes[base + data..base + data + payload.len()].copy_from_slice(payload);
                write_u32(bytes, base + data_entry, RESOURCE_RVA + data as u32);
                write_u32(bytes, base + data_entry + 4, payload.len() as u32);
                (data_entry as u32, false)
            }
            TestNode::Directory(entries) => {
                let directory = allocate(cursor, 16 + entries.len() * 8, 4);
                let mut ordered = entries.iter().collect::<Vec<_>>();
                ordered.sort_by(|(left, _), (right, _)| {
                    let left_kind = matches!(left, TestName::Text(_));
                    let right_kind = matches!(right, TestName::Text(_));
                    right_kind.cmp(&left_kind).then_with(|| left.cmp(right))
                });
                let named = ordered
                    .iter()
                    .filter(|(name, _)| matches!(name, TestName::Text(_)))
                    .count();
                let base = RESOURCE_OFFSET;
                write_u16(bytes, base + directory + 12, named as u16);
                write_u16(bytes, base + directory + 14, (ordered.len() - named) as u16);
                for (index, (name, child)) in ordered.into_iter().enumerate() {
                    let raw_name = write_name(bytes, cursor, name);
                    let (child_offset, child_is_directory) = write_node(bytes, cursor, child);
                    let target = child_offset | if child_is_directory { 0x8000_0000 } else { 0 };
                    let entry = base + directory + 16 + index * 8;
                    write_u32(bytes, entry, raw_name);
                    write_u32(bytes, entry + 4, target);
                }
                (directory as u32, true)
            }
        }
    }

    fn write_name(bytes: &mut [u8], cursor: &mut usize, name: &TestName) -> u32 {
        match name {
            TestName::Id(value) => *value,
            TestName::Text(text) => {
                let encoded = text.encode_utf16().collect::<Vec<_>>();
                let offset = allocate(cursor, 2 + encoded.len() * 2, 2);
                let base = RESOURCE_OFFSET + offset;
                write_u16(bytes, base, encoded.len() as u16);
                for (index, unit) in encoded.into_iter().enumerate() {
                    write_u16(bytes, base + 2 + index * 2, unit);
                }
                0x8000_0000 | offset as u32
            }
        }
    }

    fn allocate(cursor: &mut usize, size: usize, alignment: usize) -> usize {
        *cursor = (*cursor + alignment - 1) & !(alignment - 1);
        let offset = *cursor;
        *cursor += size;
        assert!(*cursor <= RESOURCE_SIZE);
        offset
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
