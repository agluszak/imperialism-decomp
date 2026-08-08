use crate::RetailFontFace;
use crate::retail_resources::{bitmap_resource_to_bmp, decode_string_table_block};
use pelite::pe32::{Pe, PeFile};
use pelite::resources::{FindError, Name};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

const ENGLISH_LANGUAGE: u32 = 1033;

const PICTURE_ARCHIVE_PATHS: [&str; 7] = [
    "Data/pictenu.gob",
    "Data/pictpaid.gob",
    "Data/pictwv0.gob",
    "Data/pictwv1.gob",
    "Data/pictwv2.gob",
    "Data/pictwv3.gob",
    "Data/pictuniv.gob",
];

const REQUIRED_RETAIL_FILES: &[&str] = &[
    "Data/pictenu.gob",
    "Data/pictpaid.gob",
    "Data/pictuniv.gob",
    "Data/pictwv0.gob",
    "Data/pictwv1.gob",
    "Data/pictwv2.gob",
    "Data/pictwv3.gob",
    "Data/STR#ENU.GOB",
    "Data/wave.gob",
    "Data/Antqua.ttf",
    "Data/Antquab.ttf",
    "Data/WeBeBd__.ttf",
    "MUSIC/Track02.ogg",
    "MUSIC/Track03.ogg",
    "MUSIC/Track04.ogg",
    "MUSIC/Track05.ogg",
    "MUSIC/Track06.ogg",
    "MUSIC/Track07.ogg",
    "MUSIC/Track08.ogg",
    "MUSIC/Track09.ogg",
    "MUSIC/Track10.ogg",
    "MUSIC/Track11.ogg",
    "MUSIC/Track12.ogg",
];

/// Direct access to the retail files needed by the current application.
///
/// The object owns raw archive/font bytes and indexes English PE resource ranges during opening.
/// It deliberately retains no borrowed PE views.
#[derive(Debug)]
pub struct RetailAssets {
    root: PathBuf,
    pictures: [ResourceArchive; 7],
    wave: ResourceArchive,
    strings: BTreeMap<u32, String>,
    fonts: RetailFonts,
}

impl RetailAssets {
    /// Opens the current English GOG input files and indexes their English resources.
    pub fn open(retail_dir: impl AsRef<Path>) -> Result<Self, RetailAssetError> {
        let root = retail_dir.as_ref().to_owned();
        require_retail_files(&root)?;

        let pictures = [
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[0])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[1])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[2])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[3])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[4])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[5])?,
            ResourceArchive::read(&root, PICTURE_ARCHIVE_PATHS[6])?,
        ];
        let wave = ResourceArchive::read(&root, "Data/wave.gob")?;
        let strings = ResourceArchive::read(&root, "Data/STR#ENU.GOB")?.english_strings()?;
        let fonts = RetailFonts::read(&root)?;

        Ok(Self {
            root,
            pictures,
            wave,
            strings,
            fonts,
        })
    }

    /// Resolves a retail picture using name-before-numeric and library-slot precedence.
    ///
    /// The returned bytes are a BMP file assembled from the retail DIB resource.
    pub fn picture(&self, picture_id: i16, world_variant: u8) -> Result<Vec<u8>, RetailAssetError> {
        let archives = self.active_picture_archives(world_variant)?;
        let named = format!("{picture_id}.BMP");
        let names = [
            ResourceName::Text(named),
            ResourceName::Id(u32::from(picture_id as u16)),
        ];
        for name in &names {
            for archive in archives {
                if let Some(dib) = archive.find(ResourceName::Id(2), name.clone())? {
                    return bitmap_resource_to_bmp(dib)
                        .map_err(|error| resource_error(&archive.path, error));
                }
            }
        }
        Err(RetailAssetError::PictureNotFound {
            picture_id,
            world_variant,
        })
    }

    /// Looks up a decoded English retail string.
    pub fn string(&self, id: u32) -> Option<&str> {
        self.strings.get(&id).map(String::as_str)
    }

    /// Returns the font bytes consumed by the UI.
    pub fn font_bytes(&self, face: RetailFontFace) -> Result<&[u8], RetailAssetError> {
        Ok(self.fonts.bytes(face))
    }

    /// Returns a complete RIFF/WAVE payload from `Data/wave.gob`.
    pub fn wave_bytes(&self, id: u16) -> Result<&[u8], RetailAssetError> {
        let bytes = self
            .wave
            .find(
                ResourceName::Text("WAVE".to_owned()),
                ResourceName::Id(u32::from(id)),
            )?
            .ok_or(RetailAssetError::WaveNotFound(id))?;
        validate_wave_payload("Data/wave.gob", bytes)?;
        Ok(bytes)
    }

    /// Resolves a music file without copying it into an importer cache.
    pub fn music_path(&self, track: u8) -> Result<PathBuf, RetailAssetError> {
        if !(2..=12).contains(&track) {
            return Err(RetailAssetError::InvalidMusicTrack(track));
        }
        Ok(self.root.join(format!("MUSIC/Track{track:02}.ogg")))
    }

    fn active_picture_archives(
        &self,
        world_variant: u8,
    ) -> Result<[&ResourceArchive; 4], RetailAssetError> {
        let world = match world_variant {
            0..=3 => 2 + usize::from(world_variant),
            _ => return Err(RetailAssetError::InvalidWorldVariant(world_variant)),
        };
        Ok([
            &self.pictures[0],
            &self.pictures[1],
            &self.pictures[world],
            &self.pictures[6],
        ])
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

    fn find(
        &self,
        resource_type: ResourceName,
        name: ResourceName,
    ) -> Result<Option<&[u8]>, RetailAssetError> {
        let key = ResourceKey {
            resource_type,
            name,
        };
        let Some(range) = self.english_resources.get(&key) else {
            return Ok(None);
        };
        self.bytes
            .get(range.clone())
            .map(Some)
            .ok_or_else(|| RetailAssetError::Resource {
                path: self.path.clone(),
                detail: "indexed resource range is outside its owning archive".to_owned(),
            })
    }

    fn english_strings(&self) -> Result<BTreeMap<u32, String>, RetailAssetError> {
        let mut strings = BTreeMap::new();
        for (key, range) in &self.english_resources {
            if key.resource_type != ResourceName::Id(6) {
                continue;
            }
            let ResourceName::Id(block) = &key.name else {
                return Err(RetailAssetError::Incompatible(format!(
                    "{} has named STRING block",
                    self.path.display()
                )));
            };
            let bytes =
                self.bytes
                    .get(range.clone())
                    .ok_or_else(|| RetailAssetError::Resource {
                        path: self.path.clone(),
                        detail: "indexed STRING range is outside its owning archive".to_owned(),
                    })?;
            let decoded = decode_string_table_block(*block, bytes)
                .map_err(|error| resource_error(&self.path, error))?;
            for string in decoded {
                if !string.text.is_empty() {
                    strings.insert(string.id, string.text);
                }
            }
        }
        Ok(strings)
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
    #[error(
        "retail directory is missing required English GOG files\n  {paths}",
        paths = .0.join("\n  ")
    )]
    MissingFiles(Vec<String>),
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: invalid PE/resource data: {detail}", path.display())]
    Resource { path: PathBuf, detail: String },
    #[error("incompatible English GOG retail assets: {0}")]
    Incompatible(String),
    #[error("no English picture {picture_id} is available for world variant {world_variant}")]
    PictureNotFound { picture_id: i16, world_variant: u8 },
    #[error("Data/wave.gob has no English WAVE resource {0}")]
    WaveNotFound(u16),
    #[error("world variant {0} is outside the retail range 0..=3")]
    InvalidWorldVariant(u8),
    #[error("retail music track {0} is outside the supported range 2..=12")]
    InvalidMusicTrack(u8),
}

fn require_retail_files(root: &Path) -> Result<(), RetailAssetError> {
    let missing = REQUIRED_RETAIL_FILES
        .iter()
        .filter(|relative| !root.join(relative).is_file())
        .map(|relative| (*relative).to_owned())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RetailAssetError::MissingFiles(missing))
    }
}

fn validate_wave_payload(relative: &str, bytes: &[u8]) -> Result<(), RetailAssetError> {
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        Ok(())
    } else {
        Err(RetailAssetError::Incompatible(format!(
            "{relative} WAVE resource is not a complete RIFF/WAVE file"
        )))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn reports_all_runtime_retail_inputs_before_parsing() {
        let root = temporary_root("missing");
        let error = RetailAssets::open(&root).unwrap_err();
        let RetailAssetError::MissingFiles(files) = error else {
            panic!("expected missing files");
        };
        assert_eq!(files.len(), REQUIRED_RETAIL_FILES.len());
        assert!(files.contains(&"Data/pictenu.gob".to_owned()));
        assert!(files.contains(&"MUSIC/Track12.ogg".to_owned()));
        assert!(!files.contains(&"Data/confenu.irg".to_owned()));
    }

    #[test]
    fn opens_runtime_files_without_eager_content_validation() {
        let root = synthetic_retail_install();
        let assets = RetailAssets::open(&root).unwrap();

        assert_eq!(assets.string(1), Some("direct lookup"));
        assert_eq!(assets.string(20_874), None);
        assert_eq!(
            assets.font_bytes(RetailFontFace::BelweBold).unwrap(),
            b"not a font"
        );
        assert_eq!(assets.wave_bytes(7000).unwrap(), b"RIFF\0\0\0\0WAVE");
        assert_eq!(
            assets.music_path(6).unwrap(),
            root.join("MUSIC/Track06.ogg")
        );

        let bitmap = assets.picture(4500, 0).unwrap();
        assert_eq!(bitmap[bitmap.len() - 4], 0x22);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_lookup_uses_the_index_built_at_open() {
        let root = synthetic_retail_install();
        let mut assets = RetailAssets::open(&root).unwrap();

        assets.pictures[0].bytes[..2].copy_from_slice(b"NO");

        let bitmap = assets.picture(4500, 0).unwrap();
        assert_eq!(bitmap[bitmap.len() - 4], 0x22);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wave_payload_validation_happens_at_lookup() {
        let root = synthetic_retail_install();
        write_retail_file(
            &root,
            "Data/wave.gob",
            &synthetic_pe(vec![TestResource::new(
                TestName::text("WAVE"),
                TestName::id(7000),
                b"not a wave".to_vec(),
            )]),
        );

        let assets = RetailAssets::open(&root).unwrap();
        assert!(matches!(
            assets.wave_bytes(7000),
            Err(RetailAssetError::Incompatible(_))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_world_variants_outside_retail_range() {
        let root = synthetic_retail_install();
        let assets = RetailAssets::open(&root).unwrap();

        assert!(matches!(
            assets.picture(4500, 4),
            Err(RetailAssetError::InvalidWorldVariant(4))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at the English GOG installation"]
    fn opens_the_english_gog_installation_directly() {
        let root = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let assets = RetailAssets::open(&root).unwrap();

        assert_eq!(assets.string(20_874), Some("Introductory"));
        assert!(assets.picture(4500, 0).unwrap().starts_with(b"BM"));
        assert!(assets.wave_bytes(7000).unwrap().starts_with(b"RIFF"));
    }

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "imperialism-formats-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn synthetic_retail_install() -> PathBuf {
        let root = temporary_root("retail-assets");
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
            }
            if index == 6 {
                resources.push(TestResource::new(
                    TestName::id(2),
                    TestName::text("4500.BMP"),
                    one_pixel_dib(0x33),
                ));
            }
            write_retail_file(&root, relative, &synthetic_pe(resources));
        }

        let string_resources = vec![TestResource::new(
            TestName::id(6),
            TestName::id(1),
            string_block(&[(1, "direct lookup")]),
        )];
        write_retail_file(&root, "Data/STR#ENU.GOB", &synthetic_pe(string_resources));
        write_retail_file(
            &root,
            "Data/wave.gob",
            &synthetic_pe(vec![TestResource::new(
                TestName::text("WAVE"),
                TestName::id(7000),
                b"RIFF\0\0\0\0WAVE".to_vec(),
            )]),
        );

        for relative in ["Data/Antqua.ttf", "Data/Antquab.ttf", "Data/WeBeBd__.ttf"] {
            write_retail_file(&root, relative, b"not a font");
        }
        for track in 2..=12 {
            write_retail_file(&root, &format!("MUSIC/Track{track:02}.ogg"), b"not an ogg");
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

    fn string_block(entries: &[(u8, &str)]) -> Vec<u8> {
        let mut block = Vec::new();
        for index in 0..16u8 {
            let text = entries
                .iter()
                .find_map(|(entry_index, text)| (*entry_index == index).then_some(*text))
                .unwrap_or("");
            let encoded = text.encode_utf16().collect::<Vec<_>>();
            block.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
            for unit in encoded {
                block.extend_from_slice(&unit.to_le_bytes());
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
