use crate::retail_pe::{
    DecodedStringResource, PeResourceEntry, PeResourceError, PeResourceFile, ResourceIdentifier,
    bitmap_resource_to_bmp, decode_string_table_block,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const RETAIL_ASSET_PACK_SCHEMA: &str = "imperialism.retail_asset_pack.v1";
const CACHE_KEY_DOMAIN: &[u8] = b"imperialism.retail_asset_import.v1\0";
const ENGLISH_LANGUAGE: u32 = 1033;

const REQUIRED_RETAIL_FILES: &[&str] = &[
    "Data/confenu.irg",
    "Data/pictenu.gob",
    "Data/pictpaid.gob",
    "Data/pictuniv.gob",
    "Data/pictwv0.gob",
    "Data/pictwv1.gob",
    "Data/pictwv2.gob",
    "Data/pictwv3.gob",
    "Data/STR#ENU.GOB",
    "Data/tabsenu.gob",
    "Data/wave.gob",
    "Data/Antqua.ttf",
    "Data/Antquab.ttf",
    "Data/WeBeBd__.ttf",
    "Data/WeBeLt__.ttf",
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PictureLibrary {
    Localized,
    Paid,
    World0,
    World1,
    World2,
    World3,
    Universal,
}

impl PictureLibrary {
    pub const fn active_lookup_order(world_variant: u8) -> Option<[Self; 4]> {
        let world = match world_variant {
            0 => Self::World0,
            1 => Self::World1,
            2 => Self::World2,
            3 => Self::World3,
            _ => return None,
        };
        Some([Self::Localized, Self::Paid, world, Self::Universal])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailSourceDigest {
    pub relative_path: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedRetailObject {
    pub sha256: String,
    pub byte_length: u64,
    pub extension: String,
}

impl CachedRetailObject {
    pub fn relative_path(&self) -> PathBuf {
        PathBuf::from("objects")
            .join("sha256")
            .join(format!("{}.{}", self.sha256, self.extension))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailResourceAsset {
    pub source_path: String,
    pub picture_library: Option<PictureLibrary>,
    pub resource_type: ResourceIdentifier,
    pub resource_name: ResourceIdentifier,
    pub language: u32,
    pub retail_byte_length: u64,
    pub retail_sha256: String,
    pub object: CachedRetailObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailStringAsset {
    pub id: u32,
    pub block: u32,
    pub index: u8,
    pub text: String,
    pub source_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailStandaloneAsset {
    pub relative_path: String,
    pub object: CachedRetailObject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetailAssetPackManifestV1 {
    pub schema: String,
    pub cache_key: String,
    pub logical_resolution: [u32; 2],
    pub bitmap_lookup_is_name_then_numeric: bool,
    pub sources: Vec<RetailSourceDigest>,
    pub resources: Vec<RetailResourceAsset>,
    pub strings: Vec<RetailStringAsset>,
    pub fonts: Vec<RetailStandaloneAsset>,
    pub music: Vec<RetailStandaloneAsset>,
}

impl RetailAssetPackManifestV1 {
    pub fn resolve_picture(
        &self,
        picture_id: i16,
        world_variant: u8,
    ) -> Option<&RetailResourceAsset> {
        let libraries = PictureLibrary::active_lookup_order(world_variant)?;
        let named = ResourceIdentifier::Named(format!("{picture_id}.BMP"));
        let numeric = ResourceIdentifier::Numeric(u32::from(picture_id as u16));
        for name in [&named, &numeric] {
            for library in libraries {
                if let Some(asset) = self.resources.iter().find(|asset| {
                    asset.picture_library == Some(library)
                        && asset.resource_type == ResourceIdentifier::Numeric(2)
                        && &asset.resource_name == name
                        && asset.language == ENGLISH_LANGUAGE
                }) {
                    return Some(asset);
                }
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub struct ImportedRetailAssets {
    pub cache_root: PathBuf,
    pub pack_dir: PathBuf,
    pub manifest: RetailAssetPackManifestV1,
}

impl ImportedRetailAssets {
    pub fn object_path(&self, object: &CachedRetailObject) -> PathBuf {
        self.cache_root.join(object.relative_path())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RetailAssetImportError {
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
    #[error("{path}: {source}")]
    Pe {
        path: String,
        #[source]
        source: PeResourceError,
    },
    #[error("incompatible English GOG retail assets: {0}")]
    Incompatible(String),
    #[error("invalid retail cache manifest: {0}")]
    Manifest(#[source] serde_json::Error),
}

pub fn default_retail_cache_dir() -> Result<PathBuf, RetailAssetImportError> {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("imperialism-rs"));
    }
    if let Some(path) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join(".cache").join("imperialism-rs"));
    }
    Err(RetailAssetImportError::Incompatible(
        "could not determine a cache directory; pass --cache-dir".to_owned(),
    ))
}

pub fn import_english_gog_assets(
    retail_dir: &Path,
    cache_root: &Path,
) -> Result<ImportedRetailAssets, RetailAssetImportError> {
    let source_paths = required_source_paths(retail_dir)?;
    let sources = hash_sources(&source_paths)?;
    let cache_key = cache_key(&sources);
    let pack_dir = cache_root.join("packs").join("v1").join(&cache_key);
    let manifest_path = pack_dir.join("manifest.json");
    if manifest_path.is_file()
        && let Ok(manifest) = read_manifest(&manifest_path)
        && validate_cached_manifest(cache_root, &manifest, &sources, &cache_key)?
    {
        return Ok(ImportedRetailAssets {
            cache_root: cache_root.to_owned(),
            pack_dir,
            manifest,
        });
    }

    let config = read_pe(retail_dir, "Data/confenu.irg")?;
    validate_english_config(&config)?;

    create_dir_all(cache_root)?;
    let mut resources = Vec::new();
    let picture_archives = [
        ("Data/pictenu.gob", PictureLibrary::Localized),
        ("Data/pictpaid.gob", PictureLibrary::Paid),
        ("Data/pictwv0.gob", PictureLibrary::World0),
        ("Data/pictwv1.gob", PictureLibrary::World1),
        ("Data/pictwv2.gob", PictureLibrary::World2),
        ("Data/pictwv3.gob", PictureLibrary::World3),
        ("Data/pictuniv.gob", PictureLibrary::Universal),
    ];
    for (relative, library) in picture_archives {
        let pe = read_pe(retail_dir, relative)?;
        validate_picture_archive(relative, library, &pe)?;
        import_resource_archive(cache_root, relative, Some(library), &pe, &mut resources)?;
    }

    let wave = read_pe(retail_dir, "Data/wave.gob")?;
    validate_named_archive("Data/wave.gob", &wave, "WAVE", &["7000"])?;
    import_resource_archive(cache_root, "Data/wave.gob", None, &wave, &mut resources)?;

    let tables = read_pe(retail_dir, "Data/tabsenu.gob")?;
    validate_named_archive(
        "Data/tabsenu.gob",
        &tables,
        "TABLE",
        &["NEWS.TAB", "NEWS.TEX"],
    )?;
    import_resource_archive(
        cache_root,
        "Data/tabsenu.gob",
        None,
        &tables,
        &mut resources,
    )?;

    let strings_pe = read_pe(retail_dir, "Data/STR#ENU.GOB")?;
    let strings = import_strings("Data/STR#ENU.GOB", &strings_pe)?;
    validate_launch_strings(&strings)?;

    let fonts = import_standalone_group(
        retail_dir,
        cache_root,
        &[
            "Data/Antqua.ttf",
            "Data/Antquab.ttf",
            "Data/WeBeBd__.ttf",
            "Data/WeBeLt__.ttf",
        ],
        "ttf",
        validate_font,
    )?;
    let music_paths = (2..=12)
        .map(|track| format!("MUSIC/Track{track:02}.ogg"))
        .collect::<Vec<_>>();
    let music_refs = music_paths.iter().map(String::as_str).collect::<Vec<_>>();
    let music = import_standalone_group(retail_dir, cache_root, &music_refs, "ogg", validate_ogg)?;

    let manifest = RetailAssetPackManifestV1 {
        schema: RETAIL_ASSET_PACK_SCHEMA.to_owned(),
        cache_key: cache_key.clone(),
        logical_resolution: [640, 480],
        bitmap_lookup_is_name_then_numeric: true,
        sources,
        resources,
        strings,
        fonts,
        music,
    };
    write_pack_atomically(cache_root, &pack_dir, &manifest, pack_dir.exists())?;
    Ok(ImportedRetailAssets {
        cache_root: cache_root.to_owned(),
        pack_dir,
        manifest,
    })
}

fn required_source_paths(
    retail_dir: &Path,
) -> Result<Vec<(String, PathBuf)>, RetailAssetImportError> {
    let paths = REQUIRED_RETAIL_FILES
        .iter()
        .map(|relative| ((*relative).to_owned(), retail_dir.join(relative)))
        .collect::<Vec<_>>();
    let missing = paths
        .iter()
        .filter(|(_, path)| !path.is_file())
        .map(|(relative, _)| relative.clone())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(RetailAssetImportError::MissingFiles(missing));
    }
    Ok(paths)
}

fn hash_sources(
    paths: &[(String, PathBuf)],
) -> Result<Vec<RetailSourceDigest>, RetailAssetImportError> {
    let mut sources = Vec::with_capacity(paths.len());
    for (relative, path) in paths {
        let bytes = read(path)?;
        sources.push(RetailSourceDigest {
            relative_path: relative.clone(),
            byte_length: bytes.len() as u64,
            sha256: sha256(&bytes),
        });
    }
    sources.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(sources)
}

fn cache_key(sources: &[RetailSourceDigest]) -> String {
    let mut digest = Sha256::new();
    digest.update(CACHE_KEY_DOMAIN);
    for source in sources {
        digest.update(source.relative_path.as_bytes());
        digest.update([0]);
        digest.update(source.byte_length.to_le_bytes());
        digest.update(source.sha256.as_bytes());
        digest.update([0]);
    }
    hex_digest(digest.finalize().as_slice())
}

fn read_pe(retail_dir: &Path, relative: &str) -> Result<PeResourceFile, RetailAssetImportError> {
    PeResourceFile::parse(read(&retail_dir.join(relative))?).map_err(|source| {
        RetailAssetImportError::Pe {
            path: relative.to_owned(),
            source,
        }
    })
}

fn validate_english_config(config: &PeResourceFile) -> Result<(), RetailAssetImportError> {
    let mut decoded = Vec::new();
    for entry in config.resources() {
        if entry.resource_type == ResourceIdentifier::Numeric(6) {
            let ResourceIdentifier::Numeric(block) = &entry.name else {
                continue;
            };
            decoded.extend(
                decode_string_table_block(*block, config.payload(entry)).map_err(|source| {
                    RetailAssetImportError::Pe {
                        path: "Data/confenu.irg".to_owned(),
                        source,
                    }
                })?,
            );
        }
    }
    let expected = [
        (128, "data/wave.gob"),
        (663, "data/str#enu.gob"),
        (710, "data/pictenu.gob"),
        (803, "enu"),
        (2112, "data/tabsenu.gob"),
        (7734, "English"),
    ];
    for (id, value) in expected {
        let actual = decoded.iter().find(|entry| entry.id == id);
        if actual.map(|entry| entry.text.as_str()) != Some(value) {
            return Err(RetailAssetImportError::Incompatible(format!(
                "Data/confenu.irg STRING {id} does not identify {value:?}"
            )));
        }
    }
    Ok(())
}

fn validate_picture_archive(
    relative: &str,
    library: PictureLibrary,
    pe: &PeResourceFile,
) -> Result<(), RetailAssetImportError> {
    if !pe.resources().iter().any(|entry| {
        entry.resource_type == ResourceIdentifier::Numeric(2) && entry.language == ENGLISH_LANGUAGE
    }) {
        return Err(RetailAssetImportError::Incompatible(format!(
            "{relative} has no English BITMAP resources"
        )));
    }
    let required: &[i16] = match library {
        PictureLibrary::Localized => &[950, 1031, 4500, 8452],
        PictureLibrary::World0 => &[4550],
        PictureLibrary::Universal => &[1016, 4540, 8453],
        PictureLibrary::Paid
        | PictureLibrary::World1
        | PictureLibrary::World2
        | PictureLibrary::World3 => &[],
    };
    for id in required {
        let name = ResourceIdentifier::Named(format!("{id}.BMP"));
        if pe
            .find(&ResourceIdentifier::Numeric(2), &name, ENGLISH_LANGUAGE)
            .is_none()
        {
            return Err(RetailAssetImportError::Incompatible(format!(
                "{relative} has no launch BITMAP {id}.BMP"
            )));
        }
    }
    Ok(())
}

fn validate_named_archive(
    relative: &str,
    pe: &PeResourceFile,
    resource_type: &str,
    required_names: &[&str],
) -> Result<(), RetailAssetImportError> {
    let resource_type = ResourceIdentifier::Named(resource_type.to_owned());
    for required in required_names {
        let name = required
            .parse::<u32>()
            .map(ResourceIdentifier::Numeric)
            .unwrap_or_else(|_| ResourceIdentifier::Named((*required).to_owned()));
        if pe.find(&resource_type, &name, ENGLISH_LANGUAGE).is_none() {
            return Err(RetailAssetImportError::Incompatible(format!(
                "{relative} has no {resource_type:?} resource {required}"
            )));
        }
    }
    Ok(())
}

fn import_resource_archive(
    cache_root: &Path,
    relative: &str,
    picture_library: Option<PictureLibrary>,
    pe: &PeResourceFile,
    output: &mut Vec<RetailResourceAsset>,
) -> Result<(), RetailAssetImportError> {
    for entry in pe.resources() {
        if entry.language != ENGLISH_LANGUAGE {
            continue;
        }
        let payload = pe.payload(entry);
        let (normalized, extension) =
            normalize_resource(entry, payload).map_err(|source| RetailAssetImportError::Pe {
                path: relative.to_owned(),
                source,
            })?;
        let object = write_object(cache_root, &normalized, extension)?;
        output.push(RetailResourceAsset {
            source_path: relative.to_owned(),
            picture_library,
            resource_type: entry.resource_type.clone(),
            resource_name: entry.name.clone(),
            language: entry.language,
            retail_byte_length: payload.len() as u64,
            retail_sha256: sha256(payload),
            object,
        });
    }
    Ok(())
}

fn normalize_resource(
    entry: &PeResourceEntry,
    payload: &[u8],
) -> Result<(Vec<u8>, &'static str), PeResourceError> {
    match &entry.resource_type {
        ResourceIdentifier::Numeric(2) => Ok((bitmap_resource_to_bmp(payload)?, "bmp")),
        ResourceIdentifier::Named(name) if name == "WAVE" => {
            if payload.len() < 12 || &payload[..4] != b"RIFF" || &payload[8..12] != b"WAVE" {
                return Err(PeResourceError::Invalid(
                    "WAVE resource is not a complete RIFF/WAVE file".to_owned(),
                ));
            }
            Ok((payload.to_vec(), "wav"))
        }
        ResourceIdentifier::Named(name) if name == "TABLE" => Ok((payload.to_vec(), "table")),
        _ => Ok((payload.to_vec(), "bin")),
    }
}

fn import_strings(
    relative: &str,
    pe: &PeResourceFile,
) -> Result<Vec<RetailStringAsset>, RetailAssetImportError> {
    let mut strings = Vec::new();
    for entry in pe.resources() {
        if entry.resource_type != ResourceIdentifier::Numeric(6)
            || entry.language != ENGLISH_LANGUAGE
        {
            continue;
        }
        let ResourceIdentifier::Numeric(block) = &entry.name else {
            return Err(RetailAssetImportError::Incompatible(format!(
                "{relative} has a named STRING block"
            )));
        };
        let decoded = decode_string_table_block(*block, pe.payload(entry)).map_err(|source| {
            RetailAssetImportError::Pe {
                path: relative.to_owned(),
                source,
            }
        })?;
        strings.extend(decoded.into_iter().filter_map(
            |DecodedStringResource {
                 id,
                 block,
                 index,
                 text,
             }| {
                (!text.is_empty()).then(|| RetailStringAsset {
                    id,
                    block,
                    index,
                    text,
                    source_path: relative.to_owned(),
                })
            },
        ));
    }
    strings.sort_by_key(|entry| entry.id);
    Ok(strings)
}

fn validate_launch_strings(strings: &[RetailStringAsset]) -> Result<(), RetailAssetImportError> {
    for (id, text) in [
        (20_861, "Start New Game on Random Map"),
        (20_870, "Quit"),
        (20_874, "Introductory"),
        (24_167, "(generating world...)"),
    ] {
        if strings
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.text.as_str())
            != Some(text)
        {
            return Err(RetailAssetImportError::Incompatible(format!(
                "Data/STR#ENU.GOB STRING {id} is not the expected English launch text"
            )));
        }
    }
    Ok(())
}

fn import_standalone_group(
    retail_dir: &Path,
    cache_root: &Path,
    relative_paths: &[&str],
    extension: &str,
    validate: fn(&str, &[u8]) -> Result<(), RetailAssetImportError>,
) -> Result<Vec<RetailStandaloneAsset>, RetailAssetImportError> {
    relative_paths
        .iter()
        .map(|relative| {
            let bytes = read(&retail_dir.join(relative))?;
            validate(relative, &bytes)?;
            Ok(RetailStandaloneAsset {
                relative_path: (*relative).to_owned(),
                object: write_object(cache_root, &bytes, extension)?,
            })
        })
        .collect()
}

fn validate_font(relative: &str, bytes: &[u8]) -> Result<(), RetailAssetImportError> {
    let valid = bytes.starts_with(&[0, 1, 0, 0]) || bytes.starts_with(b"OTTO");
    if valid {
        Ok(())
    } else {
        Err(RetailAssetImportError::Incompatible(format!(
            "{relative} is not a TrueType/OpenType font"
        )))
    }
}

fn validate_ogg(relative: &str, bytes: &[u8]) -> Result<(), RetailAssetImportError> {
    if bytes.starts_with(b"OggS") {
        Ok(())
    } else {
        Err(RetailAssetImportError::Incompatible(format!(
            "{relative} is not an Ogg stream"
        )))
    }
}

fn write_object(
    cache_root: &Path,
    bytes: &[u8],
    extension: &str,
) -> Result<CachedRetailObject, RetailAssetImportError> {
    let digest = sha256(bytes);
    let object = CachedRetailObject {
        sha256: digest.clone(),
        byte_length: bytes.len() as u64,
        extension: extension.to_owned(),
    };
    let final_path = cache_root.join(object.relative_path());
    if object_file_matches(&final_path, bytes)? {
        return Ok(object);
    }
    let parent = final_path.parent().ok_or_else(|| {
        RetailAssetImportError::Incompatible("cache object has no parent directory".to_owned())
    })?;
    create_dir_all(parent)?;
    let temp = parent.join(format!(".{digest}.{}.tmp", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
    {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|source| io_error(&temp, source))?;
            file.sync_all().map_err(|source| io_error(&temp, source))?;
            if final_path.is_file() {
                if object_file_matches(&final_path, bytes)? {
                    fs::remove_file(&temp).map_err(|source| io_error(&temp, source))?;
                    return Ok(object);
                }
                fs::remove_file(&final_path).map_err(|source| io_error(&final_path, source))?;
            }
            match fs::rename(&temp, &final_path) {
                Ok(()) => {}
                Err(error) if object_file_matches(&final_path, bytes)? => {
                    fs::remove_file(&temp).map_err(|source| io_error(&temp, source))?;
                    let _ = error;
                }
                Err(source) => return Err(io_error(&final_path, source)),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !final_path.is_file() {
                return Err(io_error(&temp, error));
            }
        }
        Err(source) => return Err(io_error(&temp, source)),
    }
    Ok(object)
}

fn object_file_matches(path: &Path, expected: &[u8]) -> Result<bool, RetailAssetImportError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() == expected.len() as u64 => {
            Ok(read(path)? == expected)
        }
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn write_pack_atomically(
    cache_root: &Path,
    pack_dir: &Path,
    manifest: &RetailAssetPackManifestV1,
    replace_existing: bool,
) -> Result<(), RetailAssetImportError> {
    let parent = pack_dir.parent().ok_or_else(|| {
        RetailAssetImportError::Incompatible("cache pack has no parent directory".to_owned())
    })?;
    create_dir_all(parent)?;
    let temp_dir = parent.join(format!(
        ".{}.{}.tmp",
        manifest.cache_key,
        std::process::id()
    ));
    match fs::create_dir(&temp_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(io_error(&temp_dir, error));
        }
        Err(source) => return Err(io_error(&temp_dir, source)),
    }
    let encoded = serde_json::to_vec_pretty(manifest).map_err(RetailAssetImportError::Manifest)?;
    let manifest_path = temp_dir.join("manifest.json");
    let write_result =
        fs::write(&manifest_path, encoded).map_err(|source| io_error(&manifest_path, source));
    if let Err(error) = write_result {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(error);
    }
    if replace_existing && pack_dir.is_dir() {
        fs::remove_dir_all(pack_dir).map_err(|source| io_error(pack_dir, source))?;
    }
    match fs::rename(&temp_dir, pack_dir) {
        Ok(()) => Ok(()),
        Err(_) if pack_dir.join("manifest.json").is_file() => {
            let existing = read_manifest(&pack_dir.join("manifest.json"))?;
            let valid = validate_cached_manifest(
                cache_root,
                &existing,
                &manifest.sources,
                &manifest.cache_key,
            )?;
            if valid {
                fs::remove_dir_all(&temp_dir).map_err(|source| io_error(&temp_dir, source))
            } else {
                Err(RetailAssetImportError::Incompatible(format!(
                    "cache pack {} was concurrently replaced by incompatible data",
                    pack_dir.display()
                )))
            }
        }
        Err(source) => Err(io_error(pack_dir, source)),
    }?;
    Ok(())
}

fn validate_cached_manifest(
    cache_root: &Path,
    manifest: &RetailAssetPackManifestV1,
    sources: &[RetailSourceDigest],
    cache_key: &str,
) -> Result<bool, RetailAssetImportError> {
    if manifest.schema != RETAIL_ASSET_PACK_SCHEMA
        || manifest.cache_key != cache_key
        || manifest.sources != sources
        || manifest.logical_resolution != [640, 480]
        || !manifest.bitmap_lookup_is_name_then_numeric
    {
        return Ok(false);
    }
    if manifest.resources.iter().any(|asset| {
        asset.retail_sha256.len() != 64
            || !asset
                .retail_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Ok(false);
    }

    let mut checked = HashSet::new();
    for object in manifest
        .resources
        .iter()
        .map(|asset| &asset.object)
        .chain(manifest.fonts.iter().map(|asset| &asset.object))
        .chain(manifest.music.iter().map(|asset| &asset.object))
    {
        if object.sha256.len() != 64
            || !object.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || object.extension.is_empty()
            || !object
                .extension
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Ok(false);
        }
        let relative_path = object.relative_path();
        if !checked.insert(relative_path.clone()) {
            continue;
        }
        let path = cache_root.join(relative_path);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => return Err(io_error(&path, source)),
        };
        if !metadata.is_file() || metadata.len() != object.byte_length {
            return Ok(false);
        }
        if sha256(&read(&path)?) != object.sha256 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn read_manifest(path: &Path) -> Result<RetailAssetPackManifestV1, RetailAssetImportError> {
    serde_json::from_slice(&read(path)?).map_err(RetailAssetImportError::Manifest)
}

fn create_dir_all(path: &Path) -> Result<(), RetailAssetImportError> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))
}

fn read(path: &Path) -> Result<Vec<u8>, RetailAssetImportError> {
    fs::read(path).map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: std::io::Error) -> RetailAssetImportError {
    RetailAssetImportError::Io {
        path: path.to_owned(),
        source,
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0xf)] as char);
    }
    text
}

pub fn parse_retail_import_args<I>(
    args: I,
) -> Result<(PathBuf, Option<PathBuf>), RetailAssetImportError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let mut retail_dir = None;
    let mut cache_dir = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--retail-dir") => {
                retail_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                    RetailAssetImportError::Incompatible(
                        "--retail-dir requires a directory".to_owned(),
                    )
                })?));
            }
            Some("--cache-dir") => {
                cache_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                    RetailAssetImportError::Incompatible(
                        "--cache-dir requires a directory".to_owned(),
                    )
                })?));
            }
            Some(value) => {
                return Err(RetailAssetImportError::Incompatible(format!(
                    "unknown retail-import argument {value:?}"
                )));
            }
            None => {
                return Err(RetailAssetImportError::Incompatible(
                    "retail-import arguments must be valid UTF-8 option names".to_owned(),
                ));
            }
        }
    }
    let retail_dir = retail_dir.ok_or_else(|| {
        RetailAssetImportError::Incompatible("--retail-dir is required".to_owned())
    })?;
    Ok((retail_dir, cache_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_cache(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "imperialism-formats-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn object(name: &str, library: PictureLibrary) -> RetailResourceAsset {
        RetailResourceAsset {
            source_path: "synthetic.gob".to_owned(),
            picture_library: Some(library),
            resource_type: ResourceIdentifier::Numeric(2),
            resource_name: ResourceIdentifier::Named(name.to_owned()),
            language: ENGLISH_LANGUAGE,
            retail_byte_length: 1,
            retail_sha256: sha256(b"x"),
            object: CachedRetailObject {
                sha256: "0".repeat(64),
                byte_length: 1,
                extension: "bmp".to_owned(),
            },
        }
    }

    #[test]
    fn picture_lookup_preserves_retail_slot_precedence() {
        let mut manifest = empty_manifest();
        manifest
            .resources
            .push(object("4500.BMP", PictureLibrary::Universal));
        manifest
            .resources
            .push(object("4500.BMP", PictureLibrary::Localized));

        let resolved = manifest.resolve_picture(4500, 0).unwrap();

        assert_eq!(resolved.picture_library, Some(PictureLibrary::Localized));
    }

    #[test]
    fn cache_key_changes_when_retail_identity_changes() {
        let sources = vec![RetailSourceDigest {
            relative_path: "Data/pictenu.gob".to_owned(),
            byte_length: 12,
            sha256: "a".repeat(64),
        }];
        let original = cache_key(&sources);
        let changed_contents = cache_key(&[RetailSourceDigest {
            sha256: "b".repeat(64),
            ..sources[0].clone()
        }]);
        let changed_slot = cache_key(&[RetailSourceDigest {
            relative_path: "Data/pictuniv.gob".to_owned(),
            ..sources[0].clone()
        }]);

        assert_eq!(original.len(), 64);
        assert_ne!(original, changed_contents);
        assert_ne!(original, changed_slot);
    }

    #[test]
    fn reports_all_missing_retail_inputs_before_parsing() {
        let root = std::env::temp_dir().join(format!(
            "imperialism-formats-missing-{}",
            std::process::id()
        ));
        let error = required_source_paths(&root).unwrap_err();
        let RetailAssetImportError::MissingFiles(files) = error else {
            panic!("expected missing files");
        };
        assert_eq!(files.len(), REQUIRED_RETAIL_FILES.len());
        assert!(files.contains(&"Data/confenu.irg".to_owned()));
        assert!(files.contains(&"MUSIC/Track12.ogg".to_owned()));
    }

    #[test]
    fn cached_manifest_reuse_rejects_a_missing_object() {
        let root = temporary_cache("missing-object");
        let sources = vec![RetailSourceDigest {
            relative_path: "Data/pictenu.gob".to_owned(),
            byte_length: 4,
            sha256: sha256(b"retail"),
        }];
        let mut manifest = empty_manifest();
        manifest.cache_key = cache_key(&sources);
        manifest.sources.clone_from(&sources);
        let object = write_object(&root, b"font", "ttf").unwrap();
        manifest.fonts.push(RetailStandaloneAsset {
            relative_path: "Data/Antqua.ttf".to_owned(),
            object: object.clone(),
        });

        assert!(validate_cached_manifest(&root, &manifest, &sources, &manifest.cache_key).unwrap());
        fs::remove_file(root.join(object.relative_path())).unwrap();
        assert!(
            !validate_cached_manifest(&root, &manifest, &sources, &manifest.cache_key).unwrap()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn object_write_repairs_corrupt_content_at_the_expected_digest_path() {
        let root = temporary_cache("corrupt-object");
        let object = write_object(&root, b"font", "ttf").unwrap();
        let path = root.join(object.relative_path());
        fs::write(&path, b"evil").unwrap();

        assert_eq!(write_object(&root, b"font", "ttf").unwrap(), object);
        assert_eq!(fs::read(&path).unwrap(), b"font");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_pack_manifest_is_replaced_instead_of_reported_as_success() {
        let root = temporary_cache("stale-pack");
        let pack_dir = root.join("packs/v1/current");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(pack_dir.join("manifest.json"), b"stale").unwrap();
        let manifest = empty_manifest();

        write_pack_atomically(&root, &pack_dir, &manifest, true).unwrap();

        assert_eq!(
            read_manifest(&pack_dir.join("manifest.json")).unwrap(),
            manifest
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cli_requires_a_retail_directory() {
        let error = parse_retail_import_args(Vec::<OsString>::new()).unwrap_err();
        assert!(error.to_string().contains("--retail-dir is required"));
    }

    fn empty_manifest() -> RetailAssetPackManifestV1 {
        RetailAssetPackManifestV1 {
            schema: RETAIL_ASSET_PACK_SCHEMA.to_owned(),
            cache_key: "0".repeat(64),
            logical_resolution: [640, 480],
            bitmap_lookup_is_name_then_numeric: true,
            sources: Vec::new(),
            resources: Vec::new(),
            strings: Vec::new(),
            fonts: Vec::new(),
            music: Vec::new(),
        }
    }
}
