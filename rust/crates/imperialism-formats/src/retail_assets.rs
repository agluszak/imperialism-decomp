use crate::color::DibPalette;
use crate::media::{MovieId, MusicTrack, SoundId};
use crate::retail_resources::*;
use crate::{PictureId, RetailCursor, RetailFontFace};
use imperialism_core::{
    MajorNationId, NEWS_TEMPLATE_COUNT, NationId, NationTable, RandomGameNames,
};
use pelite::pe32::{Pe, PeFile};
use pelite::resources::{FindError, Name};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

const ENGLISH_LANGUAGE: u32 = 1033;
const NEUTRAL_LANGUAGE: u32 = 0;
const STRING_RESOURCE_TYPE: u32 = 6;
const BITMAP_RESOURCE_TYPE: u32 = 2;
const CURSOR_RESOURCE_TYPE: u32 = 1;
const GROUP_CURSOR_RESOURCE_TYPE: u32 = 12;
const CHROME_BACKDROP_BITMAP_ID: u32 = 0x119;
const EXE_PATH: &str = "Imperialism.exe";
const STRINGS_ARCHIVE_PATH: &str = "Data/STR#ENU.GOB";
const TABLE_ARCHIVE_PATH: &str = "Data/tabsenu.gob";
const WAVE_ARCHIVE_PATH: &str = "Data/wave.gob";
const WAVE_RESOURCE_TYPE: &str = "WAVE";
const MUSIC_DIRECTORY: &str = "MUSIC";
const MOVIES_DIRECTORY: &str = "Movies";
const MUSIC_EXTENSIONS: [&str; 4] = ["ogg", "mp3", "flac", "wav"];

const PICTURE_ARCHIVE_PATHS: [&str; 4] = [
    "Data/pictenu.gob",
    "Data/pictpaid.gob",
    "Data/pictwv0.gob",
    "Data/pictuniv.gob",
];
const NEWS_TAB_NAME: &str = "news.tab";
const NEWS_TEX_NAME: &str = "news.tex";
const NEWS_ROW_BYTES: usize = 24;

/// Direct access to the retail files needed by the current application.
///
/// The object owns raw archive/font/exe bytes and indexes English PE resource ranges during opening.
/// It deliberately retains no borrowed PE views.
#[derive(Debug)]
pub struct RetailAssets {
    root: PathBuf,
    pictures: [ResourceArchive; 4],
    strings: ResourceArchive,
    exe: ResourceArchive,
    waves: Option<ResourceArchive>,
    fonts: RetailFonts,
    default_dib_palette: DibPalette,
    news: NewsTable,
}

/// Decoded `news.tab` / `news.tex` pair used to build and render newspaper pages.
#[derive(Clone, Debug)]
pub struct NewsTable {
    story_ids: Vec<i32>,
    headlines: Vec<String>,
    bodies: Vec<String>,
}

impl NewsTable {
    pub fn story_ids(&self) -> &[i32] {
        &self.story_ids
    }

    pub fn headline(&self, template_index: u16) -> &str {
        self.headlines
            .get(usize::from(template_index))
            .map(String::as_str)
            .unwrap_or("")
    }

    pub fn body(&self, template_index: u16) -> &str {
        self.bodies
            .get(usize::from(template_index))
            .map(String::as_str)
            .unwrap_or("")
    }
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
                    ResourceName::Id(BITMAP_RESOURCE_TYPE),
                    ResourceName::Text("950.BMP".to_owned()),
                )
                .ok_or(RetailAssetError::DefaultDibPaletteNotFound)?;
            bitmap_palette_rgb(dib).map_err(|error| resource_error(&archive.path, error))?
        };
        let strings = ResourceArchive::read(&root, STRINGS_ARCHIVE_PATH)?;
        let exe = ResourceArchive::read(&root, EXE_PATH)?;
        let waves = optional_archive(&root, WAVE_ARCHIVE_PATH)?;
        let fonts = RetailFonts::read(&root)?;
        let news = load_news_table(&root)?;

        Ok(Self {
            root,
            pictures,
            strings,
            exe,
            waves,
            fonts,
            default_dib_palette,
            news,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn news_table(&self) -> &NewsTable {
        &self.news
    }

    /// Enumerates the sparse retail `Scenario/s0..s63.inf` catalog.
    pub fn scenario_catalog(&self) -> Result<Vec<crate::ScenarioCatalogEntry>, RetailAssetError> {
        crate::read_scenario_catalog(&self.root)
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
        self.string_id(string_id).map_err(|error| match error {
            RetailAssetError::StringIdNotFound(_) => RetailAssetError::StringNotFound {
                group,
                direct_index,
            },
            error => error,
        })
    }

    /// Loads one direct Windows `RT_STRING` identifier.
    ///
    /// Retail's long-form help `TEXT` resources were assigned the same numeric
    /// identifiers when the Windows string library was built.
    pub fn text(&self, resource_id: u16) -> Result<String, RetailAssetError> {
        self.string_id(resource_id)
    }

    fn string_id(&self, string_id: u16) -> Result<String, RetailAssetError> {
        let block_id = u32::from((string_id >> 4) + 1);
        let slot = usize::from(string_id & 0xf);
        let block = self
            .strings
            .find(
                ResourceName::Id(STRING_RESOURCE_TYPE),
                ResourceName::Id(block_id),
            )
            .ok_or(RetailAssetError::StringIdNotFound(string_id))?;
        decode_string_table_entry(&self.strings.path, block, slot)
    }

    /// Materializes the localized STR# inputs used by random-game province and ocean naming.
    pub fn random_game_names(&self) -> Result<RandomGameNames, RetailAssetError> {
        let mut localized_nation_names = NationTable::default();
        for nation in NationId::all() {
            // `TSimMgr::GetString(0x2715, nationSlot)` adds one before direct lookup.
            localized_nation_names[nation] = self.string(0x2715, i16::from(nation.get()) + 1)?;
        }

        let mut province_names_by_nation: NationTable<Vec<String>> = NationTable::default();
        for nation in NationId::all() {
            let name_count = if MajorNationId::from_nation(nation).is_some() {
                8
            } else {
                4
            };
            for ordinal in 1..=name_count {
                // `TSimMgr::GetString(group, offset)` adds one before the direct resource lookup.
                province_names_by_nation[nation].push(self.string(
                    8000 + i16::from(nation.get()),
                    i16::try_from(ordinal + 1).expect("province-name ordinal fits i16"),
                )?);
            }
        }

        let mut zone_headline_templates = Vec::with_capacity(24);
        for status_code in 0..24 {
            // `TSimMgr::GetString(0x275a, statusCode)` performs this same +1 conversion.
            zone_headline_templates.push(self.string(0x275a, status_code + 1)?);
        }
        let mut fallback_ocean_names = Vec::with_capacity(37);
        for cache_id in 0..37 {
            // The localized fallback cursor is a zero-based `GetString(0x275b, cacheId)` offset.
            fallback_ocean_names.push(self.string(0x275b, cache_id + 1)?);
        }

        Ok(RandomGameNames {
            localized_nation_names,
            province_names_by_nation,
            zone_headline_templates,
            fallback_ocean_names,
        })
    }

    fn picture_resource(&self, picture_id: PictureId) -> Result<(&Path, &[u8]), RetailAssetError> {
        let named = format!("{picture_id}.BMP");
        let names = [
            ResourceName::Text(named),
            ResourceName::Id(u32::from(picture_id.get() as u16)),
        ];
        for name in &names {
            for archive in &self.pictures {
                if let Some(dib) =
                    archive.find(ResourceName::Id(BITMAP_RESOURCE_TYPE), name.clone())
                {
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

    /// `TViewMgr::LoadTurnEventCursorTable`: `LoadCursorA("~C%d")` for 1000..=1053.
    pub const TURN_EVENT_CURSOR_BASE: u16 = 1000;
    pub const TURN_EVENT_CURSOR_COUNT: usize = 0x36;

    /// Resolves one turn-event cursor loaded by `LoadTurnEventCursorByResourceIdOffset1000`.
    pub fn turn_event_cursor(&self, resource_id: u16) -> Result<RetailCursor, RetailAssetError> {
        let name = format!("~C{resource_id}");
        let group = self
            .exe
            .find(
                ResourceName::Id(GROUP_CURSOR_RESOURCE_TYPE),
                ResourceName::Text(name),
            )
            .ok_or(RetailAssetError::CursorNotFound { resource_id })?;
        group_cursor_to_rgba(group, |cursor_id| {
            self.exe
                .find(
                    ResourceName::Id(CURSOR_RESOURCE_TYPE),
                    ResourceName::Id(cursor_id),
                )
                .map(ToOwned::to_owned)
        })
        .map_err(|error| resource_error(&self.exe.path, error))
    }

    /// Loads the 54-entry `TViewMgr::turnEventCursors` table.
    pub fn turn_event_cursors(
        &self,
    ) -> Result<[RetailCursor; Self::TURN_EVENT_CURSOR_COUNT], RetailAssetError> {
        let mut cursors = Vec::with_capacity(Self::TURN_EVENT_CURSOR_COUNT);
        for index in 0..Self::TURN_EVENT_CURSOR_COUNT {
            cursors.push(self.turn_event_cursor(
                Self::TURN_EVENT_CURSOR_BASE
                    + u16::try_from(index).expect("turn-event cursor index fits u16"),
            )?);
        }
        Ok(cursors
            .try_into()
            .unwrap_or_else(|_| unreachable!("turn-event cursor table is a fixed 54-entry array")))
    }

    /// Returns the font bytes consumed by the UI.
    pub fn font_bytes(&self, face: RetailFontFace) -> &[u8] {
        self.fonts.bytes(face)
    }

    /// `Movies/<stem>.avi`. Missing files are a caller-side continue, matching
    /// `PlayMovieClipAndDispatchTurnStateFollowup`.
    pub fn movie_path(&self, movie: MovieId) -> PathBuf {
        self.root
            .join(MOVIES_DIRECTORY)
            .join(format!("{}.avi", movie.file_stem()))
    }

    /// GOG replacement for CD track `cue`, usually `MUSIC/TrackNN.ogg`.
    pub fn music_track_path(&self, track: MusicTrack) -> Result<PathBuf, RetailAssetError> {
        let stem = track.file_stem();
        for directory in [MUSIC_DIRECTORY, "Music"] {
            for extension in MUSIC_EXTENSIONS {
                for name in [
                    format!("{stem}.{extension}"),
                    format!("{}.{extension}", stem.to_ascii_lowercase()),
                ] {
                    let path = self.root.join(directory).join(name);
                    if path.is_file() {
                        return Ok(path);
                    }
                }
            }
        }
        Err(RetailAssetError::MusicTrackNotFound(track))
    }

    /// Raw RIFF WAVE bytes from `Data/wave.gob`.
    pub fn sound(&self, sound_id: SoundId) -> Result<Vec<u8>, RetailAssetError> {
        let waves = self
            .waves
            .as_ref()
            .ok_or(RetailAssetError::WaveArchiveNotFound)?;
        waves
            .find(
                ResourceName::Text(WAVE_RESOURCE_TYPE.to_owned()),
                ResourceName::Id(u32::from(sound_id.get())),
            )
            .map(ToOwned::to_owned)
            .ok_or(RetailAssetError::SoundNotFound(sound_id))
    }

    /// WAVE resource ids present in `Data/wave.gob`, in archive order.
    pub fn sound_ids(&self) -> Vec<SoundId> {
        let Some(waves) = &self.waves else {
            return Vec::new();
        };
        waves
            .english_resources
            .keys()
            .filter(|key| key.resource_type == ResourceName::Text(WAVE_RESOURCE_TYPE.to_owned()))
            .filter_map(|key| match key.name {
                ResourceName::Id(id) => u16::try_from(id).ok().map(SoundId::new),
                ResourceName::Text(_) => None,
            })
            .collect()
    }

    /// Host-frame tile from `Imperialism.exe` BITMAP `0x119` (`CMainFrame::OnEraseBkgnd`).
    ///
    /// The returned bytes are a BMP file assembled from the retail DIB, same as `picture()`.
    pub fn chrome_backdrop(&self) -> Result<Vec<u8>, RetailAssetError> {
        let dib = self
            .exe
            .find(
                ResourceName::Id(BITMAP_RESOURCE_TYPE),
                ResourceName::Id(CHROME_BACKDROP_BITMAP_ID),
            )
            .ok_or(RetailAssetError::ChromeBackdropNotFound)?;
        bitmap_resource_to_bmp(dib).map_err(|error| resource_error(&self.exe.path, error))
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
            RetailFontFace::System => {
                unreachable!("the Windows System font is supplied by the platform")
            }
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
                Err(FindError::NotFound) => match languages.get_data(Name::Id(NEUTRAL_LANGUAGE)) {
                    Ok(data) => data,
                    Err(FindError::NotFound) => continue,
                    Err(error) => return Err(resource_error(path, error)),
                },
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
    #[error("no English WAVE resource {0} is available")]
    SoundNotFound(SoundId),
    #[error("Data/wave.gob is not present in the retail directory")]
    WaveArchiveNotFound,
    #[error("no GOG music file is available for CD track {0}")]
    MusicTrackNotFound(MusicTrack),
    #[error("Imperialism.exe has no English BITMAP resource 0x119")]
    ChromeBackdropNotFound,
    #[error("no English turn-event cursor ~C{resource_id} is available")]
    CursorNotFound { resource_id: u16 },
    #[error("no English string is available for group {group:#06x}, direct index {direct_index}")]
    StringNotFound { group: i16, direct_index: i16 },
    #[error("no English text resource {0} is available")]
    StringIdNotFound(u16),
    #[error("Data/pictenu.gob has no English BITMAP resource 950.BMP")]
    DefaultDibPaletteNotFound,
    #[error("news.tab / news.tex are unavailable in Data/tabsenu.gob or as Data files")]
    NewsTableNotFound,
    #[error("{}: news.tab does not contain 360 rows", path.display())]
    NewsTableSize { path: PathBuf },
    #[error("{}: news.tab row {row} text range is outside news.tex", path.display())]
    NewsTextRange { path: PathBuf, row: usize },
    #[error("{}: invalid retail scenario data: {detail}", path.display())]
    Scenario { path: PathBuf, detail: String },
}

fn load_news_table(root: &Path) -> Result<NewsTable, RetailAssetError> {
    let tab = load_named_table(root, NEWS_TAB_NAME)?;
    let tex = load_named_table(root, NEWS_TEX_NAME)?;
    parse_news_table(root, &tab, &tex)
}

fn load_named_table(root: &Path, name: &str) -> Result<Vec<u8>, RetailAssetError> {
    if let Ok(archive) = ResourceArchive::read(root, TABLE_ARCHIVE_PATH)
        && let Some(bytes) = archive.find(
            ResourceName::Text("TABLE".to_owned()),
            ResourceName::Text(name.to_ascii_uppercase()),
        )
    {
        return Ok(bytes.to_vec());
    }
    for relative in [name, &format!("Data/{name}")] {
        let path = root.join(relative);
        if path.exists() {
            return read_file(&path);
        }
    }
    Err(RetailAssetError::NewsTableNotFound)
}

fn parse_news_table(root: &Path, tab: &[u8], tex: &[u8]) -> Result<NewsTable, RetailAssetError> {
    let path = root.join(NEWS_TAB_NAME);
    if tab.len() != NEWS_TEMPLATE_COUNT * NEWS_ROW_BYTES {
        return Err(RetailAssetError::NewsTableSize { path });
    }
    let mut story_ids = Vec::with_capacity(NEWS_TEMPLATE_COUNT);
    let mut headlines = Vec::with_capacity(NEWS_TEMPLATE_COUNT);
    let mut bodies = Vec::with_capacity(NEWS_TEMPLATE_COUNT);
    for (row, record) in tab.chunks_exact(NEWS_ROW_BYTES).enumerate() {
        let story_id = i32::from_be_bytes(record[0..4].try_into().expect("news.tab story id"));
        let headline = news_tex_slice(&path, row, tex, record[4..12].try_into().unwrap())?;
        let body = news_tex_slice(&path, row, tex, record[12..20].try_into().unwrap())?;
        story_ids.push(story_id);
        headlines.push(headline);
        bodies.push(body);
    }
    Ok(NewsTable {
        story_ids,
        headlines,
        bodies,
    })
}

fn news_tex_slice(
    path: &Path,
    row: usize,
    tex: &[u8],
    fields: [u8; 8],
) -> Result<String, RetailAssetError> {
    let offset = i32::from_be_bytes(fields[0..4].try_into().expect("news.tex offset"));
    let length = i32::from_be_bytes(fields[4..8].try_into().expect("news.tex length"));
    if offset < 0 || length < 0 {
        return Err(RetailAssetError::NewsTextRange {
            path: path.to_owned(),
            row,
        });
    }
    let start = offset as usize;
    let end = start.saturating_add(length as usize);
    let bytes = tex
        .get(start..end)
        .ok_or_else(|| RetailAssetError::NewsTextRange {
            path: path.to_owned(),
            row,
        })?;
    Ok(bytes.iter().map(|&byte| char::from(byte)).collect())
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

fn optional_archive(
    root: &Path,
    relative: &str,
) -> Result<Option<ResourceArchive>, RetailAssetError> {
    match ResourceArchive::read(root, relative) {
        Ok(archive) => Ok(Some(archive)),
        Err(RetailAssetError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
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
    const RESOURCE_SIZE: usize = 0x10000;

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
        assert_eq!(assets.news_table().story_ids()[0], 42);
        assert_eq!(assets.news_table().headline(0), "Title");
        assert_eq!(assets.news_table().body(0), "Body");

        let bitmap = assets.picture(PictureId::new(4500)).unwrap();
        assert_eq!(bitmap[bitmap.len() - 4], 0x22);
        assert_eq!(
            assets.default_dib_palette()[0x16],
            crate::Rgb::new(0x57, 0x8b, 0xa6)
        );
        let idle = assets.turn_event_cursor(0x41b).unwrap();
        assert_eq!(idle.width, 32);
        assert_eq!(idle.height, 32);
        assert_eq!(idle.rgba.len(), 32 * 32 * 4);
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
        assert_eq!(assets.string(0x2724, 12).unwrap(), "Civilian Report");
        assert_eq!(assets.string(0x2724, 13).unwrap(), "Rescind Orders");
        assert_eq!(assets.string(0x2724, 14).unwrap(), "Confirm Orders");
        let names = assets.random_game_names().unwrap();
        assert_eq!(names.localized_nation_names[NationId::new(0)], "Zimm");
        assert_eq!(names.localized_nation_names[NationId::new(22)], "Sindel");
        assert_eq!(
            names.province_names_by_nation[NationId::new(0)][0],
            "Bergen"
        );
        assert_eq!(
            names.province_names_by_nation[NationId::new(22)][0],
            "Vershire"
        );
        assert_eq!(names.zone_headline_templates[0], "[1] Lake");
        assert_eq!(names.fallback_ocean_names[0], "Red");
        assert!(
            assets
                .picture(PictureId::new(4500))
                .unwrap()
                .starts_with(b"BM")
        );
        let palette = assets.default_dib_palette();
        assert_eq!(palette[0x13], crate::Rgb::new(0xff, 0xff, 0xff));
        assert_eq!(palette[0x16], crate::Rgb::new(0x57, 0x8b, 0xa6));
        let peace = assets
            .turn_event_cursor(1028)
            .expect("diplomacy peace cursor ~C1028");
        assert_eq!(peace.width, 32);
        assert_eq!(peace.height, 32);
        assert_eq!(peace.rgba.len(), 32 * 32 * 4);
        assert!(assets.chrome_backdrop().unwrap().starts_with(b"BM"));
    }

    #[test]
    fn discovers_media_paths_without_requiring_wave_or_music_at_open() {
        let root = synthetic_retail_install();
        write_retail_file(root.path(), "MUSIC/Track06.ogg", b"not a real ogg");
        let assets = RetailAssets::open(root.path()).unwrap();

        assert_eq!(
            assets.movie_path(MovieId::Open),
            root.path().join("Movies/open.avi")
        );
        assert_eq!(
            assets.movie_path(MovieId::Vote),
            root.path().join("Movies/vote.avi")
        );
        assert!(!assets.movie_path(MovieId::Open).exists());
        assert_eq!(
            assets.music_track_path(MusicTrack::MAIN_MENU).unwrap(),
            root.path().join("MUSIC/Track06.ogg")
        );
        assert!(matches!(
            assets.music_track_path(MusicTrack::DIPLOMACY),
            Err(RetailAssetError::MusicTrackNotFound(_))
        ));
        assert!(matches!(
            assets.sound(SoundId::UI_CLICK),
            Err(RetailAssetError::WaveArchiveNotFound)
        ));
        assert!(assets.sound_ids().is_empty());
        assert!(assets.chrome_backdrop().unwrap().starts_with(b"BM"));
    }

    #[test]
    fn loads_wave_resources_from_wave_gob() {
        let root = synthetic_retail_install();
        write_retail_file(
            root.path(),
            WAVE_ARCHIVE_PATH,
            &synthetic_pe(vec![TestResource::new(
                TestName::text(WAVE_RESOURCE_TYPE),
                TestName::id(u32::from(SoundId::UI_CLICK.get())),
                pcm_wav(),
            )]),
        );
        let assets = RetailAssets::open(root.path()).unwrap();
        let wave = assets.sound(SoundId::UI_CLICK).unwrap();
        assert!(wave.starts_with(b"RIFF"));
        assert_eq!(assets.sound_ids(), vec![SoundId::UI_CLICK]);
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at the English GOG installation"]
    fn inventories_gog_movies_music_and_wave_resources() {
        let root = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let assets = RetailAssets::open(&root).unwrap();
        for movie in [MovieId::Open, MovieId::Vote, MovieId::Win, MovieId::Lose] {
            let path = assets.movie_path(movie);
            assert!(
                path.is_file(),
                "expected GOG cinematic {} at {}",
                movie.file_stem(),
                path.display()
            );
        }
        let menu = assets
            .music_track_path(MusicTrack::MAIN_MENU)
            .expect("GOG MUSIC/Track06.* replacement for CD cue 6");
        assert!(menu.is_file(), "{}", menu.display());
        assert!(
            !assets.sound_ids().is_empty(),
            "Data/wave.gob should expose WAVE resources"
        );
        assert!(
            assets
                .sound(SoundId::UI_CLICK)
                .expect("WAVE 7000")
                .starts_with(b"RIFF")
        );
        let backdrop = assets.chrome_backdrop().unwrap();
        assert!(backdrop.starts_with(b"BM"));
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at the English GOG installation"]
    fn loads_recovered_civilian_order_sounds() {
        let root = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let assets = RetailAssets::open(&root).unwrap();
        for id in [
            0x2328, 0x2329, 0x232a, 0x232b, 0x232c, 0x232d, 0x232e, 0x2331, 0x2332, 0x2333, 0x2335,
            0x2338, 0x2339,
        ] {
            assert!(
                assets
                    .sound(SoundId::new(id))
                    .unwrap_or_else(|_| panic!("civilian WAVE {id}"))
                    .starts_with(b"RIFF")
            );
        }
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
        let mut news_tab = vec![0; NEWS_TEMPLATE_COUNT * NEWS_ROW_BYTES];
        news_tab[0..4].copy_from_slice(&42_i32.to_be_bytes());
        news_tab[8..12].copy_from_slice(&5_i32.to_be_bytes());
        news_tab[12..16].copy_from_slice(&5_i32.to_be_bytes());
        news_tab[16..20].copy_from_slice(&4_i32.to_be_bytes());
        write_retail_file(
            root.path(),
            TABLE_ARCHIVE_PATH,
            &synthetic_pe(vec![
                TestResource::new(
                    TestName::text("TABLE"),
                    TestName::text("NEWS.TAB"),
                    news_tab,
                ),
                TestResource::new(
                    TestName::text("TABLE"),
                    TestName::text("NEWS.TEX"),
                    b"TitleBody".to_vec(),
                ),
            ]),
        );
        write_retail_file(
            root.path(),
            EXE_PATH,
            &synthetic_pe(turn_event_cursor_resources()),
        );
        root
    }

    fn turn_event_cursor_resources() -> Vec<TestResource> {
        let cursor = one_bit_cursor_resource();
        let group = group_cursor_directory(cursor.len() as u32, 7);
        let mut resources = vec![
            TestResource::new(TestName::id(CURSOR_RESOURCE_TYPE), TestName::id(7), cursor),
            TestResource::new(
                TestName::id(BITMAP_RESOURCE_TYPE),
                TestName::id(CHROME_BACKDROP_BITMAP_ID),
                default_palette_dib(),
            ),
        ];
        for index in 0..RetailAssets::TURN_EVENT_CURSOR_COUNT {
            let id = RetailAssets::TURN_EVENT_CURSOR_BASE + index as u16;
            resources.push(TestResource::new(
                TestName::id(GROUP_CURSOR_RESOURCE_TYPE),
                TestName::text(&format!("~C{id}")),
                group.clone(),
            ));
        }
        resources
    }

    fn one_bit_cursor_resource() -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&40u32.to_le_bytes());
        blob.extend_from_slice(&32i32.to_le_bytes());
        blob.extend_from_slice(&64i32.to_le_bytes());
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&256u32.to_le_bytes());
        blob.extend_from_slice(&0i32.to_le_bytes());
        blob.extend_from_slice(&0i32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0]);
        blob.extend_from_slice(&[0u8; 128]);
        blob.extend_from_slice(&[0xffu8; 128]);
        blob
    }

    fn group_cursor_directory(resource_size: u32, resource_id: u16) -> Vec<u8> {
        let mut group = Vec::new();
        group.extend_from_slice(&0u16.to_le_bytes());
        group.extend_from_slice(&2u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&32u16.to_le_bytes());
        group.extend_from_slice(&64u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&resource_size.to_le_bytes());
        group.extend_from_slice(&resource_id.to_le_bytes());
        group
    }

    fn write_retail_file(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn pcm_wav() -> Vec<u8> {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&36u32.to_le_bytes());
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&16000u32.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[0, 0, 0, 0]);
        wav
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
