use crate::color::DibPalette;
use crate::media::{MovieId, MusicTrack, SoundId};
use crate::retail_resources::*;
use crate::{PictureId, RetailCursor, RetailFontFace, ScenarioInfo, StringGroup, StringResourceId};
use imperialism_core::{
    MajorNationId, MapMgr, NEWS_TEMPLATE_COUNT, NationId, NationTable, RandomGameNames,
    ScenarioInstruction, ScenarioMapId,
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
/// The object owns raw archive/exe bytes and indexes English PE resource ranges during opening.
/// It deliberately retains no borrowed PE views.
#[derive(Debug)]
pub struct RetailAssets {
    root: PathBuf,
    pictures: [ResourceArchive; 4],
    strings: ResourceArchive,
    exe: ResourceArchive,
    waves: Option<ResourceArchive>,
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
        let news = load_news_table(&root)?;

        Ok(Self {
            root,
            pictures,
            strings,
            exe,
            waves,
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

    /// Decodes the retail startup script for one scenario map.
    pub fn scenario_script(
        &self,
        scenario: ScenarioMapId,
    ) -> Result<Vec<ScenarioInstruction>, RetailAssetError> {
        let relative = format!("Scenario/s{}.scn", scenario.index());
        let path = self.root.join(&relative);
        let bytes = fs::read(&path).map_err(|source| RetailAssetError::Io {
            path: path.clone(),
            source,
        })?;
        crate::decode_scenario_script(&bytes)
            .map_err(|source| RetailAssetError::ScenarioScript { path, source })
    }

    /// Reads every installed single-player scenario chooser entry.
    pub fn single_player_scenarios(&self) -> Result<Vec<ScenarioInfo>, RetailAssetError> {
        let mut scenarios = Vec::new();
        for index in 9..16 {
            let scenario = ScenarioMapId::new(index);
            let relative = format!("Scenario/s{index}.inf");
            let path = self.root.join(&relative);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).map_err(|source| RetailAssetError::Io {
                path: path.clone(),
                source,
            })?;
            scenarios.push(
                crate::decode_scenario_info(scenario, &bytes)
                    .map_err(|detail| RetailAssetError::ScenarioInfo { path, detail })?,
            );
        }
        Ok(scenarios)
    }

    /// Decodes the fixed retail strategic map for one scenario.
    pub fn scenario_map(&self, scenario: ScenarioMapId) -> Result<MapMgr, RetailAssetError> {
        let relative = format!("Scenario/s{}.map", scenario.index());
        let path = self.root.join(&relative);
        let bytes = fs::read(&path).map_err(|source| RetailAssetError::Io {
            path: path.clone(),
            source,
        })?;
        crate::legacy_save::decode_scenario_map(&bytes)
            .map_err(|detail| RetailAssetError::ScenarioMap { path, detail })
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

    /// Loads one Windows `LoadStringA` / `RT_STRING` identifier from the English
    /// retail string library.
    pub fn string(&self, id: StringResourceId) -> Result<String, RetailAssetError> {
        match self.string_table_entry(id.get()) {
            Some(result) => result,
            None => Err(RetailAssetError::StringNotFound(id)),
        }
    }

    /// Loads one long-form help body by its raw PE resource ID.
    ///
    /// Callers treat these as a distinct provenance from ordinary UI string
    /// lookups even though retail stores both in the same `RT_STRING` table.
    pub fn text(&self, resource_id: u16) -> Result<String, RetailAssetError> {
        match self.string_table_entry(resource_id) {
            Some(result) => result,
            None => Err(RetailAssetError::TextNotFound(resource_id)),
        }
    }

    /// Shared `RT_STRING` block/slot decode used by [`Self::string`] and [`Self::text`].
    fn string_table_entry(&self, id: u16) -> Option<Result<String, RetailAssetError>> {
        let block_id = u32::from((id >> 4) + 1);
        let slot = usize::from(id & 0xf);
        let block = self.strings.find(
            ResourceName::Id(STRING_RESOURCE_TYPE),
            ResourceName::Id(block_id),
        )?;
        Some(decode_string_table_entry(&self.strings.path, block, slot))
    }

    /// Materializes the localized STR# inputs used by random-game province and ocean naming.
    pub fn random_game_names(&self) -> Result<RandomGameNames, RetailAssetError> {
        let nation_names = StringGroup::new(0x2715);
        let zone_headlines = StringGroup::new(0x275a);
        let fallback_oceans = StringGroup::new(0x275b);

        let mut localized_nation_names = NationTable::default();
        for nation in NationId::all() {
            // `TSimMgr::GetString(0x2715, nationSlot)` adds one before direct lookup.
            localized_nation_names[nation] =
                self.string(nation_names.offset(u16::from(nation.get())))?;
        }

        let mut province_names_by_nation: NationTable<Vec<String>> = NationTable::default();
        for nation in NationId::all() {
            let name_count = if MajorNationId::from_nation(nation).is_some() {
                8
            } else {
                4
            };
            let province_names = StringGroup::new(8000 + u16::from(nation.get()));
            for ordinal in 1..=name_count {
                // `TSimMgr::GetString(group, offset)` adds one before the direct resource lookup.
                province_names_by_nation[nation].push(
                    self.string(
                        province_names.offset(
                            u16::try_from(ordinal).expect("province-name ordinal fits u16"),
                        ),
                    )?,
                );
            }
        }

        let mut zone_headline_templates = Vec::with_capacity(24);
        for status_code in 0..24u16 {
            // `TSimMgr::GetString(0x275a, statusCode)` performs this same +1 conversion.
            zone_headline_templates.push(self.string(zone_headlines.offset(status_code))?);
        }
        let mut fallback_ocean_names = Vec::with_capacity(37);
        for cache_id in 0..37u16 {
            // The localized fallback cursor is a zero-based `GetString(0x275b, cacheId)` offset.
            fallback_ocean_names.push(self.string(fallback_oceans.offset(cache_id))?);
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

    /// Reads a GOG-shipped TrueType face from `Data/*.ttf`.
    ///
    /// `RetailFontFace::System` is not a retail file; the application supplies it.
    pub fn read_font(&self, face: RetailFontFace) -> Result<Option<Vec<u8>>, RetailAssetError> {
        let Some(relative) = shipped_font_relative_path(face) else {
            return Ok(None);
        };
        Ok(Some(read_file(&self.root.join(relative))?))
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

fn shipped_font_relative_path(face: RetailFontFace) -> Option<&'static str> {
    match face {
        RetailFontFace::System => None,
        RetailFontFace::BelweBold => Some("Data/WeBeBd__.ttf"),
        RetailFontFace::BookAntiquaRegular => Some("Data/Antqua.ttf"),
        RetailFontFace::BookAntiquaBold => Some("Data/Antquab.ttf"),
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
    #[error("{}: {source}", path.display())]
    ScenarioScript {
        path: PathBuf,
        #[source]
        source: crate::ScenarioScriptError,
    },
    #[error("{}: {detail}", path.display())]
    ScenarioMap { path: PathBuf, detail: String },
    #[error("could not decode scenario metadata {path}: {detail}")]
    ScenarioInfo { path: PathBuf, detail: String },
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
    #[error("no English string resource {0} is available")]
    StringNotFound(StringResourceId),
    #[error("no English TEXT resource {0} is available")]
    TextNotFound(u16),
    #[error("Data/pictenu.gob has no English BITMAP resource 950.BMP")]
    DefaultDibPaletteNotFound,
    #[error("news.tab / news.tex are unavailable in Data/tabsenu.gob or as Data files")]
    NewsTableNotFound,
    #[error("{}: news.tab does not contain 360 rows", path.display())]
    NewsTableSize { path: PathBuf },
    #[error("{}: news.tab row {row} text range is outside news.tex", path.display())]
    NewsTextRange { path: PathBuf, row: usize },
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
    // NEWS.TEX records are C strings: retail copies the whole recorded span,
    // then constructs a CString from it.  The length therefore includes the
    // terminating NUL, which is not text to render.
    Ok(bytes
        .strip_suffix(&[0])
        .unwrap_or(bytes)
        .iter()
        .map(|&byte| char::from(byte))
        .collect())
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

    #[test]
    fn news_text_discards_the_retail_c_string_terminator() {
        let path = Path::new("news.tex");
        assert_eq!(
            news_tex_slice(path, 0, b"Headline\0", [0, 0, 0, 0, 0, 0, 0, 9]).unwrap(),
            "Headline"
        );
    }

    #[test]
    fn pelite_indexes_a_minimal_english_resource_directory() {
        let path = Path::new("fixture.gob");
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/minimal_resource.pe"
        ))
        .expect("checked-in minimal PE fixture");
        assert_eq!(bytes.len(), 66_048);
        let index = index_english_resources(path, &bytes).unwrap();
        let key = ResourceKey {
            resource_type: ResourceName::Id(STRING_RESOURCE_TYPE),
            name: ResourceName::Id(1117),
        };
        let range = index.get(&key).expect("RT_STRING block 1117");
        let block = &bytes[range.clone()];
        assert_eq!(
            decode_string_table_entry(path, block, 5).unwrap(),
            "Textile Mill"
        );
    }

    #[test]
    fn resource_archive_find_resolves_indexed_bytes() {
        let payload = b"payload";
        let mut index = BTreeMap::new();
        index.insert(
            ResourceKey {
                resource_type: ResourceName::Text(WAVE_RESOURCE_TYPE.to_owned()),
                name: ResourceName::Id(7000),
            },
            0..payload.len(),
        );
        let archive = ResourceArchive {
            path: PathBuf::from("test.gob"),
            bytes: payload.to_vec(),
            english_resources: index,
        };
        assert_eq!(
            archive.find(
                ResourceName::Text(WAVE_RESOURCE_TYPE.to_owned()),
                ResourceName::Id(7000),
            ),
            Some(b"payload".as_slice())
        );
        assert!(
            archive
                .find(
                    ResourceName::Text(WAVE_RESOURCE_TYPE.to_owned()),
                    ResourceName::Id(7001),
                )
                .is_none()
        );
    }

    #[test]
    fn decode_string_table_entry_reads_the_requested_slot() {
        let mut block = Vec::new();
        for slot in 0..16 {
            let words = if slot == 9 {
                "Clipper description".encode_utf16().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            block.extend_from_slice(&(words.len() as u16).to_le_bytes());
            for word in words {
                block.extend_from_slice(&word.to_le_bytes());
            }
        }
        assert_eq!(
            decode_string_table_entry(Path::new("strings.gob"), &block, 9).unwrap(),
            "Clipper description"
        );
    }
}
