/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */
use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use typst::{
    diag::{FileError, FileResult, PackageError, PackageResult},
    ecow::eco_format,
    foundations::{Bytes, Datetime},
    syntax::{package::PackageSpec, FileId, Source, VirtualPath},
    text::{Font, FontBook, FontInfo},
    utils::LazyHash,
    Library, LibraryExt,
};
use typst_pdf::PdfOptions;

#[uniffi::export]
fn render(main_file: &str, additional_files: HashMap<String, Vec<u8>>) -> Vec<u8> {
    let world = TypstWrapperWorld::new(".", main_file, additional_files);
    let doc = typst::compile(&world);
    let Ok(doc_output) = doc.output else {
        return vec![];
    };
    let Ok(pdf) = typst_pdf::pdf(&doc_output, &PdfOptions::default()) else {
        return vec![];
    };
    pdf
}

/// Main interface that determines the environment for Typst.
pub struct TypstWrapperWorld {
    /// Root path to which files will be resolved.
    root: PathBuf,

    /// The content of a source.
    source: Source,

    /// The standard library.
    library: LazyHash<Library>,

    /// Metadata about all known fonts.
    book: LazyHash<FontBook>,

    /// Metadata about all known fonts.
    fonts: Vec<Font>,

    /// Map of all known files.
    files: Arc<Mutex<HashMap<FileId, FileEntry>>>,

    /// Cache directory (e.g. where packages are downloaded to).
    cache_directory: PathBuf,

    /// http agent to download packages.
    http: ureq::Agent,

    /// Datetime.
    time: time::OffsetDateTime,
}

impl TypstWrapperWorld {
    pub fn new(root: &str, source: &str, additional_files: HashMap<String, Vec<u8>>) -> Self {
        let root = PathBuf::from(root);
        let (font_book, fonts) = load_fonts();
        let mut files = HashMap::new();
        for (name, content) in additional_files {
            files.insert(
                FileId::new(None, VirtualPath::new(name)),
                FileEntry::new(content, None),
            );
        }

        Self {
            library: LazyHash::new(Library::default()),
            book: LazyHash::new(font_book),
            root,
            fonts,
            source: Source::detached(source),
            time: time::OffsetDateTime::now_utc(),
            cache_directory: std::env::var_os("CACHE_DIRECTORY")
                .map(|os_path| os_path.into())
                .unwrap_or(std::env::temp_dir()),
            http: ureq::Agent::new_with_defaults(),
            files: Arc::new(Mutex::new(files)),
        }
    }
}

/// A File that will be stored in the HashMap.
#[derive(Clone, Debug)]
struct FileEntry {
    bytes: Bytes,
    source: Option<Source>,
}

impl FileEntry {
    fn new(bytes: Vec<u8>, source: Option<Source>) -> Self {
        Self {
            bytes: Bytes::new(bytes),
            source,
        }
    }

    fn source(&mut self, id: FileId) -> FileResult<Source> {
        let source = if let Some(source) = &self.source {
            source
        } else {
            let contents = std::str::from_utf8(&self.bytes).map_err(|_| FileError::InvalidUtf8)?;
            let contents = contents.trim_start_matches('\u{feff}');
            let source = Source::new(id, contents.into());
            self.source.insert(source)
        };
        Ok(source.clone())
    }
}

impl TypstWrapperWorld {
    /// Helper to handle file requests.
    ///
    /// Requests will be either in packages or a local file.
    fn file(&self, id: FileId) -> FileResult<FileEntry> {
        let mut files = self.files.lock().map_err(|_| FileError::AccessDenied)?;
        if let Some(entry) = files.get(&id) {
            return Ok(entry.clone());
        }
        let path = if let Some(package) = id.package() {
            // Fetching file from package
            let package_dir = self.download_package(package)?;
            id.vpath().resolve(&package_dir)
        } else {
            // Fetching file from disk
            id.vpath().resolve(&self.root)
        }
        .ok_or(FileError::AccessDenied)?;

        let content = std::fs::read(&path).map_err(|error| FileError::from_io(error, &path))?;
        Ok(files
            .entry(id)
            .or_insert(FileEntry::new(content, None))
            .clone())
    }

    /// Downloads the package and returns the system path of the unpacked package.
    fn download_package(&self, package: &PackageSpec) -> PackageResult<PathBuf> {
        let package_subdir = format!("{}/{}/{}", package.namespace, package.name, package.version);
        let path = self.cache_directory.join(package_subdir);

        if path.exists() {
            return Ok(path);
        }

        eprintln!("downloading {package}");
        let url = format!(
            "https://packages.typst.org/{}/{}-{}.tar.gz",
            package.namespace, package.name, package.version,
        );

        let response = retry(|| {
            let response = self
                .http
                .get(&url)
                .call()
                .map_err(|error| eco_format!("{error}"))?;

            let status = response.status();
            if !status.is_success() {
                return Err(eco_format!(
                    "response returned unsuccessful status code {status}",
                ));
            }

            Ok(response)
        })
        .map_err(|error| PackageError::NetworkFailed(Some(error)))?;

        let mut compressed_archive = Vec::new();
        response
            .into_body()
            .into_reader()
            .read_to_end(&mut compressed_archive)
            .map_err(|error| PackageError::NetworkFailed(Some(eco_format!("{error}"))))?;
        let raw_archive = zune_inflate::DeflateDecoder::new(&compressed_archive)
            .decode_gzip()
            .map_err(|error| PackageError::MalformedArchive(Some(eco_format!("{error}"))))?;
        let mut archive = tar::Archive::new(raw_archive.as_slice());
        archive.unpack(&path).map_err(|error| {
            _ = std::fs::remove_dir_all(&path);
            PackageError::MalformedArchive(Some(eco_format!("{error}")))
        })?;

        Ok(path)
    }
}

/// This is the interface we have to implement such that `typst` can compile it.
///
/// I have tried to keep it as minimal as possible
impl typst::World for TypstWrapperWorld {
    /// Standard library.
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    /// Metadata about all known Books.
    fn book(&self) -> &LazyHash<FontBook> {
        &self.book
    }

    /// Accessing the main source file.
    fn main(&self) -> FileId {
        self.source.id()
    }

    /// Accessing a specified source file (based on `FileId`).
    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.source.id() {
            Ok(self.source.clone())
        } else {
            self.file(id)?.source(id)
        }
    }

    /// Accessing a specified file (non-file).
    fn file(&self, id: FileId) -> FileResult<Bytes> {
        self.file(id).map(|file| file.bytes.clone())
    }

    /// Accessing a specified font per index of font book.
    fn font(&self, id: usize) -> Option<Font> {
        self.fonts.get(id).cloned()
    }

    /// Get the current date.
    ///
    /// Optionally, an offset in hours is given.
    fn today(&self, offset: Option<i64>) -> Option<Datetime> {
        let offset = offset.unwrap_or(0);
        let offset = time::UtcOffset::from_hms(offset.try_into().ok()?, 0, 0).ok()?;
        let time = self.time.checked_to_offset(offset)?;
        Some(Datetime::Date(time.date()))
    }
}

/// Helper function
fn fonts() -> Vec<Font> {
    typst_assets::fonts()
        .map(|entry| {
            let buffer = Bytes::new(entry);
            let face_count = ttf_parser::fonts_in_collection(&buffer).unwrap_or(1);

            (0..face_count)
                .map(move |face| {
                    Font::new(buffer.clone(), face).unwrap_or_else(|| {
                        panic!("failed to load font from embedded assets (face index {face})")
                    })
                })
                .collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect()
}

pub fn load_fonts() -> (FontBook, Vec<Font>) {
    let mut fonts = fonts();

    let mut db = fontdb::Database::new();
    db.load_system_fonts();

    let mut book = FontBook::from_fonts(&fonts);
    for font_face in db.faces() {
        let info = db
            .with_face_data(font_face.id, FontInfo::new)
            .expect("database must contain this font");

        let path = match &font_face.source {
            fontdb::Source::File(path) | fontdb::Source::SharedFile(path, _) => path,
            // We never add binary sources to the database, so there
            // shouln't be any.
            fontdb::Source::Binary(_) => continue,
        };
        let font_data = std::fs::read(path).unwrap();
        if let Some(font) = Font::new(typst::foundations::Bytes::new(font_data), font_face.index) {
            fonts.push(font);
            book.push(info.unwrap());
        } else {
            println!("{:?} not found", path);
        }
    }
    for data in typst_assets::fonts() {
        let buffer = typst::foundations::Bytes::new(data);
        for (_, font) in Font::iter(buffer).enumerate() {
            book.push(font.info().clone());
            fonts.push(font);
        }
    }
    (book, fonts)
}

fn retry<T, E>(mut f: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    if let Ok(ok) = f() {
        Ok(ok)
    } else {
        f()
    }
}

uniffi::setup_scaffolding!();
