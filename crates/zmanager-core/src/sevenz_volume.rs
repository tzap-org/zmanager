//! Split-volume machinery for the 7z backend.
//!
//! `sevenz_rust2` writes a single seekable archive; splitting it into
//! numbered `.7z.001`/`.7z.002`/... volumes is done byte-wise after the
//! archive is finished. Reading a split set requires discovering all parts
//! from any part's path and exposing them as one contiguous
//! [`Read`] + [`Seek`] stream.

use crate::segmented_reader::SegmentedReader;
use crate::sevenz_backend::SevenZError;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const MIN_VOLUME_SIZE_BYTES: u64 = 1_048_576;
const SEVENZ_VOLUME_EXTENSION_WIDTH: usize = 3;

pub(crate) fn split_7z_temp_archive(archive_path: &Path, destination: &Path, volume_size: u64, replace_existing: bool) -> Result<usize, SevenZError> {
    let archive_size = fs::metadata(archive_path).map_err(|source| SevenZError::Io { path: archive_path.to_path_buf(), source })?.len();
    let volume_count = crate::archive_split::split_volume_count(archive_size, volume_size)
        .ok_or_else(|| io_error(destination, io::ErrorKind::InvalidInput, "too many 7z volumes"))?;
    let volume_paths = sevenz_volume_paths(destination, volume_count)?;

    let existing_volume_paths = existing_7z_volume_paths(destination)?;
    ensure_split_destinations_available(destination, &volume_paths, &existing_volume_paths, replace_existing)?;

    let archive_file = File::open(archive_path).map_err(|source| SevenZError::Io { path: archive_path.to_path_buf(), source })?;
    let mut archive = BufReader::new(archive_file);
    let mut volume_outputs = Vec::with_capacity(volume_paths.len());

    for (index, volume_path) in volume_paths.iter().enumerate() {
        let mut output = crate::atomic_file::AtomicOutputFile::create(volume_path).map_err(|source| SevenZError::Io { path: volume_path.clone(), source })?;
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(volume_size))
            .ok_or_else(|| io_error(volume_path, io::ErrorKind::InvalidInput, "7z volume offset overflow"))?;
        let bytes_to_copy = archive_size.saturating_sub(offset).min(volume_size);
        let output_file = output.file_mut().map_err(|source| SevenZError::Io { path: volume_path.clone(), source })?;
        copy_exact_volume_bytes(&mut archive, output_file, bytes_to_copy, volume_path)?;
        output.close();
        volume_outputs.push(output);
    }

    let created_volume_count = volume_paths.len();
    let mut previous_paths = existing_volume_paths;
    previous_paths.push(destination.to_path_buf());
    crate::atomic_file::commit_file_set(volume_outputs, &previous_paths, replace_existing)
        .map_err(|source| SevenZError::Io { path: destination.to_path_buf(), source })?;

    Ok(created_volume_count)
}

fn sevenz_volume_paths(destination: &Path, count: usize) -> Result<Vec<PathBuf>, SevenZError> {
    let mut paths = Vec::with_capacity(count);
    for index in 1..=count {
        let index = u64::try_from(index).map_err(|_| io_error(destination, io::ErrorKind::InvalidInput, "too many 7z volumes"))?;
        paths.push(sevenz_volume_path(destination, index));
    }
    Ok(paths)
}

fn sevenz_volume_path(destination: &Path, one_based_index: u64) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(format!(".{one_based_index:0SEVENZ_VOLUME_EXTENSION_WIDTH$}"));
    PathBuf::from(path)
}

fn ensure_split_destinations_available(
    destination: &Path,
    volume_paths: &[PathBuf],
    existing_volume_paths: &[PathBuf],
    replace_existing: bool,
) -> Result<(), SevenZError> {
    ensure_file_destination_available(destination, replace_existing)?;
    for path in crate::archive_split::unique_paths(volume_paths, existing_volume_paths) {
        ensure_file_destination_available(path, replace_existing)?;
    }
    Ok(())
}

fn ensure_file_destination_available(path: &Path, replace_existing: bool) -> Result<(), SevenZError> {
    crate::archive_split::ensure_file_destination_available(path, replace_existing).map_err(|source| SevenZError::Io { path: path.to_path_buf(), source })
}

fn existing_7z_volume_paths(destination: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(destination_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let directory = destination.parent().unwrap_or_else(|| Path::new("."));
    crate::archive_split::existing_volume_paths(directory, &mut |candidate_name| {
        parse_7z_volume_file_name(candidate_name).filter(|(base_name, _)| *base_name == destination_name).map(|(_, part)| part)
    })
    .map_err(|source| SevenZError::Io { path: directory.to_path_buf(), source })
}

pub(crate) fn parse_7z_volume_file_name(name: &str) -> Option<(&str, u32)> {
    let (base, number) = name.rsplit_once('.')?;
    if number.len() != SEVENZ_VOLUME_EXTENSION_WIDTH || !number.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    let part = number.parse().ok()?;
    (part > 0).then_some((base, part))
}

pub(crate) fn has_7z_extension(value: &str) -> bool {
    Path::new(value).extension().is_some_and(|extension| extension.eq_ignore_ascii_case("7z"))
}

pub(crate) fn discover_7z_read_volume_paths(path: &Path) -> Result<Vec<PathBuf>, SevenZError> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(vec![path.to_path_buf()]);
    };
    let lower_name = file_name.to_ascii_lowercase();
    let volume_base = if let Some((base, _)) = parse_7z_volume_file_name(&lower_name) {
        if !has_7z_extension(base) {
            return Ok(vec![path.to_path_buf()]);
        }
        base.to_owned()
    } else if has_7z_extension(&lower_name) {
        lower_name
    } else {
        return Ok(vec![path.to_path_buf()]);
    };
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(vec![path.to_path_buf()]);
        }
        Err(source) => {
            return Err(SevenZError::Io { path: directory.to_path_buf(), source });
        }
    };

    let mut parts = BTreeMap::new();
    for entry in entries.flatten() {
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        let candidate_lower = candidate_name.to_ascii_lowercase();
        if let Some((candidate_base, part)) = parse_7z_volume_file_name(&candidate_lower)
            && candidate_base == volume_base
        {
            parts.insert(part, entry.path());
        }
    }

    if parts.is_empty() {
        return Ok(vec![path.to_path_buf()]);
    }
    let max_part = *parts.keys().last().unwrap_or(&0);
    for expected in 1..=max_part {
        if !parts.contains_key(&expected) {
            return Err(io_error(path, io::ErrorKind::NotFound, format!("missing 7z volume part {expected:03}")));
        }
    }
    Ok(parts.into_values().collect())
}

pub(crate) type MultiVolumeReader = SegmentedReader;

fn copy_exact_volume_bytes<R: Read, W: Write>(reader: &mut R, writer: &mut W, bytes_to_copy: u64, volume_path: &Path) -> Result<(), SevenZError> {
    let mut limited = reader.take(bytes_to_copy);
    let copied = io::copy(&mut limited, writer).map_err(|source| SevenZError::Io { path: volume_path.to_path_buf(), source })?;
    if copied != bytes_to_copy {
        return Err(io_error(volume_path, io::ErrorKind::UnexpectedEof, "7z temp archive ended before volume was filled"));
    }
    Ok(())
}

fn io_error(path: &Path, kind: io::ErrorKind, message: impl Into<String>) -> SevenZError {
    SevenZError::Io { path: path.to_path_buf(), source: io::Error::new(kind, message.into()) }
}

#[cfg(test)]
mod tests {
    use super::{MIN_VOLUME_SIZE_BYTES, MultiVolumeReader};
    use crate::manifest::{PlanOptions, plan_archives};
    use crate::safety::{ExtractionPolicy, OverwritePolicy};
    use crate::secrets::SecretString;
    use crate::sevenz_backend::{SevenZCreateOptions, SevenZError, create_7z_from_manifest, create_7z_from_path, extract_7z, list_7z};
    use crate::test_support::TestDir;
    use std::fs;
    use std::io::{Read as _, Seek as _, SeekFrom};

    #[test]
    fn creates_split_7z_volumes() {
        let temp = TestDir::new("creates_split_7z_volumes");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { solid: false, level: Some(1), volume_size: Some(MIN_VOLUME_SIZE_BYTES), ..SevenZCreateOptions::default() },
        )
        .unwrap();

        assert_eq!(report.volume_size, Some(MIN_VOLUME_SIZE_BYTES));
        assert!(report.volume_count >= 2);
        assert!(!archive.exists());
        assert_eq!(fs::metadata(temp.path("payload.7z.001")).unwrap().len(), MIN_VOLUME_SIZE_BYTES);

        let mut joined = Vec::new();
        for index in 1..=report.volume_count {
            let part = temp.path(format!("payload.7z.{index:03}"));
            let part_bytes = fs::read(part).unwrap();
            assert!(u64::try_from(part_bytes.len()).unwrap() <= MIN_VOLUME_SIZE_BYTES);
            joined.extend(part_bytes);
        }
        temp.write_file("joined.7z", &joined);

        let listing = list_7z(temp.path("joined.7z"), None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/blob.bin"));
        let extract_report = extract_7z(temp.path("joined.7z"), temp.path("out"), None, ExtractionPolicy::default()).unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn passworded_split_7z_volumes_read_from_first_part() {
        let temp = TestDir::new("passworded_split_7z_volumes_read_from_first_part");
        let payload = deterministic_bytes(3 * 1024 * 1024);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");
        let first_volume = temp.path("payload.7z.001");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                password: Some(SecretString::from("correct horse")),
                encrypt_file_names: true,
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(report.encrypted);
        assert!(report.volume_count >= 2);
        assert!(matches!(list_7z(&first_volume, None), Err(SevenZError::PasswordRequired)));

        let listing = list_7z(&first_volume, Some("correct horse")).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/blob.bin"));
        let extract_report = extract_7z(&first_volume, temp.path("out"), Some("correct horse"), ExtractionPolicy::default()).unwrap();

        assert_eq!(extract_report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn solid_split_7z_volumes_extract_from_first_part() {
        let temp = TestDir::new("solid_split_7z_volumes_extract_from_first_part");
        let payload = deterministic_bytes(3_200_000);
        temp.write_file("payload/blob.bin", &payload);
        let archive = temp.path("payload.7z");
        let first_volume = temp.path("payload.7z.001");

        let manifest = plan_archives([temp.path("payload")], &PlanOptions::default()).unwrap();
        let create_report =
            create_7z_from_manifest(&manifest, &archive, &SevenZCreateOptions { volume_size: Some(MIN_VOLUME_SIZE_BYTES), ..SevenZCreateOptions::default() })
                .unwrap();
        assert!(create_report.volume_count >= 2);

        let listing = list_7z(&first_volume, None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/blob.bin"));

        let report =
            extract_7z(&first_volume, temp.path("out"), None, ExtractionPolicy { overwrite: OverwritePolicy::Replace, ..ExtractionPolicy::default() }).unwrap();

        assert_eq!(report.written_bytes, payload.len() as u64);
        assert_eq!(fs::read(temp.path("out/payload/blob.bin")).unwrap(), payload);
    }

    #[test]
    fn single_volume_split_7z_reads_from_base_path() {
        let temp = TestDir::new("single_volume_split_7z_reads_from_base_path");
        temp.write_file("payload/file.txt", b"small payload");
        let archive = temp.path("payload.7z");

        let report = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { solid: false, level: Some(1), volume_size: Some(MIN_VOLUME_SIZE_BYTES), ..SevenZCreateOptions::default() },
        )
        .unwrap();

        assert_eq!(report.volume_count, 1);
        assert!(!archive.exists());
        assert!(temp.path("payload.7z.001").exists());

        let listing = list_7z(&archive, None).unwrap();
        assert!(listing.entries.iter().any(|entry| entry.name == "payload/file.txt"));
    }

    #[test]
    fn multi_volume_reader_streams_across_parts_and_supports_reseek() {
        let temp = TestDir::new("multi_volume_reader_streams_across_parts_and_supports_reseek");
        temp.write_file("part-1", b"abc");
        temp.write_file("part-2", b"def");

        let mut reader = MultiVolumeReader::open(vec![temp.path("part-1"), temp.path("part-2")]).unwrap();
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"abcdef");

        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).unwrap();
        assert_eq!(suffix, b"cdef");
    }

    #[test]
    fn split_7z_refuses_existing_volume_without_replace() {
        let temp = TestDir::new("split_7z_refuses_existing_volume_without_replace");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        temp.write_file("payload.7z.001", b"old");
        let archive = temp.path("payload.7z");

        let error = create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { solid: false, level: Some(1), volume_size: Some(MIN_VOLUME_SIZE_BYTES), ..SevenZCreateOptions::default() },
        )
        .unwrap_err();

        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(fs::read(temp.path("payload.7z.001")).unwrap(), b"old");
    }

    #[test]
    fn split_7z_replace_removes_stale_old_volumes() {
        let temp = TestDir::new("split_7z_replace_removes_stale_old_volumes");
        temp.write_file("payload/blob.bin", &deterministic_bytes(2 * 1024 * 1024));
        let archive = temp.path("payload.7z");

        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions { solid: false, level: Some(1), volume_size: Some(MIN_VOLUME_SIZE_BYTES), ..SevenZCreateOptions::default() },
        )
        .unwrap();
        assert!(temp.path("payload.7z.002").exists());

        temp.write_file("payload/blob.bin", b"small");
        create_7z_from_path(
            temp.path("payload"),
            &archive,
            &SevenZCreateOptions {
                solid: false,
                level: Some(1),
                replace_existing: true,
                volume_size: Some(MIN_VOLUME_SIZE_BYTES),
                ..SevenZCreateOptions::default()
            },
        )
        .unwrap();

        assert!(temp.path("payload.7z.001").exists());
        assert!(!temp.path("payload.7z.002").exists());
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        crate::test_support::deterministic_bytes(len)
    }
}
