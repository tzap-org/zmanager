//! Regression coverage for the DPP dependency.
//!
//! These tests intentionally exercise the public DPP contracts through
//! synthetic on-disk structures. They stay small and platform-independent
//! while covering bugs that the checked-in happy-path DMG/XAR fixtures missed.

mod common;

use common::TestDir;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::{Cursor, Write};
use zmanager_core::archive_browser::BrowserEntryKind;
use zmanager_core::backend_test_support::xar_backend;
use zmanager_core::safety::ExtractionPolicy;

const APFS_BLOCK_SIZE: usize = 4096;
const APFS_OBJECT_HEADER_SIZE: usize = 32;
const APFS_BTREE_NODE_HEADER_SIZE: usize = 24;
const APFS_BTREE_INFO_SIZE: usize = 40;

fn apfs_catalog_key(oid: u64, record_type: u8, name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(10 + name.len() + 1);
    let oid_and_type = (oid & 0x0fff_ffff_ffff_ffff) | (u64::from(record_type) << 60);
    key.extend_from_slice(&oid_and_type.to_le_bytes());
    key.extend_from_slice(&u16::try_from(name.len() + 1).unwrap().to_le_bytes());
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    key
}

fn apfs_xattr_key(oid: u64, name: &str) -> Vec<u8> {
    apfs_catalog_key(oid, dpp::apfs::catalog::J_TYPE_XATTR, name)
}

fn embedded_xattr_value(data: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + data.len());
    value.extend_from_slice(&0_u16.to_le_bytes());
    value.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    value.extend_from_slice(data);
    value
}

fn apfs_catalog_leaf(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut block = vec![0_u8; APFS_BLOCK_SIZE];
    let table_start = APFS_OBJECT_HEADER_SIZE + APFS_BTREE_NODE_HEADER_SIZE;
    let table_len = records.len() * 8;
    let key_area_start = table_start + table_len;
    let value_area_end = APFS_BLOCK_SIZE - APFS_BTREE_INFO_SIZE;

    // Root + leaf. The remaining node-header fields can be zero for this
    // compact variable-key/value test tree.
    block[APFS_OBJECT_HEADER_SIZE..APFS_OBJECT_HEADER_SIZE + 2].copy_from_slice(&0x0003_u16.to_le_bytes());
    block[APFS_OBJECT_HEADER_SIZE + 4..APFS_OBJECT_HEADER_SIZE + 8].copy_from_slice(&u32::try_from(records.len()).unwrap().to_le_bytes());
    block[APFS_OBJECT_HEADER_SIZE + 10..APFS_OBJECT_HEADER_SIZE + 12].copy_from_slice(&u16::try_from(table_len).unwrap().to_le_bytes());

    let mut key_cursor = key_area_start;
    let mut value_cursor = value_area_end;
    for (index, (key, value)) in records.iter().enumerate() {
        value_cursor -= value.len();
        block[key_cursor..key_cursor + key.len()].copy_from_slice(key);
        block[value_cursor..value_cursor + value.len()].copy_from_slice(value);

        let toc = table_start + index * 8;
        block[toc..toc + 2].copy_from_slice(&u16::try_from(key_cursor - key_area_start).unwrap().to_le_bytes());
        block[toc + 2..toc + 4].copy_from_slice(&u16::try_from(key.len()).unwrap().to_le_bytes());
        block[toc + 4..toc + 6].copy_from_slice(&u16::try_from(value_area_end - value_cursor).unwrap().to_le_bytes());
        block[toc + 6..toc + 8].copy_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        key_cursor += key.len();
    }
    assert!(key_cursor <= value_cursor, "synthetic APFS B-tree fields overlap");

    // Variable-sized root B-tree info.
    let info = value_area_end;
    block[info + 4..info + 8].copy_from_slice(&u32::try_from(APFS_BLOCK_SIZE).unwrap().to_le_bytes());
    block[info + 16..info + 20].copy_from_slice(&u32::try_from(records.iter().map(|(key, _)| key.len()).max().unwrap_or(0)).unwrap().to_le_bytes());
    block[info + 20..info + 24].copy_from_slice(&u32::try_from(records.iter().map(|(_, value)| value.len()).max().unwrap_or(0)).unwrap().to_le_bytes());
    block[info + 24..info + 32].copy_from_slice(&u64::try_from(records.len()).unwrap().to_le_bytes());
    block[info + 32..info + 40].copy_from_slice(&1_u64.to_le_bytes());
    let checksum = apfs_fletcher64(&block[8..]);
    block[..8].copy_from_slice(&checksum.to_le_bytes());
    block
}

fn apfs_fletcher64(data: &[u8]) -> u64 {
    const MODULUS: u64 = 0xffff_ffff;
    let (sum1, sum2) = data.as_chunks::<4>().0.iter().fold((0_u64, 0_u64), |(sum1, sum2), word| {
        let word = u64::from(u32::from_le_bytes(*word));
        let sum1 = (sum1 + word) % MODULUS;
        let sum2 = (sum2 + sum1) % MODULUS;
        (sum1, sum2)
    });
    let check1 = MODULUS - ((sum1 + sum2) % MODULUS);
    let check2 = MODULUS - ((sum1 + check1) % MODULUS);
    (check2 << 32) | check1
}

fn lookup_apfs_xattr(records: &[(Vec<u8>, Vec<u8>)], oid: u64, name: &str) -> dpp::apfs::Result<Option<Vec<u8>>> {
    let mut image = Cursor::new(apfs_catalog_leaf(records));
    dpp::apfs::catalog::lookup_xattr(&mut image, 0, 0, u32::try_from(APFS_BLOCK_SIZE).unwrap(), oid, name)
}

#[test]
fn pr4_apfs_xattr_lookup_uses_numeric_catalog_order() {
    let symlink_name = dpp::apfs::catalog::SYMLINK_XATTR_NAME;
    let cases = [
        (
            0x100,
            vec![
                (apfs_xattr_key(0x02, symlink_name), embedded_xattr_value(b"wrong-low-oid")),
                (apfs_xattr_key(0x100, symlink_name), embedded_xattr_value(b"numeric-oid")),
            ],
            b"numeric-oid".as_slice(),
        ),
        (
            25,
            vec![
                (apfs_catalog_key(25, dpp::apfs::catalog::J_TYPE_INODE, ""), embedded_xattr_value(b"wrong-record-type")),
                (apfs_xattr_key(25, symlink_name), embedded_xattr_value(b"record-type")),
            ],
            b"record-type".as_slice(),
        ),
        (
            25,
            vec![
                (apfs_xattr_key(25, "com.apple.diskimages.recentcksum"), embedded_xattr_value(b"wrong-earlier-name")),
                (apfs_xattr_key(25, symlink_name), embedded_xattr_value(b"name-order")),
                (apfs_xattr_key(25, "com.apple.quarantine"), embedded_xattr_value(b"wrong-later-name")),
            ],
            b"name-order".as_slice(),
        ),
    ];

    for (oid, records, expected) in cases {
        assert_eq!(lookup_apfs_xattr(&records, oid, symlink_name).unwrap().as_deref(), Some(expected));
    }
}

#[test]
fn pr4_apfs_malformed_catalog_key_fails_closed() {
    let name = dpp::apfs::catalog::SYMLINK_XATTR_NAME;
    let error =
        lookup_apfs_xattr(&[(b"short".to_vec(), embedded_xattr_value(b"malformed")), (apfs_xattr_key(25, name), embedded_xattr_value(b"target"))], 25, name)
            .unwrap_err();

    assert!(matches!(error, dpp::apfs::ApfsError::InvalidBTree(_)), "{error:?}");
}

#[test]
fn pr4_apfs_stream_backed_xattr_is_reported_as_unsupported() {
    let name = dpp::apfs::catalog::SYMLINK_XATTR_NAME;
    let mut stream_value = vec![1_u8, 0, 0, 0];
    stream_value.extend_from_slice(&42_u64.to_le_bytes());
    stream_value.extend_from_slice(&4_u64.to_le_bytes());
    stream_value.extend_from_slice(&[0_u8; 32]);
    let error = lookup_apfs_xattr(&[(apfs_xattr_key(42, name), stream_value)], 42, name).unwrap_err();

    assert!(matches!(error, dpp::apfs::ApfsError::Unsupported(_)));
}

#[test]
fn pr4_apfs_embedded_xattr_length_is_validated_and_bounded() {
    let name = dpp::apfs::catalog::SYMLINK_XATTR_NAME;
    let short_header = lookup_apfs_xattr(&[(apfs_xattr_key(1, name), b"abc".to_vec())], 1, name).unwrap_err();
    assert!(matches!(short_header, dpp::apfs::ApfsError::CorruptedData(_)));

    let declared_too_long = vec![0, 0, 0xff, 0, b'a', b'b'];
    assert_eq!(lookup_apfs_xattr(&[(apfs_xattr_key(2, name), declared_too_long)], 2, name).unwrap().as_deref(), Some(b"ab".as_slice()));
}

fn build_xar(toc_xml: &[u8], heap: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(toc_xml).unwrap();
    let compressed_toc = encoder.finish().unwrap();

    let mut archive = Vec::new();
    archive.extend_from_slice(&0x7861_7221_u32.to_be_bytes());
    archive.extend_from_slice(&28_u16.to_be_bytes());
    archive.extend_from_slice(&1_u16.to_be_bytes());
    archive.extend_from_slice(&u64::try_from(compressed_toc.len()).unwrap().to_be_bytes());
    archive.extend_from_slice(&u64::try_from(toc_xml.len()).unwrap().to_be_bytes());
    archive.extend_from_slice(&0_u32.to_be_bytes());
    archive.extend_from_slice(&compressed_toc);
    archive.extend_from_slice(heap);
    archive
}

fn write_xar(temp: &TestDir, name: &str, toc_xml: &[u8], heap: &[u8]) -> std::path::PathBuf {
    let archive = temp.path(name);
    std::fs::write(&archive, build_xar(toc_xml, heap)).unwrap();
    archive
}

#[test]
fn pr5_xar_base64_name_decodes_through_zmanager() {
    // Standard base64 encoding of the macOS XAR filename "こんにちは.txt".
    let xml = br#"<xar><toc><file id="1">
  <type>file</type><name enctype="base64">44GT44KT44Gr44Gh44GvLnR4dA==</name>
  <data><offset>0</offset><length>7</length><size>7</size><encoding style="application/octet-stream"/></data>
</file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-base64-name");
    let archive = write_xar(&temp, "base64-name.xar", xml, b"payload");

    let entries = xar_backend::list(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "こんにちは.txt");
    assert_eq!(entries[0].kind, BrowserEntryKind::File);

    let mut copied = Vec::new();
    assert_eq!(xar_backend::copy(&archive, 0, &mut copied).unwrap(), 7);
    assert_eq!(copied, b"payload");

    let destination = temp.path("out");
    let report = xar_backend::extract(&archive, &destination, ExtractionPolicy::default(), None, None).unwrap();
    assert_eq!(report.entries, 1);
    assert_eq!(std::fs::read(destination.join("こんにちは.txt")).unwrap(), b"payload");
}

#[test]
fn pr5_xar_nested_metadata_cannot_clobber_path_or_payload() {
    let xml = br#"<xar><toc><file id="1">
  <type>file</type><name>real-name.txt</name>
  <data>
    <offset>0</offset>
    <extension><data><offset>999</offset><length>3</length><size>3</size></data></extension>
    <length>7</length><size>7</size><encoding style="application&#x2f;octet-stream"/>
  </data>
  <ea id="0"><name>com.apple.provenance</name><data>
    <offset>999</offset><length>3</length><size>3</size><encoding style="application/x-gzip"/>
  </data></ea>
</file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-metadata");
    let archive = write_xar(&temp, "metadata.xar", xml, b"payload");

    let entries = xar_backend::list(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "real-name.txt");
    assert_eq!(entries[0].kind, BrowserEntryKind::File);
    assert_eq!(entries[0].size, 7);

    let mut copied = Vec::new();
    assert_eq!(xar_backend::copy(&archive, 0, &mut copied).unwrap(), 7);
    assert_eq!(copied, b"payload");
}

#[test]
fn pr5_xar_ea_names_before_and_after_cannot_replace_file_names() {
    let xml = br#"<xar><toc>
<file id="1"><ea><name>before-ea</name></ea><type>directory</type><name>before.txt</name></file>
<file id="2"><type>directory</type><name>after.txt</name><ea><name>after-ea</name></ea></file>
</toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-ea-names");
    let archive = write_xar(&temp, "ea-names.xar", xml, &[]);

    let entries = xar_backend::list(&archive).unwrap();
    assert_eq!(entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), ["before.txt", "after.txt"]);
}

#[test]
fn pr5_xar_symlink_target_preserves_xml_text_and_scope() {
    let xml = br#"<xar><toc><file id="1">
  <type>directory</type><name>dir</name>
  <file id="2"><link type="file"><![CDATA[ ../A&B ]]></link><type>symlink</type><name>link</name></file>
  <ea id="0"><name>must-not-become-the-directory-name</name></ea>
</file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-link");
    let archive = write_xar(&temp, "link.xar", xml, &[]);

    let entries = xar_backend::list(&archive).unwrap();
    let directory = entries.iter().find(|entry| entry.kind == BrowserEntryKind::Directory).unwrap();
    let link = entries.iter().find(|entry| entry.kind == BrowserEntryKind::Symlink).unwrap();
    assert_eq!(directory.path, "dir");
    assert_eq!(link.path, "dir/link");
    assert_eq!(link.link_target.as_deref(), Some(" ../A&B "));
}

#[test]
fn pr5_xar_link_text_survives_text_comments_cdata_and_entities() {
    let cases: &[(&[u8], &str)] = &[
        (br#"<xar><toc><file id="1"><link type="file"> target </link><type>symlink</type><name>link</name></file></toc></xar>"#, " target "),
        (br#"<xar><toc><file id="1"><link type="file">foo<!-- split -->bar</link><type>symlink</type><name>link</name></file></toc></xar>"#, "foobar"),
        (br#"<xar><toc><file id="1"><link type="file"><![CDATA[../A&B]]></link><type>symlink</type><name>link</name></file></toc></xar>"#, "../A&B"),
        (br#"<xar><toc><file id="1"><link type="file">A&amp;B</link><type>symlink</type><name>link</name></file></toc></xar>"#, "A&B"),
    ];
    let temp = TestDir::new("dpp-pr5-xar-link-events");

    for (index, (xml, expected)) in cases.iter().enumerate() {
        let archive = write_xar(&temp, &format!("link-{index}.xar"), xml, &[]);
        let entries = xar_backend::list(&archive).unwrap();
        assert_eq!(entries[0].link_target.as_deref(), Some(*expected), "case {index}");
    }
}

#[test]
fn pr5_xar_link_metadata_does_not_leak_to_regular_files() {
    let xml = br#"<xar><toc><file id="1"><name>plain.txt</name><type>file</type><link type="file">must-not-leak</link></file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-regular-link");
    let archive = write_xar(&temp, "regular-link.xar", xml, &[]);

    let entries = xar_backend::list(&archive).unwrap();
    assert_eq!(entries[0].kind, BrowserEntryKind::File);
    assert_eq!(entries[0].link_target, None);
}

#[test]
fn pr5_xar_nested_ea_cannot_clobber_checksums_or_encoding() {
    let xml = br#"<xar><toc><file id="1"><type>file</type><name>payload</name>
<data><offset>0</offset><length>4</length><size>4</size><encoding style="application/octet-stream"/>
<extracted-checksum>real-extracted</extracted-checksum><archived-checksum>real-archived</archived-checksum></data>
<ea><data><offset>999</offset><length>3</length><size>3</size><encoding style="application/x-gzip"/>
<extracted-checksum>fake-extracted</extracted-checksum><archived-checksum>fake-archived</archived-checksum></data></ea>
</file></toc></xar>"#;
    let archive = dpp::xara::XarArchive::open(Cursor::new(build_xar(xml, b"data"))).unwrap();
    let data = archive.files()[0].data.as_ref().unwrap();

    assert_eq!((data.offset, data.length, data.size), (0, 4, 4));
    assert_eq!(data.encoding, "application/octet-stream");
    assert_eq!(data.extracted_checksum.as_deref(), Some("real-extracted"));
    assert_eq!(data.archived_checksum.as_deref(), Some("real-archived"));
}

#[test]
fn pr5_xar_rejects_ambiguous_direct_data_metadata() {
    let cases: &[&[u8]] = &[
        br#"<xar><toc><file id="1"><type>file</type><name>missing-size</name><data><offset>0</offset><length>1</length></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>empty-data</name><data/></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>duplicate-data</name><data><offset>0</offset><length>0</length><size>0</size></data><data><offset>0</offset><length>0</length><size>0</size></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>symlink</type><name>nested-link</name><link>before<extension/>after</link></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>symlink</type><name>invalid-entity</name><link>&unknown;</link></file></toc></xar>"#,
    ];
    let temp = TestDir::new("dpp-pr5-xar-invalid");

    for (index, xml) in cases.iter().enumerate() {
        let archive = write_xar(&temp, &format!("invalid-{index}.xar"), xml, &[]);
        assert!(matches!(xar_backend::list(&archive), Err(xar_backend::XarError::Parser { .. })), "case {index} was accepted");
    }
}

#[test]
fn pr5_xar_parent_path_is_independent_of_metadata_order() {
    let xml = br#"<xar><toc><file id="1">
  <type>directory</type>
  <file id="2"><type>directory</type>
    <file id="3"><type>file</type><name>leaf.txt</name></file>
    <name>child</name>
  </file>
  <name>parent</name>
</file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-late-parent-name");
    let archive = write_xar(&temp, "late-parent-name.xar", xml, &[]);

    let entries = xar_backend::list(&archive).unwrap();
    assert_eq!(entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), ["parent/child/leaf.txt", "parent/child", "parent"]);
}

#[test]
fn pr5_xar_rejects_duplicate_or_invalid_scalar_metadata() {
    let cases: &[&[u8]] = &[
        br#"<xar><toc><file id="1"><type>file</type><name>first</name><name>second</name></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><type>symlink</type><name>entry</name><link>target</link></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>entry</name><data><offset>0</offset><offset>1</offset><length>0</length><size>0</size></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>entry</name><data><offset>0</offset><length>0</length><size>0</size><encoding style="a"/><encoding style="b"/></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>entry</name><data><offset>0</offset><length>0</length><size>0</size><encoding/></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1" id="2"><type>file</type><name>entry</name></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>entry</name><data><offset>0</offset><length>0</length><size>0</size><encoding style="a" style="b"/></data></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name/></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><name>entry</name></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>symlink</type><name>link</name></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>symlink</type><name>link</name><link/></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>mystery</type><name>entry</name></file></toc></xar>"#,
        br#"<xar><toc><file id="18446744073709551616"><type>file</type><name>entry</name></file></toc></xar>"#,
        br#"<xar><toc><file id="1"><type>file</type><name>entry</name><data><offset>-1</offset><length>0</length><size>0</size></data></file></toc></xar>"#,
    ];
    let temp = TestDir::new("dpp-pr5-xar-invalid-scalars");

    for (index, xml) in cases.iter().enumerate() {
        let archive = write_xar(&temp, &format!("invalid-scalar-{index}.xar"), xml, &[]);
        assert!(matches!(xar_backend::list(&archive), Err(xar_backend::XarError::Parser { .. })), "case {index} was accepted");
    }
}

#[test]
fn pr5_xar_requires_one_well_formed_xar_toc_document() {
    let cases: &[&[u8]] = &[
        br"<toc><file><type>file</type><name>entry</name></file></toc>",
        br"<xar></xar>",
        br"<xar><toc/><toc/></xar>",
        br"<xar><extension><toc/></extension></xar>",
        br"<xar><toc/></xar><second/>",
    ];
    let temp = TestDir::new("dpp-pr5-xar-document-structure");

    for (index, xml) in cases.iter().enumerate() {
        let archive = write_xar(&temp, &format!("invalid-document-{index}.xar"), xml, &[]);
        assert!(matches!(xar_backend::list(&archive), Err(xar_backend::XarError::Parser { .. })), "case {index} was accepted");
    }
}

#[test]
fn pr5_xar_validates_declared_toc_extents() {
    let xml = br"<xar><toc/></xar>";
    let temp = TestDir::new("dpp-pr5-xar-toc-extents");

    for (name, header_range) in [("compressed", 8..16), ("uncompressed", 16..24)] {
        let mut bytes = build_xar(xml, &[]);
        let declared = u64::from_be_bytes(bytes[header_range.clone()].try_into().unwrap()) + 1;
        bytes[header_range].copy_from_slice(&declared.to_be_bytes());
        let archive = temp.path(format!("invalid-{name}-extent.xar"));
        std::fs::write(&archive, bytes).unwrap();

        assert!(matches!(xar_backend::list(&archive), Err(xar_backend::XarError::Parser { .. })), "{name} extent mismatch was accepted");
    }
}

#[test]
fn pr5_xar_file_state_is_isolated_across_deep_siblings() {
    let xml = br#"<xar><toc><file id="1"><type>directory</type><name>root</name>
  <file id="2"><type>symlink</type><name>first-link</name><link>first-target</link></file>
  <file id="3"><type>file</type><name>payload.bin</name><data>
    <offset>0</offset><length>4</length><size>4</size><encoding style="application/octet-stream"/>
  </data></file>
  <file id="4"><type>directory</type><name>nested</name>
    <file id="5"><link>second-target</link><name>second-link</name><type>symlink</type></file>
  </file>
</file></toc></xar>"#;
    let temp = TestDir::new("dpp-pr5-xar-deep-siblings");
    let archive = write_xar(&temp, "deep-siblings.xar", xml, b"data");

    let entries = xar_backend::list(&archive).unwrap();
    let first = entries.iter().find(|entry| entry.path.ends_with("first-link")).unwrap();
    let payload = entries.iter().find(|entry| entry.path.ends_with("payload.bin")).unwrap();
    let second = entries.iter().find(|entry| entry.path.ends_with("second-link")).unwrap();
    assert_eq!(first.link_target.as_deref(), Some("first-target"));
    assert_eq!(payload.link_target, None);
    assert_eq!(payload.size, 4);
    assert_eq!(second.link_target.as_deref(), Some("second-target"));

    let mut copied = Vec::new();
    assert_eq!(xar_backend::copy(&archive, payload.index, &mut copied).unwrap(), 4);
    assert_eq!(copied, b"data");
}

#[test]
fn pr5_xar_heap_extents_encodings_and_decoded_sizes_fail_closed() {
    let temp = TestDir::new("dpp-pr5-xar-heap-bounds");
    let mut zlib_encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib_encoder.write_all(b"four").unwrap();
    let zlib_payload = zlib_encoder.finish().unwrap();
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "offset-overflow",
            br"<xar><toc><file><type>file</type><name>payload</name><data><offset>18446744073709551615</offset><length>1</length><size>1</size></data></file></toc></xar>".to_vec(),
            vec![0],
        ),
        (
            "offset-beyond-heap",
            br"<xar><toc><file><type>file</type><name>payload</name><data><offset>4</offset><length>2</length><size>2</size></data></file></toc></xar>".to_vec(),
            b"data".to_vec(),
        ),
        (
            "stored-size-mismatch",
            br"<xar><toc><file><type>file</type><name>payload</name><data><offset>0</offset><length>2</length><size>3</size></data></file></toc></xar>".to_vec(),
            b"ab".to_vec(),
        ),
        (
            "unsupported-encoding",
            br#"<xar><toc><file><type>file</type><name>payload</name><data><offset>0</offset><length>1</length><size>1</size><encoding style="application/x-unknown"/></data></file></toc></xar>"#.to_vec(),
            vec![0],
        ),
        (
            "decoded-size-mismatch",
            format!(
                "<xar><toc><file><type>file</type><name>payload</name><data><offset>0</offset><length>{}</length><size>2</size><encoding style=\"application/zlib\"/></data></file></toc></xar>",
                zlib_payload.len()
            )
            .into_bytes(),
            zlib_payload,
        ),
    ];

    for (name, xml, heap) in cases {
        let archive = write_xar(&temp, &format!("{name}.xar"), &xml, &heap);
        assert_eq!(xar_backend::list(&archive).unwrap().len(), 1, "{name}");
        assert!(matches!(xar_backend::copy(&archive, 0, &mut Vec::new()), Err(xar_backend::XarError::Parser { .. })), "{name} copied successfully");

        let destination = temp.path(format!("out-{name}"));
        assert!(xar_backend::extract(&archive, &destination, ExtractionPolicy::default(), None, None).is_err(), "{name} extracted successfully");
        assert!(!destination.join("payload").exists(), "{name} committed a partial output file");
    }
}
