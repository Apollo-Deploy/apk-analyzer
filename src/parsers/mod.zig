//! Parsers Module
//!
//! Format-specific parsers for Android package formats.
//! Each parser is self-contained and returns core domain types.
//!
//! ## Parsers
//!
//! - `zip`: ZIP archive parsing with ZIP64 support
//! - `axml`: Android binary XML (AndroidManifest.xml)
//! - `dex`: DEX file analysis (method counts, multidex)
//! - `certificate`: X.509 certificate extraction
//! - `arsc`: resources.arsc parsing
//! - `protobuf`: Protocol buffer parsing (for AAB)
//! - `pb_manifest`: Protobuf manifest parsing (AAB)

const std = @import("std");

// Import all parsers
pub const zip = @import("zip.zig");
pub const axml = @import("axml.zig");
pub const dex = @import("dex.zig");
pub const certificate = @import("certificate.zig");
pub const arsc = @import("arsc.zig");
pub const protobuf = @import("protobuf.zig");
pub const pb_manifest = @import("pb_manifest.zig");

// Re-export main parser types for convenience
pub const ZipParser = zip.ZipParser;
pub const AxmlParser = axml.AxmlParser;
pub const DexAnalyzer = dex.DexAnalyzer;
pub const CertificateParser = certificate.CertificateParser;
pub const ArscParser = arsc.ArscParser;
pub const PbManifestParser = pb_manifest.PbManifestParser;

// ============================================================================
// Parser Utilities
// ============================================================================

/// Check if data looks like a valid ZIP archive
pub fn isZipArchive(data: []const u8) bool {
    if (data.len < 4) return false;
    return data[0] == 'P' and data[1] == 'K' and data[2] == 0x03 and data[3] == 0x04;
}

/// Check if data looks like Android binary XML
pub fn isAndroidBinaryXml(data: []const u8) bool {
    if (data.len < 4) return false;
    // AXML magic: 0x00080003 (little-endian)
    return data[0] == 0x03 and data[1] == 0x00 and data[2] == 0x08 and data[3] == 0x00;
}

/// Check if data looks like a DEX file
pub fn isDexFile(data: []const u8) bool {
    if (data.len < 8) return false;
    // DEX magic: "dex\n" followed by version
    return data[0] == 'd' and data[1] == 'e' and data[2] == 'x' and data[3] == '\n';
}

/// Check if data looks like resources.arsc
pub fn isResourcesArsc(data: []const u8) bool {
    if (data.len < 4) return false;
    // ARSC magic: 0x0002 (RES_TABLE_TYPE)
    return data[0] == 0x02 and data[1] == 0x00;
}

// ============================================================================
// Tests
// ============================================================================

test "isZipArchive" {
    const valid = [_]u8{ 'P', 'K', 0x03, 0x04, 0x00 };
    const invalid = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expect(isZipArchive(&valid));
    try std.testing.expect(!isZipArchive(&invalid));
    try std.testing.expect(!isZipArchive(&[_]u8{}));
}

test "isDexFile" {
    const valid = [_]u8{ 'd', 'e', 'x', '\n', '0', '3', '5', 0x00 };
    const invalid = [_]u8{ 0x00, 0x00, 0x00, 0x00 };

    try std.testing.expect(isDexFile(&valid));
    try std.testing.expect(!isDexFile(&invalid));
}

test {
    std.testing.refAllDecls(@This());
}
