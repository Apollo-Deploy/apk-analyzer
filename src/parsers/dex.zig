//! DEX File Analyzer
//!
//! Parses and analyzes Dalvik Executable (DEX) files to extract
//! method counts, class counts, field counts, and detect multidex issues.
//!
//! ## DEX Format Overview
//!
//! DEX files contain compiled Java/Kotlin bytecode for the Android runtime.
//! The format includes:
//! - Header with magic bytes and file metadata
//! - String IDs, Type IDs, Proto IDs, Field IDs, Method IDs
//! - Class definitions
//!
//! ## Supported Versions
//!
//! - DEX 035 (Android 1.0+)
//! - DEX 039 (Android 9.0+)
//!
//! ## Usage
//!
//! ```zig
//! const dex = @import("dex.zig");
//!
//! // Parse a single DEX file
//! const header = try dex.DexAnalyzer.parseHeader(dex_data);
//! const info = try dex.DexAnalyzer.analyze(allocator, dex_data);
//!
//! // Analyze multiple DEX files (multidex)
//! const multi_info = try dex.DexAnalyzer.analyzeMultiple(allocator, &.{
//!     classes_dex,
//!     classes2_dex,
//!     classes3_dex,
//! });
//! ```

const std = @import("std");

/// DEX file analyzer for extracting method counts, class counts, and field counts
pub const DexAnalyzer = struct {
    allocator: std.mem.Allocator,

    pub const DexError = error{
        InvalidMagic,
        InvalidChecksum,
        TruncatedData,
        UnsupportedVersion,
        OutOfMemory,
        InvalidHeader,
    };

    /// DEX file header structure (112 bytes)
    /// Matches the official DEX format specification
    pub const DexHeader = struct {
        /// Magic bytes: "dex\n" followed by version (e.g., "035\0" or "039\0")
        magic: [8]u8,
        /// Adler32 checksum of the file (excluding magic and checksum)
        checksum: u32,
        /// SHA-1 signature of the file (excluding magic, checksum, and signature)
        signature: [20]u8,
        /// Total file size in bytes
        file_size: u32,
        /// Header size (always 0x70 = 112 bytes)
        header_size: u32,
        /// Endian tag (0x12345678 for little-endian)
        endian_tag: u32,
        /// Size of link section
        link_size: u32,
        /// Offset to link section
        link_off: u32,
        /// Offset to map list
        map_off: u32,
        /// Number of strings in the string IDs list
        string_ids_size: u32,
        /// Offset to string IDs list
        string_ids_off: u32,
        /// Number of types in the type IDs list
        type_ids_size: u32,
        /// Offset to type IDs list
        type_ids_off: u32,
        /// Number of prototypes in the proto IDs list
        proto_ids_size: u32,
        /// Offset to proto IDs list
        proto_ids_off: u32,
        /// Number of fields in the field IDs list
        field_ids_size: u32,
        /// Offset to field IDs list
        field_ids_off: u32,
        /// Number of methods in the method IDs list
        method_ids_size: u32,
        /// Offset to method IDs list
        method_ids_off: u32,
        /// Number of class definitions
        class_defs_size: u32,
        /// Offset to class definitions
        class_defs_off: u32,
        /// Size of data section
        data_size: u32,
        /// Offset to data section
        data_off: u32,
    };

    /// Analysis result for a single DEX file
    pub const DexFileInfo = struct {
        /// Total number of method references
        method_count: u32,
        /// Total number of class definitions
        class_count: u32,
        /// Total number of field references
        field_count: u32,
        /// Total number of strings
        string_count: u32,
        /// DEX version string (e.g., "035" or "039")
        version: [3]u8,
        /// Whether method count exceeds 65536 limit
        exceeds_limit: bool,
    };

    /// Aggregate DEX analysis result for multiple DEX files
    pub const DexInfo = struct {
        /// Information for each DEX file
        files: []DexFileInfo,
        /// Total methods across all DEX files
        total_methods: u64,
        /// Total classes across all DEX files
        total_classes: u64,
        /// Total fields across all DEX files
        total_fields: u64,
        /// Whether this is a multidex APK (more than one DEX file)
        is_multidex: bool,
        /// Allocator used for cleanup
        allocator: std.mem.Allocator,

        pub fn deinit(self: *DexInfo) void {
            self.allocator.free(self.files);
        }
    };

    /// DEX magic bytes prefix: "dex\n"
    const DEX_MAGIC_PREFIX = [_]u8{ 'd', 'e', 'x', '\n' };

    /// Supported DEX versions
    const DEX_VERSION_035 = [_]u8{ '0', '3', '5', 0 };
    const DEX_VERSION_039 = [_]u8{ '0', '3', '9', 0 };

    /// Expected endian tag for little-endian DEX files
    const ENDIAN_CONSTANT: u32 = 0x12345678;

    /// Method count limit per DEX file (64K limit)
    const METHOD_LIMIT: u32 = 65536;

    /// Minimum DEX header size
    const HEADER_SIZE: usize = 112;

    /// Initialize a new DEX analyzer
    pub fn init(allocator: std.mem.Allocator) DexAnalyzer {
        return .{ .allocator = allocator };
    }

    /// Parse DEX header only (fast operation)
    /// Returns the header structure without full analysis
    pub fn parseHeader(data: []const u8) DexError!DexHeader {
        if (data.len < HEADER_SIZE) {
            return DexError.TruncatedData;
        }

        // Validate magic bytes
        const magic = data[0..8].*;
        if (!std.mem.eql(u8, magic[0..4], &DEX_MAGIC_PREFIX)) {
            return DexError.InvalidMagic;
        }

        // Validate version
        const version = magic[4..8].*;
        if (!std.mem.eql(u8, &version, &DEX_VERSION_035) and
            !std.mem.eql(u8, &version, &DEX_VERSION_039))
        {
            return DexError.UnsupportedVersion;
        }

        // Parse header fields
        const header = DexHeader{
            .magic = magic,
            .checksum = readU32(data, 8),
            .signature = data[12..32].*,
            .file_size = readU32(data, 32),
            .header_size = readU32(data, 36),
            .endian_tag = readU32(data, 40),
            .link_size = readU32(data, 44),
            .link_off = readU32(data, 48),
            .map_off = readU32(data, 52),
            .string_ids_size = readU32(data, 56),
            .string_ids_off = readU32(data, 60),
            .type_ids_size = readU32(data, 64),
            .type_ids_off = readU32(data, 68),
            .proto_ids_size = readU32(data, 72),
            .proto_ids_off = readU32(data, 76),
            .field_ids_size = readU32(data, 80),
            .field_ids_off = readU32(data, 84),
            .method_ids_size = readU32(data, 88),
            .method_ids_off = readU32(data, 92),
            .class_defs_size = readU32(data, 96),
            .class_defs_off = readU32(data, 100),
            .data_size = readU32(data, 104),
            .data_off = readU32(data, 108),
        };

        // Validate endian tag
        if (header.endian_tag != ENDIAN_CONSTANT) {
            return DexError.InvalidHeader;
        }

        // Validate header size
        if (header.header_size != HEADER_SIZE) {
            return DexError.InvalidHeader;
        }

        return header;
    }

    /// Analyze a single DEX file
    /// Returns method count, class count, field count, and multidex detection
    pub fn analyze(allocator: std.mem.Allocator, data: []const u8) DexError!DexFileInfo {
        _ = allocator; // Reserved for future use

        const header = try parseHeader(data);

        return DexFileInfo{
            .method_count = header.method_ids_size,
            .class_count = header.class_defs_size,
            .field_count = header.field_ids_size,
            .string_count = header.string_ids_size,
            .version = header.magic[4..7].*,
            .exceeds_limit = header.method_ids_size >= METHOD_LIMIT,
        };
    }

    /// Analyze multiple DEX files (multidex support)
    /// Aggregates counts across all DEX files
    pub fn analyzeMultiple(allocator: std.mem.Allocator, dex_files: []const []const u8) DexError!DexInfo {
        if (dex_files.len == 0) {
            return DexInfo{
                .files = &[_]DexFileInfo{},
                .total_methods = 0,
                .total_classes = 0,
                .total_fields = 0,
                .is_multidex = false,
                .allocator = allocator,
            };
        }

        var files = allocator.alloc(DexFileInfo, dex_files.len) catch {
            return DexError.OutOfMemory;
        };
        errdefer allocator.free(files);

        var total_methods: u64 = 0;
        var total_classes: u64 = 0;
        var total_fields: u64 = 0;

        for (dex_files, 0..) |dex_data, i| {
            const info = try analyze(allocator, dex_data);
            files[i] = info;
            total_methods += info.method_count;
            total_classes += info.class_count;
            total_fields += info.field_count;
        }

        return DexInfo{
            .files = files,
            .total_methods = total_methods,
            .total_classes = total_classes,
            .total_fields = total_fields,
            .is_multidex = dex_files.len > 1,
            .allocator = allocator,
        };
    }

    /// Check if data appears to be a valid DEX file
    pub fn isDexFile(data: []const u8) bool {
        if (data.len < 8) return false;
        if (!std.mem.eql(u8, data[0..4], &DEX_MAGIC_PREFIX)) return false;

        const version = data[4..8];
        return std.mem.eql(u8, version, &DEX_VERSION_035) or
            std.mem.eql(u8, version, &DEX_VERSION_039);
    }

    /// Get the DEX version string from data
    pub fn getVersion(data: []const u8) ?[3]u8 {
        if (data.len < 8) return null;
        if (!std.mem.eql(u8, data[0..4], &DEX_MAGIC_PREFIX)) return null;
        return data[4..7].*;
    }
};

/// Read a little-endian u32 from data at the given offset
fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "DexAnalyzer.parseHeader returns InvalidMagic for non-DEX data" {
    const invalid_data = "not a dex file at all!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    const result = DexAnalyzer.parseHeader(invalid_data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidMagic, result);
}

test "DexAnalyzer.parseHeader returns TruncatedData for short data" {
    const short_data = "dex\n035";
    const result = DexAnalyzer.parseHeader(short_data);
    try std.testing.expectError(DexAnalyzer.DexError.TruncatedData, result);
}

test "DexAnalyzer.parseHeader returns UnsupportedVersion for unknown version" {
    // Create a buffer with valid magic but unsupported version
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '9';
    data[6] = '9'; // Invalid version 099
    data[7] = 0;

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.UnsupportedVersion, result);
}

test "DexAnalyzer.parseHeader parses valid DEX 035 header" {
    // Create a minimal valid DEX 035 header
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    // Magic: "dex\n035\0"
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    // Header size at offset 36 (must be 112 = 0x70)
    std.mem.writeInt(u32, data[36..40], 112, .little);

    // Endian tag at offset 40 (must be 0x12345678)
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    // Set some counts for testing
    std.mem.writeInt(u32, data[56..60], 100, .little); // string_ids_size
    std.mem.writeInt(u32, data[80..84], 50, .little); // field_ids_size
    std.mem.writeInt(u32, data[88..92], 200, .little); // method_ids_size
    std.mem.writeInt(u32, data[96..100], 30, .little); // class_defs_size

    const header = try DexAnalyzer.parseHeader(&data);

    try std.testing.expectEqualSlices(u8, "dex\n035\x00", &header.magic);
    try std.testing.expectEqual(@as(u32, 112), header.header_size);
    try std.testing.expectEqual(@as(u32, 0x12345678), header.endian_tag);
    try std.testing.expectEqual(@as(u32, 100), header.string_ids_size);
    try std.testing.expectEqual(@as(u32, 50), header.field_ids_size);
    try std.testing.expectEqual(@as(u32, 200), header.method_ids_size);
    try std.testing.expectEqual(@as(u32, 30), header.class_defs_size);
}

test "DexAnalyzer.parseHeader parses valid DEX 039 header" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    // Magic: "dex\n039\0"
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '9';
    data[7] = 0;

    // Header size
    std.mem.writeInt(u32, data[36..40], 112, .little);

    // Endian tag
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    const header = try DexAnalyzer.parseHeader(&data);
    try std.testing.expectEqualSlices(u8, "dex\n039\x00", &header.magic);
}

test "DexAnalyzer.analyze returns correct counts" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    // Valid DEX 035 header
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    std.mem.writeInt(u32, data[36..40], 112, .little); // header_size
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little); // endian_tag
    std.mem.writeInt(u32, data[56..60], 1000, .little); // string_ids_size
    std.mem.writeInt(u32, data[80..84], 500, .little); // field_ids_size
    std.mem.writeInt(u32, data[88..92], 2000, .little); // method_ids_size
    std.mem.writeInt(u32, data[96..100], 300, .little); // class_defs_size

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);

    try std.testing.expectEqual(@as(u32, 2000), info.method_count);
    try std.testing.expectEqual(@as(u32, 300), info.class_count);
    try std.testing.expectEqual(@as(u32, 500), info.field_count);
    try std.testing.expectEqual(@as(u32, 1000), info.string_count);
    try std.testing.expectEqualSlices(u8, "035", &info.version);
    try std.testing.expect(!info.exceeds_limit);
}

test "DexAnalyzer.analyze detects method limit exceeded" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    // Valid DEX header
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    std.mem.writeInt(u32, data[36..40], 112, .little);
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    // Set method count to exactly 65536 (the limit)
    std.mem.writeInt(u32, data[88..92], 65536, .little);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(info.exceeds_limit);
}

test "DexAnalyzer.analyze detects method count below limit" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    std.mem.writeInt(u32, data[36..40], 112, .little);
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    // Set method count to 65535 (just below limit)
    std.mem.writeInt(u32, data[88..92], 65535, .little);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(!info.exceeds_limit);
}

test "DexAnalyzer.analyzeMultiple handles empty input" {
    const empty: []const []const u8 = &.{};
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, empty);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 0), info.files.len);
    try std.testing.expectEqual(@as(u64, 0), info.total_methods);
    try std.testing.expectEqual(@as(u64, 0), info.total_classes);
    try std.testing.expectEqual(@as(u64, 0), info.total_fields);
    try std.testing.expect(!info.is_multidex);
}

test "DexAnalyzer.analyzeMultiple handles single DEX file" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    std.mem.writeInt(u32, data[36..40], 112, .little);
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);
    std.mem.writeInt(u32, data[88..92], 1000, .little); // methods
    std.mem.writeInt(u32, data[96..100], 100, .little); // classes
    std.mem.writeInt(u32, data[80..84], 200, .little); // fields

    const dex_files: []const []const u8 = &.{&data};
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 1), info.files.len);
    try std.testing.expectEqual(@as(u64, 1000), info.total_methods);
    try std.testing.expectEqual(@as(u64, 100), info.total_classes);
    try std.testing.expectEqual(@as(u64, 200), info.total_fields);
    try std.testing.expect(!info.is_multidex);
}

test "DexAnalyzer.analyzeMultiple handles multidex" {
    // Create two DEX files
    var data1: [112]u8 = undefined;
    var data2: [112]u8 = undefined;
    @memset(&data1, 0);
    @memset(&data2, 0);

    // First DEX file
    data1[0] = 'd';
    data1[1] = 'e';
    data1[2] = 'x';
    data1[3] = '\n';
    data1[4] = '0';
    data1[5] = '3';
    data1[6] = '5';
    data1[7] = 0;
    std.mem.writeInt(u32, data1[36..40], 112, .little);
    std.mem.writeInt(u32, data1[40..44], 0x12345678, .little);
    std.mem.writeInt(u32, data1[88..92], 60000, .little); // methods
    std.mem.writeInt(u32, data1[96..100], 500, .little); // classes
    std.mem.writeInt(u32, data1[80..84], 1000, .little); // fields

    // Second DEX file
    data2[0] = 'd';
    data2[1] = 'e';
    data2[2] = 'x';
    data2[3] = '\n';
    data2[4] = '0';
    data2[5] = '3';
    data2[6] = '5';
    data2[7] = 0;
    std.mem.writeInt(u32, data2[36..40], 112, .little);
    std.mem.writeInt(u32, data2[40..44], 0x12345678, .little);
    std.mem.writeInt(u32, data2[88..92], 10000, .little); // methods
    std.mem.writeInt(u32, data2[96..100], 200, .little); // classes
    std.mem.writeInt(u32, data2[80..84], 500, .little); // fields

    const dex_files: []const []const u8 = &.{ &data1, &data2 };
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 2), info.files.len);
    try std.testing.expectEqual(@as(u64, 70000), info.total_methods);
    try std.testing.expectEqual(@as(u64, 700), info.total_classes);
    try std.testing.expectEqual(@as(u64, 1500), info.total_fields);
    try std.testing.expect(info.is_multidex);
}

test "DexAnalyzer.isDexFile returns true for valid DEX" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    try std.testing.expect(DexAnalyzer.isDexFile(&data));
}

test "DexAnalyzer.isDexFile returns false for non-DEX" {
    try std.testing.expect(!DexAnalyzer.isDexFile("not a dex file"));
    try std.testing.expect(!DexAnalyzer.isDexFile(""));
    try std.testing.expect(!DexAnalyzer.isDexFile("dex"));
}

test "DexAnalyzer.getVersion returns correct version" {
    var data035: [8]u8 = .{ 'd', 'e', 'x', '\n', '0', '3', '5', 0 };
    var data039: [8]u8 = .{ 'd', 'e', 'x', '\n', '0', '3', '9', 0 };

    const version035 = DexAnalyzer.getVersion(&data035);
    const version039 = DexAnalyzer.getVersion(&data039);

    try std.testing.expect(version035 != null);
    try std.testing.expectEqualSlices(u8, "035", &version035.?);

    try std.testing.expect(version039 != null);
    try std.testing.expectEqualSlices(u8, "039", &version039.?);
}

test "DexAnalyzer.getVersion returns null for invalid data" {
    try std.testing.expect(DexAnalyzer.getVersion("") == null);
    try std.testing.expect(DexAnalyzer.getVersion("short") == null);
    try std.testing.expect(DexAnalyzer.getVersion("not dex!") == null);
}

test "DexAnalyzer.parseHeader returns InvalidHeader for wrong endian tag" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    std.mem.writeInt(u32, data[36..40], 112, .little);
    // Wrong endian tag
    std.mem.writeInt(u32, data[40..44], 0x87654321, .little);

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidHeader, result);
}

test "DexAnalyzer.parseHeader returns InvalidHeader for wrong header size" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '5';
    data[7] = 0;

    // Wrong header size
    std.mem.writeInt(u32, data[36..40], 100, .little);
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidHeader, result);
}
