//! DEX Analyzer Unit Tests
//!
//! Additional unit tests for the DEX file analyzer.
//! These tests complement the inline tests in dex.zig.

const std = @import("std");
const dex = @import("dex");
const DexAnalyzer = dex.DexAnalyzer;

/// Helper to create a valid DEX header buffer
fn createValidDexHeader(version: []const u8) [112]u8 {
    var data: [112]u8 = undefined;
    @memset(&data, 0);

    // Magic: "dex\n" + version
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = version[0];
    data[5] = version[1];
    data[6] = version[2];
    data[7] = 0;

    // Header size (must be 112)
    std.mem.writeInt(u32, data[36..40], 112, .little);

    // Endian tag (must be 0x12345678)
    std.mem.writeInt(u32, data[40..44], 0x12345678, .little);

    return data;
}

/// Helper to set counts in a DEX header
fn setDexCounts(data: *[112]u8, strings: u32, fields: u32, methods: u32, classes: u32) void {
    std.mem.writeInt(u32, data[56..60], strings, .little); // string_ids_size
    std.mem.writeInt(u32, data[80..84], fields, .little); // field_ids_size
    std.mem.writeInt(u32, data[88..92], methods, .little); // method_ids_size
    std.mem.writeInt(u32, data[96..100], classes, .little); // class_defs_size
}

// ============================================================================
// Valid DEX File Tests
// ============================================================================

test "parse valid DEX 035 header with all counts" {
    var data = createValidDexHeader("035");
    setDexCounts(&data, 5000, 2000, 30000, 1000);

    const header = try DexAnalyzer.parseHeader(&data);

    try std.testing.expectEqual(@as(u32, 5000), header.string_ids_size);
    try std.testing.expectEqual(@as(u32, 2000), header.field_ids_size);
    try std.testing.expectEqual(@as(u32, 30000), header.method_ids_size);
    try std.testing.expectEqual(@as(u32, 1000), header.class_defs_size);
}

test "parse valid DEX 039 header with all counts" {
    var data = createValidDexHeader("039");
    setDexCounts(&data, 10000, 5000, 50000, 2000);

    const header = try DexAnalyzer.parseHeader(&data);

    try std.testing.expectEqual(@as(u32, 10000), header.string_ids_size);
    try std.testing.expectEqual(@as(u32, 5000), header.field_ids_size);
    try std.testing.expectEqual(@as(u32, 50000), header.method_ids_size);
    try std.testing.expectEqual(@as(u32, 2000), header.class_defs_size);
}

// ============================================================================
// Invalid/Malformed DEX File Tests
// ============================================================================

test "reject empty data" {
    const result = DexAnalyzer.parseHeader("");
    try std.testing.expectError(DexAnalyzer.DexError.TruncatedData, result);
}

test "reject data shorter than header" {
    const short_data = "dex\n035\x00" ++ [_]u8{0} ** 50; // Only 58 bytes
    const result = DexAnalyzer.parseHeader(short_data);
    try std.testing.expectError(DexAnalyzer.DexError.TruncatedData, result);
}

test "reject data with wrong magic prefix" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 'D'; // Wrong case
    data[1] = 'E';
    data[2] = 'X';
    data[3] = '\n';

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidMagic, result);
}

test "reject data with corrupted magic" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 0xFF;
    data[1] = 0xFF;
    data[2] = 0xFF;
    data[3] = 0xFF;

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidMagic, result);
}

test "reject unsupported DEX version 036" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '6';
    data[7] = 0;

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.UnsupportedVersion, result);
}

test "reject unsupported DEX version 037" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '7';
    data[7] = 0;

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.UnsupportedVersion, result);
}

test "reject unsupported DEX version 038" {
    var data: [112]u8 = undefined;
    @memset(&data, 0);
    data[0] = 'd';
    data[1] = 'e';
    data[2] = 'x';
    data[3] = '\n';
    data[4] = '0';
    data[5] = '3';
    data[6] = '8';
    data[7] = 0;

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.UnsupportedVersion, result);
}

test "reject big-endian DEX file" {
    var data = createValidDexHeader("035");
    // Set wrong endian tag (big-endian marker)
    std.mem.writeInt(u32, data[40..44], 0x78563412, .little);

    const result = DexAnalyzer.parseHeader(&data);
    try std.testing.expectError(DexAnalyzer.DexError.InvalidHeader, result);
}

// ============================================================================
// Multidex Scenario Tests
// ============================================================================

test "analyze three DEX files (multidex)" {
    var data1 = createValidDexHeader("035");
    var data2 = createValidDexHeader("035");
    var data3 = createValidDexHeader("035");

    setDexCounts(&data1, 1000, 500, 40000, 300);
    setDexCounts(&data2, 800, 400, 30000, 200);
    setDexCounts(&data3, 500, 200, 15000, 100);

    const dex_files: []const []const u8 = &.{ &data1, &data2, &data3 };
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 3), info.files.len);
    try std.testing.expectEqual(@as(u64, 85000), info.total_methods);
    try std.testing.expectEqual(@as(u64, 600), info.total_classes);
    try std.testing.expectEqual(@as(u64, 1100), info.total_fields);
    try std.testing.expect(info.is_multidex);
}

test "multidex with mixed versions" {
    var data1 = createValidDexHeader("035");
    var data2 = createValidDexHeader("039");

    setDexCounts(&data1, 1000, 500, 50000, 300);
    setDexCounts(&data2, 800, 400, 20000, 200);

    const dex_files: []const []const u8 = &.{ &data1, &data2 };
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);
    defer info.deinit();

    try std.testing.expectEqual(@as(usize, 2), info.files.len);
    try std.testing.expectEqualSlices(u8, "035", &info.files[0].version);
    try std.testing.expectEqualSlices(u8, "039", &info.files[1].version);
    try std.testing.expectEqual(@as(u64, 70000), info.total_methods);
    try std.testing.expect(info.is_multidex);
}

test "multidex fails on invalid second DEX" {
    var data1 = createValidDexHeader("035");
    setDexCounts(&data1, 1000, 500, 40000, 300);

    const invalid_data = "not a dex file at all!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

    const dex_files: []const []const u8 = &.{ &data1, invalid_data };
    const result = DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);

    try std.testing.expectError(DexAnalyzer.DexError.InvalidMagic, result);
}

// ============================================================================
// Method Limit Detection Tests
// ============================================================================

test "detect method limit at exactly 65536" {
    var data = createValidDexHeader("035");
    setDexCounts(&data, 1000, 500, 65536, 300);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(info.exceeds_limit);
}

test "detect method limit above 65536" {
    var data = createValidDexHeader("035");
    setDexCounts(&data, 1000, 500, 100000, 300);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(info.exceeds_limit);
}

test "no limit exceeded at 65535" {
    var data = createValidDexHeader("035");
    setDexCounts(&data, 1000, 500, 65535, 300);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(!info.exceeds_limit);
}

test "no limit exceeded at zero methods" {
    var data = createValidDexHeader("035");
    setDexCounts(&data, 0, 0, 0, 0);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expect(!info.exceeds_limit);
}

// ============================================================================
// Utility Function Tests
// ============================================================================

test "isDexFile with various inputs" {
    // Valid DEX 035
    var valid035 = createValidDexHeader("035");
    try std.testing.expect(DexAnalyzer.isDexFile(&valid035));

    // Valid DEX 039
    var valid039 = createValidDexHeader("039");
    try std.testing.expect(DexAnalyzer.isDexFile(&valid039));

    // Invalid: too short
    try std.testing.expect(!DexAnalyzer.isDexFile("dex\n03"));

    // Invalid: wrong magic
    try std.testing.expect(!DexAnalyzer.isDexFile("DEX\n035\x00"));

    // Invalid: unsupported version
    try std.testing.expect(!DexAnalyzer.isDexFile("dex\n036\x00"));

    // Invalid: random data
    try std.testing.expect(!DexAnalyzer.isDexFile(&[_]u8{0xFF} ** 112));
}

test "getVersion extracts correct version strings" {
    const v035 = DexAnalyzer.getVersion("dex\n035\x00");
    try std.testing.expect(v035 != null);
    try std.testing.expectEqualSlices(u8, "035", &v035.?);

    const v039 = DexAnalyzer.getVersion("dex\n039\x00");
    try std.testing.expect(v039 != null);
    try std.testing.expectEqualSlices(u8, "039", &v039.?);

    // Invalid inputs
    try std.testing.expect(DexAnalyzer.getVersion("") == null);
    try std.testing.expect(DexAnalyzer.getVersion("dex") == null);
    try std.testing.expect(DexAnalyzer.getVersion("notdex!") == null);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "handle maximum u32 counts" {
    var data = createValidDexHeader("035");
    const max_u32: u32 = 0xFFFFFFFF;
    setDexCounts(&data, max_u32, max_u32, max_u32, max_u32);

    const info = try DexAnalyzer.analyze(std.testing.allocator, &data);
    try std.testing.expectEqual(max_u32, info.method_count);
    try std.testing.expectEqual(max_u32, info.class_count);
    try std.testing.expectEqual(max_u32, info.field_count);
    try std.testing.expectEqual(max_u32, info.string_count);
    try std.testing.expect(info.exceeds_limit);
}

test "multidex aggregation with large counts" {
    var data1 = createValidDexHeader("035");
    var data2 = createValidDexHeader("035");

    // Set large counts that would overflow u32 when summed
    setDexCounts(&data1, 0, 0, 0xFFFFFFFF, 0);
    setDexCounts(&data2, 0, 0, 0xFFFFFFFF, 0);

    const dex_files: []const []const u8 = &.{ &data1, &data2 };
    var info = try DexAnalyzer.analyzeMultiple(std.testing.allocator, dex_files);
    defer info.deinit();

    // Should use u64 for totals to avoid overflow
    try std.testing.expectEqual(@as(u64, 0x1FFFFFFFE), info.total_methods);
}
