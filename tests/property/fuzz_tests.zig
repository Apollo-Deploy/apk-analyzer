const std = @import("std");
const apk = @import("apk-analyzer");
const zip = apk.parsers.zip;
const axml = apk.parsers.axml;
const dex = apk.parsers.dex;
const certificate = apk.parsers.certificate;
const protobuf = apk.parsers.protobuf;

// ============================================================================
// Property-Based (Fuzz) Tests for APK Analyzer Parsers
// ============================================================================
//
// These tests ensure that all parsers handle arbitrary/malformed input
// gracefully without crashing. Errors are acceptable, crashes are not.
//
// Requirements addressed: 11.1, 11.2, 11.3, 11.4, 11.5 (Error Handling)
// ============================================================================

/// Number of fuzz iterations per test
const FUZZ_ITERATIONS: usize = 1000;

/// Maximum size for generated fuzz data
const MAX_FUZZ_SIZE: usize = 65536; // 64KB

/// Random number generator for fuzz testing
var prng = std.Random.DefaultPrng.init(0);
const random = prng.random();

// ============================================================================
// ZIP Parser Fuzz Tests
// ============================================================================

test "ZIP parser handles random data without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Generate random data
        const size = random.intRangeAtMost(usize, 0, MAX_FUZZ_SIZE);
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        random.bytes(data);

        // Try to parse - should not crash
        var parser = zip.ZipParser.parse(allocator, data) catch continue;
        parser.deinit();
    }
}

test "ZIP parser handles truncated data without crashing" {
    const allocator = std.testing.allocator;

    // Create a minimal valid ZIP header
    var valid_zip: [22]u8 = undefined;
    std.mem.writeInt(u32, valid_zip[0..4], 0x04034b50, .little); // Local file header signature
    @memset(valid_zip[4..], 0);

    // Test with progressively truncated data
    var size: usize = 0;
    while (size <= valid_zip.len) : (size += 1) {
        const truncated = valid_zip[0..size];

        // Should not crash, may return error
        var parser = zip.ZipParser.parse(allocator, truncated) catch continue;
        parser.deinit();
    }
}

test "ZIP parser handles malformed headers without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Create data with valid magic but random rest
        var data: [1024]u8 = undefined;
        random.bytes(&data);

        // Set valid ZIP magic
        std.mem.writeInt(u32, data[0..4], 0x04034b50, .little);

        // Try to parse - should not crash
        var parser = zip.ZipParser.parse(allocator, &data) catch continue;
        parser.deinit();
    }
}

// ============================================================================
// AXML Parser Fuzz Tests
// ============================================================================

test "AXML parser handles random data without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Generate random data
        const size = random.intRangeAtMost(usize, 0, MAX_FUZZ_SIZE);
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        random.bytes(data);

        // Try to parse - should not crash
        var parser = axml.AxmlParser.parse(allocator, data) catch continue;
        parser.deinit();
    }
}

test "AXML parser handles truncated data without crashing" {
    const allocator = std.testing.allocator;

    // Create a minimal valid AXML header
    var valid_axml: [8]u8 = undefined;
    std.mem.writeInt(u16, valid_axml[0..2], 0x0003, .little); // AXML magic
    std.mem.writeInt(u16, valid_axml[2..4], 8, .little); // Header size
    std.mem.writeInt(u32, valid_axml[4..8], 8, .little); // File size

    // Test with progressively truncated data
    var size: usize = 0;
    while (size <= valid_axml.len) : (size += 1) {
        const truncated = valid_axml[0..size];

        // Should not crash, may return error
        var parser = axml.AxmlParser.parse(allocator, truncated) catch continue;
        parser.deinit();
    }
}

test "AXML parser handles malformed chunks without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Create data with valid magic but random chunks
        var data: [2048]u8 = undefined;
        random.bytes(&data);

        // Set valid AXML magic
        std.mem.writeInt(u16, data[0..2], 0x0003, .little);
        std.mem.writeInt(u16, data[2..4], 8, .little);
        std.mem.writeInt(u32, data[4..8], @intCast(data.len), .little);

        // Try to parse - should not crash
        var parser = axml.AxmlParser.parse(allocator, &data) catch continue;
        parser.deinit();
    }
}

// ============================================================================
// DEX Parser Fuzz Tests
// ============================================================================

test "DEX parser handles random data without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Generate random data
        const size = random.intRangeAtMost(usize, 0, MAX_FUZZ_SIZE);
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        random.bytes(data);

        // Try to parse header - should not crash
        _ = dex.DexAnalyzer.parseHeader(data) catch continue;

        // Try to analyze - should not crash
        _ = dex.DexAnalyzer.analyze(allocator, data) catch continue;
    }
}

test "DEX parser handles truncated data without crashing" {
    const allocator = std.testing.allocator;

    // Create a minimal valid DEX header
    var valid_dex: [112]u8 = undefined;
    @memset(&valid_dex, 0);

    // Set DEX magic: "dex\n035\0"
    valid_dex[0] = 'd';
    valid_dex[1] = 'e';
    valid_dex[2] = 'x';
    valid_dex[3] = '\n';
    valid_dex[4] = '0';
    valid_dex[5] = '3';
    valid_dex[6] = '5';
    valid_dex[7] = 0;

    // Set header size and endian tag
    std.mem.writeInt(u32, valid_dex[36..40], 112, .little);
    std.mem.writeInt(u32, valid_dex[40..44], 0x12345678, .little);

    // Test with progressively truncated data
    var size: usize = 0;
    while (size <= valid_dex.len) : (size += 1) {
        const truncated = valid_dex[0..size];

        // Should not crash, may return error
        _ = dex.DexAnalyzer.parseHeader(truncated) catch continue;
        _ = dex.DexAnalyzer.analyze(allocator, truncated) catch continue;
    }
}

test "DEX parser handles malformed headers without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Create data with valid magic but random rest
        var data: [512]u8 = undefined;
        random.bytes(&data);

        // Set valid DEX magic
        data[0] = 'd';
        data[1] = 'e';
        data[2] = 'x';
        data[3] = '\n';
        data[4] = '0';
        data[5] = '3';
        data[6] = '5';
        data[7] = 0;

        // Try to parse - should not crash
        _ = dex.DexAnalyzer.parseHeader(&data) catch continue;
        _ = dex.DexAnalyzer.analyze(allocator, &data) catch continue;
    }
}

// ============================================================================
// Certificate Parser Fuzz Tests
// ============================================================================

test "Certificate parser handles random data without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Generate random data
        const size = random.intRangeAtMost(usize, 0, MAX_FUZZ_SIZE);
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        random.bytes(data);

        // Try to parse - should not crash
        var parser = certificate.CertificateParser.init(allocator);
        defer parser.deinit();

        var info = parser.parsePkcs7(data) catch continue;
        info.deinit();
    }
}

test "Certificate parser handles truncated data without crashing" {
    const allocator = std.testing.allocator;

    // Create a minimal ASN.1 SEQUENCE
    var valid_asn1: [10]u8 = undefined;
    valid_asn1[0] = 0x30; // SEQUENCE tag
    valid_asn1[1] = 0x08; // Length
    @memset(valid_asn1[2..], 0);

    // Test with progressively truncated data
    var size: usize = 0;
    while (size <= valid_asn1.len) : (size += 1) {
        const truncated = valid_asn1[0..size];

        // Should not crash, may return error
        var parser = certificate.CertificateParser.init(allocator);
        defer parser.deinit();

        var info = parser.parsePkcs7(truncated) catch continue;
        info.deinit();
    }
}

test "Certificate parser handles malformed ASN.1 without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Create data with valid ASN.1 tag but random content
        var data: [1024]u8 = undefined;
        random.bytes(&data);

        // Set valid SEQUENCE tag
        data[0] = 0x30;

        // Try to parse - should not crash
        var parser = certificate.CertificateParser.init(allocator);
        defer parser.deinit();

        var info = parser.parsePkcs7(&data) catch continue;
        info.deinit();
    }
}

// ============================================================================
// Protobuf Parser Fuzz Tests
// ============================================================================

test "Protobuf parser handles random data without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Generate random data
        const size = random.intRangeAtMost(usize, 0, MAX_FUZZ_SIZE);
        const data = try allocator.alloc(u8, size);
        defer allocator.free(data);

        random.bytes(data);

        // Try to parse - should not crash
        var parser = protobuf.ProtobufParser.parse(allocator, data) catch continue;
        parser.deinit();
    }
}

test "Protobuf parser handles truncated data without crashing" {
    const allocator = std.testing.allocator;

    // Create a minimal valid protobuf message
    var valid_pb: [10]u8 = undefined;
    valid_pb[0] = 0x08; // Field 1, wire type 0 (varint)
    valid_pb[1] = 0x01; // Value 1
    @memset(valid_pb[2..], 0);

    // Test with progressively truncated data
    var size: usize = 0;
    while (size <= valid_pb.len) : (size += 1) {
        const truncated = valid_pb[0..size];

        // Should not crash, may return error
        var parser = protobuf.ProtobufParser.parse(allocator, truncated) catch continue;
        parser.deinit();
    }
}

test "Protobuf parser handles malformed varints without crashing" {
    const allocator = std.testing.allocator;

    var i: usize = 0;
    while (i < FUZZ_ITERATIONS) : (i += 1) {
        // Create data with malformed varints (all continuation bits set)
        var data: [512]u8 = undefined;

        // Fill with bytes that have continuation bit set
        for (&data) |*byte| {
            byte.* = 0x80 | @as(u8, random.int(u7));
        }

        // Try to parse - should not crash
        var parser = protobuf.ProtobufParser.parse(allocator, &data) catch continue;
        parser.deinit();
    }
}

// ============================================================================
// Combined Fuzz Tests
// ============================================================================

test "All parsers handle empty input without crashing" {
    const allocator = std.testing.allocator;
    const empty: []const u8 = &.{};

    // ZIP parser
    _ = zip.ZipParser.parse(allocator, empty) catch {};

    // AXML parser
    var axml_parser = axml.AxmlParser.parse(allocator, empty) catch return;
    axml_parser.deinit();

    // DEX parser
    _ = dex.DexAnalyzer.parseHeader(empty) catch {};
    _ = dex.DexAnalyzer.analyze(allocator, empty) catch {};

    // Certificate parser
    var cert_parser = certificate.CertificateParser.init(allocator);
    defer cert_parser.deinit();
    var cert_info = cert_parser.parsePkcs7(empty) catch return;
    cert_info.deinit();

    // Protobuf parser
    var pb_parser = protobuf.ProtobufParser.parse(allocator, empty) catch return;
    pb_parser.deinit();
}

test "All parsers handle single byte input without crashing" {
    const allocator = std.testing.allocator;
    const single_byte: []const u8 = &.{0xFF};

    // ZIP parser
    _ = zip.ZipParser.parse(allocator, single_byte) catch {};

    // AXML parser
    var axml_parser = axml.AxmlParser.parse(allocator, single_byte) catch return;
    axml_parser.deinit();

    // DEX parser
    _ = dex.DexAnalyzer.parseHeader(single_byte) catch {};
    _ = dex.DexAnalyzer.analyze(allocator, single_byte) catch {};

    // Certificate parser
    var cert_parser = certificate.CertificateParser.init(allocator);
    defer cert_parser.deinit();
    var cert_info = cert_parser.parsePkcs7(single_byte) catch return;
    cert_info.deinit();

    // Protobuf parser
    var pb_parser = protobuf.ProtobufParser.parse(allocator, single_byte) catch return;
    pb_parser.deinit();
}

test "All parsers handle maximum size input without crashing" {
    const allocator = std.testing.allocator;

    // Allocate maximum size buffer
    const data = try allocator.alloc(u8, MAX_FUZZ_SIZE);
    defer allocator.free(data);

    random.bytes(data);

    // ZIP parser
    var zip_parser = zip.ZipParser.parse(allocator, data) catch return;
    zip_parser.deinit();

    // AXML parser
    var axml_parser = axml.AxmlParser.parse(allocator, data) catch return;
    axml_parser.deinit();

    // DEX parser
    _ = dex.DexAnalyzer.parseHeader(data) catch {};
    _ = dex.DexAnalyzer.analyze(allocator, data) catch {};

    // Certificate parser
    var cert_parser = certificate.CertificateParser.init(allocator);
    defer cert_parser.deinit();
    var cert_info = cert_parser.parsePkcs7(data) catch return;
    cert_info.deinit();

    // Protobuf parser
    var pb_parser = protobuf.ProtobufParser.parse(allocator, data) catch return;
    pb_parser.deinit();
}
