//! Certificate Parser Unit Tests
//!
//! Additional unit tests for the certificate parser.
//! These tests complement the inline tests in certificate.zig.

const std = @import("std");
const cert = @import("certificate");
const CertificateParser = cert.CertificateParser;
const CertificateInfo = CertificateParser.CertificateInfo;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a minimal valid ASN.1 SEQUENCE
fn createAsn1Sequence(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, content.len + 2);
    result[0] = 0x30; // SEQUENCE tag
    result[1] = @intCast(content.len);
    @memcpy(result[2..], content);
    return result;
}

/// Create a minimal ASN.1 INTEGER
fn createAsn1Integer(value: u8) [3]u8 {
    return [_]u8{ 0x02, 0x01, value };
}

/// Create a minimal ASN.1 OID
fn createAsn1Oid(oid: []const u8) []const u8 {
    _ = oid;
    // For testing, return a simple OID structure
    return &[_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 }; // CN OID
}

// ============================================================================
// Fingerprint Computation Tests
// ============================================================================

test "MD5 fingerprint is deterministic" {
    const data = "Hello, World!";
    const fp1 = CertificateParser.computeMd5Fingerprint(data);
    const fp2 = CertificateParser.computeMd5Fingerprint(data);
    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
}

test "SHA-256 fingerprint is deterministic" {
    const data = "Hello, World!";
    const fp1 = CertificateParser.computeSha256Fingerprint(data);
    const fp2 = CertificateParser.computeSha256Fingerprint(data);
    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
}

test "different data produces different MD5 fingerprints" {
    const fp1 = CertificateParser.computeMd5Fingerprint("data1");
    const fp2 = CertificateParser.computeMd5Fingerprint("data2");
    try std.testing.expect(!std.mem.eql(u8, &fp1, &fp2));
}

test "different data produces different SHA-256 fingerprints" {
    const fp1 = CertificateParser.computeSha256Fingerprint("data1");
    const fp2 = CertificateParser.computeSha256Fingerprint("data2");
    try std.testing.expect(!std.mem.eql(u8, &fp1, &fp2));
}

test "empty data produces valid fingerprints" {
    const empty: []const u8 = "";
    const md5 = CertificateParser.computeMd5Fingerprint(empty);
    const sha256 = CertificateParser.computeSha256Fingerprint(empty);

    // MD5 of empty string is d41d8cd98f00b204e9800998ecf8427e
    try std.testing.expectEqual(@as(u8, 0xd4), md5[0]);

    // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    try std.testing.expectEqual(@as(u8, 0xe3), sha256[0]);
}

// ============================================================================
// Fingerprint Formatting Tests
// ============================================================================

test "formatFingerprintHex formats 16-byte MD5 correctly" {
    const md5 = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, &md5);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF", hex);
}

test "formatFingerprintHex handles all zeros" {
    const zeros = [_]u8{0} ** 4;
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, &zeros);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("00:00:00:00", hex);
}

test "formatFingerprintHex handles all 0xFF" {
    const ones = [_]u8{0xFF} ** 4;
    const hex = try CertificateParser.formatFingerprintHex(std.testing.allocator, &ones);
    defer std.testing.allocator.free(hex);

    try std.testing.expectEqualStrings("FF:FF:FF:FF", hex);
}

// ============================================================================
// Signature File Detection Tests
// ============================================================================

test "isSignatureFile accepts various RSA file names" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.RSA"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/ANDROIDDEBUGKEY.RSA"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/RELEASE.RSA"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/A.RSA"));
}

test "isSignatureFile accepts DSA files" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.DSA"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/KEY.DSA"));
}

test "isSignatureFile accepts EC files" {
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/CERT.EC"));
    try std.testing.expect(CertificateParser.isSignatureFile("META-INF/KEY.EC"));
}

test "isSignatureFile rejects files not in META-INF" {
    try std.testing.expect(!CertificateParser.isSignatureFile("CERT.RSA"));
    try std.testing.expect(!CertificateParser.isSignatureFile("lib/CERT.RSA"));
    try std.testing.expect(!CertificateParser.isSignatureFile("assets/CERT.RSA"));
}

test "isSignatureFile rejects non-signature extensions" {
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/MANIFEST.MF"));
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/CERT.SF"));
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/CERT.PEM"));
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/CERT.CRT"));
}

test "isSignatureFile rejects short filenames" {
    try std.testing.expect(!CertificateParser.isSignatureFile(""));
    try std.testing.expect(!CertificateParser.isSignatureFile("M"));
    try std.testing.expect(!CertificateParser.isSignatureFile("META-INF/"));
}

// ============================================================================
// ASN.1 Parsing Tests
// ============================================================================

test "parseAsn1Length handles maximum short form length" {
    var pos: usize = 0;
    const data = [_]u8{0x7F}; // Length 127 (max short form)
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 127), length);
}

test "parseAsn1Length handles 3-byte long form" {
    var pos: usize = 0;
    const data = [_]u8{ 0x83, 0x01, 0x00, 0x00 }; // Length 65536
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 65536), length);
}

test "parseAsn1Length handles 4-byte long form" {
    var pos: usize = 0;
    const data = [_]u8{ 0x84, 0x00, 0x01, 0x00, 0x00 }; // Length 65536
    const length = try CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectEqual(@as(usize, 65536), length);
}

test "parseAsn1Length rejects too many length bytes" {
    var pos: usize = 0;
    const data = [_]u8{ 0x85, 0x00, 0x00, 0x00, 0x00, 0x01 }; // 5 length bytes
    const result = CertificateParser.parseAsn1Length(&data, &pos);
    try std.testing.expectError(CertificateParser.CertError.InvalidAsn1, result);
}

test "parseAsn1Length returns TruncatedData for empty input" {
    var pos: usize = 0;
    const data: []const u8 = &.{};
    const result = CertificateParser.parseAsn1Length(data, &pos);
    try std.testing.expectError(CertificateParser.CertError.TruncatedData, result);
}

// ============================================================================
// Time Parsing Tests
// ============================================================================

test "parseUtcTime parses various valid times" {
    // Test different dates
    const times = [_]struct { input: []const u8, year: i32 }{
        .{ .input = "230101000000Z", .year = 2023 },
        .{ .input = "991231235959Z", .year = 1999 },
        .{ .input = "500101000000Z", .year = 1950 },
        .{ .input = "490101000000Z", .year = 2049 },
    };

    for (times) |t| {
        const timestamp = try CertificateParser.parseUtcTime(t.input);
        // Just verify it parses without error and produces reasonable output
        if (t.year >= 2000) {
            try std.testing.expect(timestamp > 946684800); // After Y2K
        } else {
            try std.testing.expect(timestamp < 946684800); // Before Y2K
        }
    }
}

test "parseUtcTime rejects short input" {
    const result = CertificateParser.parseUtcTime("230101");
    try std.testing.expectError(CertificateParser.CertError.InvalidUtcTime, result);
}

test "parseUtcTime rejects invalid digits" {
    const result = CertificateParser.parseUtcTime("XX0101000000Z");
    try std.testing.expectError(CertificateParser.CertError.InvalidUtcTime, result);
}

test "parseGeneralizedTime parses valid times" {
    const timestamp = try CertificateParser.parseGeneralizedTime("20230615120000Z");
    try std.testing.expect(timestamp > 1672531200); // After 2023-01-01
}

test "parseGeneralizedTime rejects short input" {
    const result = CertificateParser.parseGeneralizedTime("2023061512");
    try std.testing.expectError(CertificateParser.CertError.InvalidGeneralizedTime, result);
}

// ============================================================================
// Date Calculation Tests
// ============================================================================

test "dateToTimestamp handles leap years correctly" {
    // February 1, 2000 (before leap day)
    const before_leap = CertificateParser.dateToTimestamp(2000, 2, 1, 0, 0, 0);
    // February 1, 2001 (non-leap year)
    const after_leap = CertificateParser.dateToTimestamp(2001, 2, 1, 0, 0, 0);

    // From Feb 1, 2000 to Feb 1, 2001 is 366 days (includes Feb 29, 2000)
    const diff = after_leap - before_leap;
    const expected_diff = 366 * 86400; // 366 days in seconds
    try std.testing.expectEqual(expected_diff, diff);
}

test "dateToTimestamp handles end of year" {
    // December 31, 2023, 23:59:59
    const eoy = CertificateParser.dateToTimestamp(2023, 12, 31, 23, 59, 59);
    // January 1, 2024, 00:00:00
    const ny = CertificateParser.dateToTimestamp(2024, 1, 1, 0, 0, 0);

    // Difference should be 1 second
    try std.testing.expectEqual(@as(i64, 1), ny - eoy);
}

test "isLeapYear handles century years" {
    try std.testing.expect(CertificateParser.isLeapYear(2000)); // Divisible by 400
    try std.testing.expect(!CertificateParser.isLeapYear(1900)); // Divisible by 100 but not 400
    try std.testing.expect(!CertificateParser.isLeapYear(2100)); // Divisible by 100 but not 400
    try std.testing.expect(CertificateParser.isLeapYear(2400)); // Divisible by 400
}

// ============================================================================
// Algorithm Name Tests
// ============================================================================

test "getAlgorithmName returns all known algorithms" {
    const algorithms = [_]struct { oid: []const u8, name: []const u8 }{
        .{ .oid = &CertificateParser.OID_SHA1_WITH_RSA, .name = "SHA1withRSA" },
        .{ .oid = &CertificateParser.OID_SHA256_WITH_RSA, .name = "SHA256withRSA" },
        .{ .oid = &CertificateParser.OID_SHA384_WITH_RSA, .name = "SHA384withRSA" },
        .{ .oid = &CertificateParser.OID_SHA512_WITH_RSA, .name = "SHA512withRSA" },
        .{ .oid = &CertificateParser.OID_SHA256_WITH_ECDSA, .name = "SHA256withECDSA" },
        .{ .oid = &CertificateParser.OID_SHA384_WITH_ECDSA, .name = "SHA384withECDSA" },
        .{ .oid = &CertificateParser.OID_SHA256_WITH_DSA, .name = "SHA256withDSA" },
        .{ .oid = &CertificateParser.OID_RSA_ENCRYPTION, .name = "RSA" },
        .{ .oid = &CertificateParser.OID_EC_PUBLIC_KEY, .name = "EC" },
        .{ .oid = &CertificateParser.OID_DSA, .name = "DSA" },
    };

    for (algorithms) |alg| {
        try std.testing.expectEqualStrings(alg.name, CertificateParser.getAlgorithmName(alg.oid));
    }
}

// ============================================================================
// Attribute Name Tests
// ============================================================================

test "getAttributeName returns all known attributes" {
    const attributes = [_]struct { oid: []const u8, name: []const u8 }{
        .{ .oid = &CertificateParser.OID_COMMON_NAME, .name = "CN" },
        .{ .oid = &CertificateParser.OID_ORGANIZATION, .name = "O" },
        .{ .oid = &CertificateParser.OID_ORG_UNIT, .name = "OU" },
        .{ .oid = &CertificateParser.OID_COUNTRY, .name = "C" },
        .{ .oid = &CertificateParser.OID_STATE, .name = "ST" },
        .{ .oid = &CertificateParser.OID_LOCALITY, .name = "L" },
    };

    for (attributes) |attr| {
        try std.testing.expectEqualStrings(attr.name, CertificateParser.getAttributeName(attr.oid));
    }
}

test "getAttributeName returns empty for unknown OID" {
    const unknown = [_]u8{ 0x01, 0x02, 0x03 };
    try std.testing.expectEqualStrings("", CertificateParser.getAttributeName(&unknown));
}

// ============================================================================
// Parser Error Handling Tests
// ============================================================================

test "parsePkcs7 handles various invalid inputs" {
    var parser = CertificateParser.init(std.testing.allocator);
    defer parser.deinit();

    // Empty input
    try std.testing.expectError(
        CertificateParser.CertError.TruncatedData,
        parser.parsePkcs7(""),
    );

    // Too short
    try std.testing.expectError(
        CertificateParser.CertError.TruncatedData,
        parser.parsePkcs7("12345"),
    );

    // Invalid tag (not SEQUENCE)
    const invalid_tag = [_]u8{ 0x02, 0x01, 0x00 } ++ [_]u8{0} ** 20;
    try std.testing.expectError(
        CertificateParser.CertError.InvalidFormat,
        parser.parsePkcs7(&invalid_tag),
    );
}

// ============================================================================
// CertificateInfo Tests
// ============================================================================

test "CertificateInfo.deinit frees allocated memory" {
    // Create a mock CertificateInfo with allocated strings
    var info = CertificateInfo{
        .subject = try std.testing.allocator.dupe(u8, "CN=Test"),
        .issuer = try std.testing.allocator.dupe(u8, "CN=Issuer"),
        .serial_number = try std.testing.allocator.dupe(u8, "0123456789"),
        .not_before = 0,
        .not_after = 0,
        .fingerprint_md5 = [_]u8{0} ** 16,
        .fingerprint_sha256 = [_]u8{0} ** 32,
        .signature_algorithm = try std.testing.allocator.dupe(u8, "SHA256withRSA"),
        .public_key_algorithm = try std.testing.allocator.dupe(u8, "RSA"),
        .public_key_size = 2048,
        .raw_certificate = "",
        .allocator = std.testing.allocator,
    };

    // This should not leak memory
    info.deinit();
}
