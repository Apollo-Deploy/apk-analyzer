//! Integration tests for ApkAnalyzer
//!
//! These tests verify end-to-end functionality of the analyzer
//! with real APK/AAB structures.

const std = @import("std");
const apk = @import("apk-analyzer");

test "ApkAnalyzer can be initialized and deinitialized" {
    var analyzer = apk.ApkAnalyzer.init(std.testing.allocator, .{});
    defer analyzer.deinit();

    // Verify analyzer is properly initialized
    try std.testing.expect(!analyzer.options.skip_dex_analysis);
    try std.testing.expect(!analyzer.options.skip_certificate);
}

test "ApkAnalyzer.validate detects invalid archives" {
    var analyzer = apk.ApkAnalyzer.init(std.testing.allocator, .{});
    defer analyzer.deinit();

    // Test with empty data
    const result1 = analyzer.validate(&[_]u8{});
    try std.testing.expect(!result1.is_valid);
    try std.testing.expect(result1.error_message != null);

    // Test with non-ZIP data
    const result2 = analyzer.validate("not a zip file");
    try std.testing.expect(!result2.is_valid);
    try std.testing.expectEqualStrings("Not a valid ZIP archive", result2.error_message.?);

    // Test with truncated ZIP
    const truncated_zip = [_]u8{ 'P', 'K', 0x03, 0x04 };
    const result3 = analyzer.validate(&truncated_zip);
    try std.testing.expect(!result3.is_valid);
}

test "ApkAnalyzer.analyze returns error for invalid data" {
    var analyzer = apk.ApkAnalyzer.init(std.testing.allocator, .{});
    defer analyzer.deinit();

    // Test with empty data
    const result = analyzer.analyze(&[_]u8{});
    try std.testing.expectError(apk.ApkAnalyzer.AnalyzerError.InvalidArchive, result);

    // Test with non-ZIP data
    const result2 = analyzer.analyze("not a zip file");
    try std.testing.expectError(apk.ApkAnalyzer.AnalyzerError.InvalidArchive, result2);
}

test "ApkAnalyzer respects memory budget" {
    var analyzer = apk.ApkAnalyzer.init(std.testing.allocator, .{
        .max_memory = 100, // Very small budget
    });
    defer analyzer.deinit();

    // Create data larger than budget
    var large_data: [200]u8 = undefined;
    @memset(&large_data, 0);

    const result = analyzer.analyze(&large_data);
    try std.testing.expectError(apk.ApkAnalyzer.AnalyzerError.MemoryBudgetExceeded, result);
}

test "ApkAnalyzer with skip options" {
    var analyzer = apk.ApkAnalyzer.init(std.testing.allocator, .{
        .skip_dex_analysis = true,
        .skip_certificate = true,
    });
    defer analyzer.deinit();

    try std.testing.expect(analyzer.options.skip_dex_analysis);
    try std.testing.expect(analyzer.options.skip_certificate);
}

// Note: Full end-to-end tests with real APK/AAB files would require
// test data files in tests/testdata/. These tests verify the API
// structure and error handling paths.
