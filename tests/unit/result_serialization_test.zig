//! Comprehensive serialization tests for AnalysisResult
//!
//! Tests JSON output format and validates the structure matches requirements.
//! Uses the reflection-based JSON serializer from output/json.zig

const std = @import("std");
const apk = @import("apk-analyzer");
const json = apk.json;

const AnalysisResult = apk.AnalysisResult;
const AnalysisResultJson = apk.AnalysisResultJson;
const Permission = apk.Permission;
const Feature = apk.Feature;

test "AnalysisResult JSON contains all required top-level fields" {
    var result = AnalysisResult{};
    result.artifact_type = .apk;
    result.metadata.package_id = "com.example.test";
    result.metadata.app_name = "Test App";
    result.metadata.version_code = 1;
    result.metadata.version_code_str = "1";
    result.metadata.version_name = "1.0.0";
    result.metadata.min_sdk_version = 21;
    result.compressed_size = 1000000;
    result.uncompressed_size = 2000000;

    // Convert to JSON view
    const json_view = try AnalysisResultJson.fromResult(&result, std.testing.allocator);

    var buffer: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try json.serializeCompact(stream.writer(), json_view);

    const output = stream.getWritten();

    // Verify all required top-level fields are present
    const required_fields = [_][]const u8{
        "artifact_type",
        "package_id",
        "app_name",
        "version_code",
        "version_name",
        "min_sdk_version",
        "permissions",
        "features",
        "compressed_size",
        "uncompressed_size",
    };

    for (required_fields) |field| {
        const field_with_quotes = try std.fmt.allocPrint(std.testing.allocator, "\"{s}\":", .{field});
        defer std.testing.allocator.free(field_with_quotes);
        try std.testing.expect(std.mem.indexOf(u8, output, field_with_quotes) != null);
    }
}

test "AnalysisResult JSON with permissions array" {
    var result = AnalysisResult{};

    const perms = [_]Permission{
        .{ .name = "android.permission.INTERNET", .max_sdk_version = null },
        .{ .name = "android.permission.CAMERA", .max_sdk_version = 28 },
    };

    result.metadata.package_id = "com.test";
    result.metadata.app_name = "Test";
    result.metadata.version_code = 1;
    result.metadata.version_code_str = "1";
    result.metadata.version_name = "1.0";
    result.metadata.min_sdk_version = 21;
    result.metadata.permissions = &perms;

    const json_view = try AnalysisResultJson.fromResult(&result, std.testing.allocator);

    var buffer: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try json.serializeCompact(stream.writer(), json_view);

    const output = stream.getWritten();

    // Verify permissions array is present and formatted correctly
    try std.testing.expect(std.mem.indexOf(u8, output, "\"permissions\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"android.permission.INTERNET\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"android.permission.CAMERA\"") != null);
}

test "AnalysisResult JSON with features array" {
    var result = AnalysisResult{};

    const features = [_]Feature{
        .{ .name = "android.hardware.camera", .required = true },
        .{ .name = "android.hardware.bluetooth", .required = false },
    };

    result.metadata.package_id = "com.test";
    result.metadata.app_name = "Test";
    result.metadata.version_code = 1;
    result.metadata.version_code_str = "1";
    result.metadata.version_name = "1.0";
    result.metadata.min_sdk_version = 21;
    result.metadata.features = &features;

    const json_view = try AnalysisResultJson.fromResult(&result, std.testing.allocator);

    var buffer: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try json.serializeCompact(stream.writer(), json_view);

    const output = stream.getWritten();

    // Verify features array is present and formatted correctly
    try std.testing.expect(std.mem.indexOf(u8, output, "\"features\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"android.hardware.camera\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"android.hardware.bluetooth\"") != null);
}

test "AnalysisResult JSON produces valid structure" {
    var result = AnalysisResult{};
    result.metadata.package_id = "com.test";
    result.metadata.app_name = "Test";
    result.metadata.version_code = 1;
    result.metadata.version_code_str = "1";
    result.metadata.version_name = "1.0";
    result.metadata.min_sdk_version = 21;

    const json_view = try AnalysisResultJson.fromResult(&result, std.testing.allocator);

    var buffer: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try json.serializeCompact(stream.writer(), json_view);

    const output = stream.getWritten();

    // Verify it's valid JSON structure
    try std.testing.expect(output[0] == '{');
    try std.testing.expect(output[output.len - 1] == '}');
}

test "AnalysisResult with owned arena" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    var result = AnalysisResult.initOwned(arena);
    defer result.deinit();

    result.metadata.package_id = "com.test";
    result.metadata.app_name = "Test";

    // Verify we can get the allocator
    const alloc = result.getAllocator();
    try std.testing.expect(alloc != null);
}
