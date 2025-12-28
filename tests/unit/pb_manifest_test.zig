const std = @import("std");
const pb_manifest = @import("pb_manifest");
const PbManifestParser = pb_manifest.PbManifestParser;

// ============================================================================
// Permission Tests
// ============================================================================

test "Permission struct has name and maxSdkVersion" {
    const perm = PbManifestParser.Permission{
        .name = "android.permission.CAMERA",
        .max_sdk_version = 28,
    };
    try std.testing.expectEqualStrings("android.permission.CAMERA", perm.name);
    try std.testing.expectEqual(@as(?u32, 28), perm.max_sdk_version);
}

test "Permission struct without maxSdkVersion" {
    const perm = PbManifestParser.Permission{
        .name = "android.permission.INTERNET",
        .max_sdk_version = null,
    };
    try std.testing.expectEqualStrings("android.permission.INTERNET", perm.name);
    try std.testing.expectEqual(@as(?u32, null), perm.max_sdk_version);
}

// ============================================================================
// Feature Tests
// ============================================================================

test "Feature struct with required=true" {
    const feat = PbManifestParser.Feature{
        .name = "android.hardware.camera",
        .required = true,
    };
    try std.testing.expectEqualStrings("android.hardware.camera", feat.name);
    try std.testing.expect(feat.required);
}

test "Feature struct with required=false" {
    const feat = PbManifestParser.Feature{
        .name = "android.hardware.bluetooth",
        .required = false,
    };
    try std.testing.expectEqualStrings("android.hardware.bluetooth", feat.name);
    try std.testing.expect(!feat.required);
}

// ============================================================================
// ManifestMetadata Tests
// ============================================================================

test "ManifestMetadata contains all required fields" {
    const allocator = std.testing.allocator;

    // Create a parser with test data
    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "42"),
        .version_name = try allocator.dupe(u8, "1.2.3"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = try allocator.dupe(u8, "34"),
        .app_name = try allocator.dupe(u8, "My App"),
        .is_debuggable = true,
        .permissions = &[_]PbManifestParser.Permission{},
        .features = &[_]PbManifestParser.Feature{},
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        if (parser.target_sdk_version) |t| allocator.free(t);
        allocator.free(parser.app_name);
    }

    const metadata = parser.extractMetadata();

    try std.testing.expectEqualStrings("com.example.app", metadata.package_id);
    try std.testing.expectEqualStrings("42", metadata.version_code);
    try std.testing.expectEqualStrings("1.2.3", metadata.version_name);
    try std.testing.expectEqual(@as(u32, 21), metadata.min_sdk_version);
    try std.testing.expectEqual(@as(?u32, 34), metadata.target_sdk_version);
    try std.testing.expectEqualStrings("My App", metadata.app_name);
    try std.testing.expect(metadata.is_debuggable);
}

test "ManifestMetadata handles missing target SDK" {
    const allocator = std.testing.allocator;

    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "1"),
        .version_name = try allocator.dupe(u8, "1.0"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = null,
        .app_name = try allocator.dupe(u8, "App"),
        .is_debuggable = false,
        .permissions = &[_]PbManifestParser.Permission{},
        .features = &[_]PbManifestParser.Feature{},
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        allocator.free(parser.app_name);
    }

    const metadata = parser.extractMetadata();

    try std.testing.expectEqual(@as(?u32, null), metadata.target_sdk_version);
    try std.testing.expect(!metadata.is_debuggable);
}

// ============================================================================
// extractMetadata Tests with Permissions and Features
// ============================================================================

test "extractMetadata includes permissions with maxSdkVersion" {
    const allocator = std.testing.allocator;

    const permissions = [_]PbManifestParser.Permission{
        .{ .name = "android.permission.INTERNET", .max_sdk_version = null },
        .{ .name = "android.permission.CAMERA", .max_sdk_version = 28 },
        .{ .name = "android.permission.WRITE_EXTERNAL_STORAGE", .max_sdk_version = 29 },
    };

    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "1"),
        .version_name = try allocator.dupe(u8, "1.0"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = null,
        .app_name = try allocator.dupe(u8, "App"),
        .is_debuggable = false,
        .permissions = &permissions,
        .features = &[_]PbManifestParser.Feature{},
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        allocator.free(parser.app_name);
    }

    const metadata = parser.extractMetadata();

    try std.testing.expectEqual(@as(usize, 3), metadata.permissions.len);
    try std.testing.expectEqualStrings("android.permission.INTERNET", metadata.permissions[0].name);
    try std.testing.expectEqual(@as(?u32, null), metadata.permissions[0].max_sdk_version);
    try std.testing.expectEqualStrings("android.permission.CAMERA", metadata.permissions[1].name);
    try std.testing.expectEqual(@as(?u32, 28), metadata.permissions[1].max_sdk_version);
    try std.testing.expectEqualStrings("android.permission.WRITE_EXTERNAL_STORAGE", metadata.permissions[2].name);
    try std.testing.expectEqual(@as(?u32, 29), metadata.permissions[2].max_sdk_version);
}

test "extractMetadata includes features with required flag" {
    const allocator = std.testing.allocator;

    const features = [_]PbManifestParser.Feature{
        .{ .name = "android.hardware.camera", .required = true },
        .{ .name = "android.hardware.bluetooth", .required = false },
        .{ .name = "android.software.leanback", .required = true },
    };

    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "1"),
        .version_name = try allocator.dupe(u8, "1.0"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = null,
        .app_name = try allocator.dupe(u8, "App"),
        .is_debuggable = false,
        .permissions = &[_]PbManifestParser.Permission{},
        .features = &features,
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        allocator.free(parser.app_name);
    }

    const metadata = parser.extractMetadata();

    try std.testing.expectEqual(@as(usize, 3), metadata.features.len);
    try std.testing.expectEqualStrings("android.hardware.camera", metadata.features[0].name);
    try std.testing.expect(metadata.features[0].required);
    try std.testing.expectEqualStrings("android.hardware.bluetooth", metadata.features[1].name);
    try std.testing.expect(!metadata.features[1].required);
    try std.testing.expectEqualStrings("android.software.leanback", metadata.features[2].name);
    try std.testing.expect(metadata.features[2].required);
}

// ============================================================================
// Nested Message Handling Tests
// ============================================================================

test "parse handles empty data gracefully" {
    const allocator = std.testing.allocator;
    const empty_data: []const u8 = &[_]u8{};

    var parser = try PbManifestParser.parse(allocator, empty_data);
    defer parser.deinit();

    // Should return default values
    try std.testing.expectEqualStrings("", parser.package_id);
    try std.testing.expectEqualStrings("0", parser.version_code);
    try std.testing.expectEqualStrings("", parser.version_name);
    try std.testing.expectEqualStrings("1", parser.min_sdk_version);
    try std.testing.expectEqual(@as(?[]const u8, null), parser.target_sdk_version);
    try std.testing.expectEqualStrings("", parser.app_name);
    try std.testing.expect(!parser.is_debuggable);
    try std.testing.expectEqual(@as(usize, 0), parser.permissions.len);
    try std.testing.expectEqual(@as(usize, 0), parser.features.len);
}

test "parse handles minimal data" {
    const allocator = std.testing.allocator;
    const minimal_data = "short";

    var parser = try PbManifestParser.parse(allocator, minimal_data);
    defer parser.deinit();

    // Should return default values for minimal data
    try std.testing.expectEqualStrings("", parser.package_id);
}

test "parse extracts package from protobuf-like data" {
    const allocator = std.testing.allocator;

    // Simulate protobuf data with package name
    // Format: "package" keyword followed by length-prefixed string
    var data: [100]u8 = undefined;
    @memset(&data, 0);

    // Write "package" keyword
    @memcpy(data[0..7], "package");
    // Write length byte (15 for "com.example.app")
    data[10] = 15;
    // Write package name
    @memcpy(data[11..26], "com.example.app");

    var parser = try PbManifestParser.parse(allocator, &data);
    defer parser.deinit();

    try std.testing.expectEqualStrings("com.example.app", parser.package_id);
}

test "parse extracts permissions from data" {
    const allocator = std.testing.allocator;

    // Simulate data with permission string
    const data = "android.permission.INTERNET\x00android.permission.CAMERA";

    var parser = try PbManifestParser.parse(allocator, data);
    defer parser.deinit();

    try std.testing.expectEqual(@as(usize, 2), parser.permissions.len);
    try std.testing.expectEqualStrings("android.permission.INTERNET", parser.permissions[0].name);
    try std.testing.expectEqualStrings("android.permission.CAMERA", parser.permissions[1].name);
}

test "parse extracts features from data" {
    const allocator = std.testing.allocator;

    // Simulate data with feature strings
    const data = "android.hardware.camera\x00android.software.leanback";

    var parser = try PbManifestParser.parse(allocator, data);
    defer parser.deinit();

    try std.testing.expectEqual(@as(usize, 2), parser.features.len);
    try std.testing.expectEqualStrings("android.hardware.camera", parser.features[0].name);
    try std.testing.expectEqualStrings("android.software.leanback", parser.features[1].name);
}

test "parse deduplicates permissions" {
    const allocator = std.testing.allocator;

    // Simulate data with duplicate permission
    const data = "android.permission.INTERNET\x00android.permission.INTERNET";

    var parser = try PbManifestParser.parse(allocator, data);
    defer parser.deinit();

    // Should only have one permission (deduplicated)
    try std.testing.expectEqual(@as(usize, 1), parser.permissions.len);
    try std.testing.expectEqualStrings("android.permission.INTERNET", parser.permissions[0].name);
}

test "parse deduplicates features" {
    const allocator = std.testing.allocator;

    // Simulate data with duplicate feature
    const data = "android.hardware.camera\x00android.hardware.camera";

    var parser = try PbManifestParser.parse(allocator, data);
    defer parser.deinit();

    // Should only have one feature (deduplicated)
    try std.testing.expectEqual(@as(usize, 1), parser.features.len);
    try std.testing.expectEqualStrings("android.hardware.camera", parser.features[0].name);
}

// ============================================================================
// Helper Method Tests
// ============================================================================

test "getPermissionNames returns permission names" {
    const allocator = std.testing.allocator;

    const permissions = [_]PbManifestParser.Permission{
        .{ .name = "android.permission.INTERNET", .max_sdk_version = null },
        .{ .name = "android.permission.CAMERA", .max_sdk_version = 28 },
    };

    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "1"),
        .version_name = try allocator.dupe(u8, "1.0"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = null,
        .app_name = try allocator.dupe(u8, "App"),
        .is_debuggable = false,
        .permissions = &permissions,
        .features = &[_]PbManifestParser.Feature{},
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        allocator.free(parser.app_name);
    }

    const names = try parser.getPermissionNames(allocator);
    defer allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("android.permission.INTERNET", names[0]);
    try std.testing.expectEqualStrings("android.permission.CAMERA", names[1]);
}

test "getFeatureNames returns feature names" {
    const allocator = std.testing.allocator;

    const features = [_]PbManifestParser.Feature{
        .{ .name = "android.hardware.camera", .required = true },
        .{ .name = "android.hardware.bluetooth", .required = false },
    };

    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "1"),
        .version_name = try allocator.dupe(u8, "1.0"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = null,
        .app_name = try allocator.dupe(u8, "App"),
        .is_debuggable = false,
        .permissions = &[_]PbManifestParser.Permission{},
        .features = &features,
        .allocator = allocator,
    };
    defer {
        allocator.free(parser.package_id);
        allocator.free(parser.version_code);
        allocator.free(parser.version_name);
        allocator.free(parser.min_sdk_version);
        allocator.free(parser.app_name);
    }

    const names = try parser.getFeatureNames(allocator);
    defer allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);
    try std.testing.expectEqualStrings("android.hardware.camera", names[0]);
    try std.testing.expectEqualStrings("android.hardware.bluetooth", names[1]);
}
