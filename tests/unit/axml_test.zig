const std = @import("std");
const apk = @import("apk-analyzer");
const AxmlParser = apk.AxmlParser;

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a mock AxmlParser with predefined elements for testing
fn createMockParser(allocator: std.mem.Allocator, elements: []const AxmlParser.XmlElement) AxmlParser {
    return AxmlParser{
        .elements = elements,
        .string_pool = &.{},
        .allocator = allocator,
        .arena = null,
    };
}

// ============================================================================
// InstallLocation Tests
// ============================================================================

test "InstallLocation.fromString parses auto correctly" {
    try std.testing.expectEqual(AxmlParser.InstallLocation.auto, AxmlParser.InstallLocation.fromString("0"));
    try std.testing.expectEqual(AxmlParser.InstallLocation.auto, AxmlParser.InstallLocation.fromString("auto"));
    try std.testing.expectEqual(AxmlParser.InstallLocation.auto, AxmlParser.InstallLocation.fromString("unknown"));
}

test "InstallLocation.fromString parses internalOnly correctly" {
    try std.testing.expectEqual(AxmlParser.InstallLocation.internal_only, AxmlParser.InstallLocation.fromString("1"));
    try std.testing.expectEqual(AxmlParser.InstallLocation.internal_only, AxmlParser.InstallLocation.fromString("internalOnly"));
}

test "InstallLocation.fromString parses preferExternal correctly" {
    try std.testing.expectEqual(AxmlParser.InstallLocation.prefer_external, AxmlParser.InstallLocation.fromString("2"));
    try std.testing.expectEqual(AxmlParser.InstallLocation.prefer_external, AxmlParser.InstallLocation.fromString("preferExternal"));
}

// ============================================================================
// Manifest Metadata Extraction Tests
// ============================================================================

test "extractManifestMetadata extracts package name" {
    const allocator = std.testing.allocator;

    const manifest_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "package", .namespace = "", .value = "com.example.app", .value_type = .string },
        .{ .name = "versionCode", .namespace = "android", .value = "42", .value_type = .int_dec },
        .{ .name = "versionName", .namespace = "android", .value = "1.2.3", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &manifest_attrs, .depth = 0 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);

    try std.testing.expectEqualStrings("com.example.app", metadata.package_id);
    try std.testing.expectEqualStrings("42", metadata.version_code);
    try std.testing.expectEqualStrings("1.2.3", metadata.version_name);
}

test "extractManifestMetadata extracts SDK versions" {
    const allocator = std.testing.allocator;

    const sdk_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "minSdkVersion", .namespace = "android", .value = "21", .value_type = .int_dec },
        .{ .name = "targetSdkVersion", .namespace = "android", .value = "34", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-sdk", .namespace = "", .attributes = &sdk_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);

    try std.testing.expectEqual(@as(u32, 21), metadata.min_sdk_version);
    try std.testing.expectEqual(@as(?u32, 34), metadata.target_sdk_version);
}

test "extractManifestMetadata extracts debuggable flag" {
    const allocator = std.testing.allocator;

    const app_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "debuggable", .namespace = "android", .value = "true", .value_type = .int_boolean },
        .{ .name = "label", .namespace = "android", .value = "My App", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &app_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);

    try std.testing.expect(metadata.is_debuggable);
    try std.testing.expectEqualStrings("My App", metadata.app_name);
}

test "extractManifestMetadata extracts install location" {
    const allocator = std.testing.allocator;

    const manifest_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "package", .namespace = "", .value = "com.example.app", .value_type = .string },
        .{ .name = "installLocation", .namespace = "android", .value = "2", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &manifest_attrs, .depth = 0 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);

    try std.testing.expectEqual(AxmlParser.InstallLocation.prefer_external, metadata.install_location);
}

test "extractManifestMetadata extracts permissions with maxSdkVersion" {
    const allocator = std.testing.allocator;

    const perm1_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.permission.INTERNET", .value_type = .string },
    };

    const perm2_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.permission.CAMERA", .value_type = .string },
        .{ .name = "maxSdkVersion", .namespace = "android", .value = "28", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-permission", .namespace = "", .attributes = &perm1_attrs, .depth = 1 },
        .{ .name = "uses-permission", .namespace = "", .attributes = &perm2_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);
    defer allocator.free(metadata.permissions);

    try std.testing.expectEqual(@as(usize, 2), metadata.permissions.len);
    try std.testing.expectEqualStrings("android.permission.INTERNET", metadata.permissions[0].name);
    try std.testing.expectEqual(@as(?u32, null), metadata.permissions[0].max_sdk_version);
    try std.testing.expectEqualStrings("android.permission.CAMERA", metadata.permissions[1].name);
    try std.testing.expectEqual(@as(?u32, 28), metadata.permissions[1].max_sdk_version);
}

test "extractManifestMetadata extracts features" {
    const allocator = std.testing.allocator;

    const feat1_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.hardware.camera", .value_type = .string },
        .{ .name = "required", .namespace = "android", .value = "true", .value_type = .int_boolean },
    };

    const feat2_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.hardware.bluetooth", .value_type = .string },
        .{ .name = "required", .namespace = "android", .value = "false", .value_type = .int_boolean },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-feature", .namespace = "", .attributes = &feat1_attrs, .depth = 1 },
        .{ .name = "uses-feature", .namespace = "", .attributes = &feat2_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const metadata = try parser.extractManifestMetadata(allocator);
    defer allocator.free(metadata.features);

    try std.testing.expectEqual(@as(usize, 2), metadata.features.len);
    try std.testing.expectEqualStrings("android.hardware.camera", metadata.features[0].name);
    try std.testing.expect(metadata.features[0].required);
    try std.testing.expectEqualStrings("android.hardware.bluetooth", metadata.features[1].name);
    try std.testing.expect(!metadata.features[1].required);
}

// ============================================================================
// Component Extraction Tests
// ============================================================================

test "getActivities extracts activity components" {
    const allocator = std.testing.allocator;

    const activity_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = ".MainActivity", .value_type = .string },
        .{ .name = "exported", .namespace = "android", .value = "true", .value_type = .int_boolean },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &.{}, .depth = 1 },
        .{ .name = "activity", .namespace = "", .attributes = &activity_attrs, .depth = 2 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const activities = try parser.getActivities(allocator);
    defer allocator.free(activities);

    try std.testing.expectEqual(@as(usize, 1), activities.len);
    try std.testing.expectEqualStrings(".MainActivity", activities[0].name);
    try std.testing.expectEqual(@as(?bool, true), activities[0].exported);
    try std.testing.expect(activities[0].enabled);
}

test "getServices extracts service components" {
    const allocator = std.testing.allocator;

    const service_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = ".MyService", .value_type = .string },
        .{ .name = "enabled", .namespace = "android", .value = "false", .value_type = .int_boolean },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &.{}, .depth = 1 },
        .{ .name = "service", .namespace = "", .attributes = &service_attrs, .depth = 2 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const services = try parser.getServices(allocator);
    defer allocator.free(services);

    try std.testing.expectEqual(@as(usize, 1), services.len);
    try std.testing.expectEqualStrings(".MyService", services[0].name);
    try std.testing.expect(!services[0].enabled);
}

test "getReceivers extracts receiver components" {
    const allocator = std.testing.allocator;

    const receiver_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = ".MyReceiver", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &.{}, .depth = 1 },
        .{ .name = "receiver", .namespace = "", .attributes = &receiver_attrs, .depth = 2 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const receivers = try parser.getReceivers(allocator);
    defer allocator.free(receivers);

    try std.testing.expectEqual(@as(usize, 1), receivers.len);
    try std.testing.expectEqualStrings(".MyReceiver", receivers[0].name);
    try std.testing.expectEqual(@as(?bool, null), receivers[0].exported);
    try std.testing.expect(receivers[0].enabled);
}

test "getActivities extracts intent filters" {
    const allocator = std.testing.allocator;

    const activity_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = ".MainActivity", .value_type = .string },
    };

    const action_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.intent.action.MAIN", .value_type = .string },
    };

    const category_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.intent.category.LAUNCHER", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &.{}, .depth = 1 },
        .{ .name = "activity", .namespace = "", .attributes = &activity_attrs, .depth = 2 },
        .{ .name = "intent-filter", .namespace = "", .attributes = &.{}, .depth = 3 },
        .{ .name = "action", .namespace = "", .attributes = &action_attrs, .depth = 4 },
        .{ .name = "category", .namespace = "", .attributes = &category_attrs, .depth = 4 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const activities = try parser.getActivities(allocator);
    defer {
        for (activities) |activity| {
            for (activity.intent_filters) |filter| {
                allocator.free(filter.actions);
                allocator.free(filter.categories);
                allocator.free(filter.data_schemes);
            }
            allocator.free(activity.intent_filters);
        }
        allocator.free(activities);
    }

    try std.testing.expectEqual(@as(usize, 1), activities.len);
    try std.testing.expectEqual(@as(usize, 1), activities[0].intent_filters.len);

    const filter = activities[0].intent_filters[0];
    try std.testing.expectEqual(@as(usize, 1), filter.actions.len);
    try std.testing.expectEqualStrings("android.intent.action.MAIN", filter.actions[0]);
    try std.testing.expectEqual(@as(usize, 1), filter.categories.len);
    try std.testing.expectEqualStrings("android.intent.category.LAUNCHER", filter.categories[0]);
}

// ============================================================================
// Helper Method Tests
// ============================================================================

test "isDebuggable returns true for debuggable app" {
    const allocator = std.testing.allocator;

    const app_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "debuggable", .namespace = "android", .value = "true", .value_type = .int_boolean },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &app_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    try std.testing.expect(parser.isDebuggable());
}

test "isDebuggable returns false for non-debuggable app" {
    const allocator = std.testing.allocator;

    const app_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "debuggable", .namespace = "android", .value = "false", .value_type = .int_boolean },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &app_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    try std.testing.expect(!parser.isDebuggable());
}

test "getAppLabel returns application label" {
    const allocator = std.testing.allocator;

    const app_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "label", .namespace = "android", .value = "My Awesome App", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "application", .namespace = "", .attributes = &app_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const label = parser.getAppLabel();
    try std.testing.expect(label != null);
    try std.testing.expectEqualStrings("My Awesome App", label.?);
}

test "getPackageName returns package name" {
    const allocator = std.testing.allocator;

    const manifest_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "package", .namespace = "", .value = "com.example.myapp", .value_type = .string },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &manifest_attrs, .depth = 0 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const pkg = parser.getPackageName();
    try std.testing.expect(pkg != null);
    try std.testing.expectEqualStrings("com.example.myapp", pkg.?);
}

test "getMinSdkVersion returns minimum SDK version" {
    const allocator = std.testing.allocator;

    const sdk_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "minSdkVersion", .namespace = "android", .value = "21", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-sdk", .namespace = "", .attributes = &sdk_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const min_sdk = parser.getMinSdkVersion();
    try std.testing.expect(min_sdk != null);
    try std.testing.expectEqual(@as(u32, 21), min_sdk.?);
}

test "getTargetSdkVersion returns target SDK version" {
    const allocator = std.testing.allocator;

    const sdk_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "targetSdkVersion", .namespace = "android", .value = "34", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-sdk", .namespace = "", .attributes = &sdk_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const target_sdk = parser.getTargetSdkVersion();
    try std.testing.expect(target_sdk != null);
    try std.testing.expectEqual(@as(u32, 34), target_sdk.?);
}

test "getInstallLocation returns correct location" {
    const allocator = std.testing.allocator;

    const manifest_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "installLocation", .namespace = "android", .value = "1", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &manifest_attrs, .depth = 0 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    try std.testing.expectEqual(AxmlParser.InstallLocation.internal_only, parser.getInstallLocation());
}

test "getPermissionsWithSdk extracts permissions with SDK constraints" {
    const allocator = std.testing.allocator;

    const perm_attrs = [_]AxmlParser.XmlAttribute{
        .{ .name = "name", .namespace = "android", .value = "android.permission.WRITE_EXTERNAL_STORAGE", .value_type = .string },
        .{ .name = "maxSdkVersion", .namespace = "android", .value = "29", .value_type = .int_dec },
    };

    const elements = [_]AxmlParser.XmlElement{
        .{ .name = "manifest", .namespace = "", .attributes = &.{}, .depth = 0 },
        .{ .name = "uses-permission", .namespace = "", .attributes = &perm_attrs, .depth = 1 },
    };

    var parser = createMockParser(allocator, &elements);
    defer parser.deinit();

    const permissions = try parser.getPermissionsWithSdk(allocator);
    defer allocator.free(permissions);

    try std.testing.expectEqual(@as(usize, 1), permissions.len);
    try std.testing.expectEqualStrings("android.permission.WRITE_EXTERNAL_STORAGE", permissions[0].name);
    try std.testing.expectEqual(@as(?u32, 29), permissions[0].max_sdk_version);
}
