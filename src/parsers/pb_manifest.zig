const std = @import("std");

/// Protobuf AndroidManifest Parser for Android App Bundle (AAB) - Optimized
/// AAB files store AndroidManifest.xml in protobuf format (AAPT2 compiled XML)
/// This parser extracts manifest data from the protobuf-encoded format
///
/// Key optimizations:
/// - Single-pass extraction for all fields
/// - Comptime lookup tables for O(1) character validation
/// - Pre-allocated buffers
/// - Early termination when all fields found
pub const PbManifestParser = struct {
    /// Package name (application ID)
    package_id: []const u8,
    /// Version code
    version_code: []const u8,
    /// Version name
    version_name: []const u8,
    /// Minimum SDK version
    min_sdk_version: []const u8,
    /// Target SDK version (optional)
    target_sdk_version: ?[]const u8,
    /// Application label/name
    app_name: []const u8,
    /// Is debuggable
    is_debuggable: bool,
    /// Permissions with maxSdkVersion support
    permissions: []const Permission,
    /// Features with required flag
    features: []const Feature,
    /// Allocator
    allocator: std.mem.Allocator,

    /// Permission with optional maxSdkVersion constraint
    pub const Permission = struct {
        name: []const u8,
        max_sdk_version: ?u32,
    };

    /// Feature with required flag
    pub const Feature = struct {
        name: []const u8,
        required: bool,
    };

    /// Manifest metadata for convenience extraction
    pub const ManifestMetadata = struct {
        package_id: []const u8,
        version_code: []const u8,
        version_name: []const u8,
        min_sdk_version: u32,
        target_sdk_version: ?u32,
        app_name: []const u8,
        is_debuggable: bool,
        permissions: []const Permission,
        features: []const Feature,
    };

    pub const ParseError = error{
        InvalidFormat,
        TruncatedData,
        OutOfMemory,
    };

    const log = std.log.scoped(.pb_manifest);

    /// Parse protobuf-encoded AndroidManifest from AAB - Single-pass optimized
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) ParseError!PbManifestParser {
        // Pre-allocate collections with reasonable capacity
        var permissions = std.ArrayListUnmanaged(Permission){};
        errdefer {
            for (permissions.items) |p| allocator.free(p.name);
            permissions.deinit(allocator);
        }
        try permissions.ensureTotalCapacity(allocator, 32);

        var features = std.ArrayListUnmanaged(Feature){};
        errdefer {
            for (features.items) |f| allocator.free(f.name);
            features.deinit(allocator);
        }
        try features.ensureTotalCapacity(allocator, 16);

        // Use hash sets for O(1) deduplication
        var seen_permissions = std.StringHashMap(void).init(allocator);
        defer seen_permissions.deinit();
        var seen_features = std.StringHashMap(void).init(allocator);
        defer seen_features.deinit();

        // Result fields - will be populated during single-pass scan
        var result = ExtractedFields{};

        // Single-pass extraction
        extractAllFieldsSinglePass(allocator, data, &result, &permissions, &features, &seen_permissions, &seen_features) catch {};

        // Log what we found
        if (result.package_id) |p| {
            log.debug("Found package: {s}", .{p});
        }
        if (result.version_code) |v| {
            log.debug("Found versionCode: {s}", .{v});
        }
        if (result.version_name) |v| {
            log.debug("Found versionName: {s}", .{v});
        }
        if (result.min_sdk) |m| {
            log.debug("Found minSdk: {s}", .{m});
        }
        if (result.target_sdk) |t| {
            log.debug("Found targetSdk: {s}", .{t});
        }

        return PbManifestParser{
            .package_id = result.package_id orelse allocator.dupe(u8, "") catch return ParseError.OutOfMemory,
            .version_code = result.version_code orelse allocator.dupe(u8, "0") catch return ParseError.OutOfMemory,
            .version_name = result.version_name orelse allocator.dupe(u8, "") catch return ParseError.OutOfMemory,
            .min_sdk_version = result.min_sdk orelse allocator.dupe(u8, "1") catch return ParseError.OutOfMemory,
            .target_sdk_version = result.target_sdk,
            .app_name = result.app_name orelse allocator.dupe(u8, "") catch return ParseError.OutOfMemory,
            .is_debuggable = result.is_debuggable,
            .permissions = permissions.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
            .features = features.toOwnedSlice(allocator) catch return ParseError.OutOfMemory,
            .allocator = allocator,
        };
    }

    /// Extract complete manifest metadata in one call
    /// This is a convenience method that returns all metadata in a structured format
    pub fn extractMetadata(self: *const PbManifestParser) ManifestMetadata {
        return ManifestMetadata{
            .package_id = self.package_id,
            .version_code = self.version_code,
            .version_name = self.version_name,
            .min_sdk_version = std.fmt.parseInt(u32, self.min_sdk_version, 10) catch 1,
            .target_sdk_version = if (self.target_sdk_version) |t|
                std.fmt.parseInt(u32, t, 10) catch null
            else
                null,
            .app_name = self.app_name,
            .is_debuggable = self.is_debuggable,
            .permissions = self.permissions,
            .features = self.features,
        };
    }

    /// Get all permissions as a simple string slice (for backward compatibility)
    pub fn getPermissionNames(self: *const PbManifestParser, allocator: std.mem.Allocator) ![]const []const u8 {
        var names = try allocator.alloc([]const u8, self.permissions.len);
        for (self.permissions, 0..) |perm, i| {
            names[i] = perm.name;
        }
        return names;
    }

    /// Get all feature names as a simple string slice (for backward compatibility)
    pub fn getFeatureNames(self: *const PbManifestParser, allocator: std.mem.Allocator) ![]const []const u8 {
        var names = try allocator.alloc([]const u8, self.features.len);
        for (self.features, 0..) |feat, i| {
            names[i] = feat.name;
        }
        return names;
    }

    pub fn deinit(self: *PbManifestParser) void {
        self.allocator.free(self.package_id);
        self.allocator.free(self.version_code);
        self.allocator.free(self.version_name);
        self.allocator.free(self.min_sdk_version);
        if (self.target_sdk_version) |t| self.allocator.free(t);
        self.allocator.free(self.app_name);
        for (self.permissions) |p| self.allocator.free(p.name);
        self.allocator.free(self.permissions);
        for (self.features) |f| self.allocator.free(f.name);
        self.allocator.free(self.features);
    }
};

/// Extracted fields during single-pass scan
const ExtractedFields = struct {
    package_id: ?[]u8 = null,
    version_code: ?[]u8 = null,
    version_name: ?[]u8 = null,
    min_sdk: ?[]u8 = null,
    target_sdk: ?[]u8 = null,
    app_name: ?[]u8 = null,
    is_debuggable: bool = false,
};

/// Single-pass extraction of all manifest fields
/// Scans data once and extracts all patterns in parallel
fn extractAllFieldsSinglePass(
    allocator: std.mem.Allocator,
    data: []const u8,
    result: *ExtractedFields,
    permissions: *std.ArrayListUnmanaged(PbManifestParser.Permission),
    features: *std.ArrayListUnmanaged(PbManifestParser.Feature),
    seen_permissions: *std.StringHashMap(void),
    seen_features: *std.StringHashMap(void),
) !void {
    if (data.len < 10) return;

    var i: usize = 0;
    const end = data.len;

    // Track what we've found to enable early termination
    var found_count: u8 = 0;
    const max_basic_fields: u8 = 6; // package, versionCode, versionName, minSdk, targetSdk, appName

    while (i < end) {
        const c = data[i];

        // Fast character dispatch based on first character
        switch (c) {
            'p' => {
                // Check for "package"
                if (result.package_id == null and i + 7 < end and
                    std.mem.eql(u8, data[i..][0..7], "package"))
                {
                    if (extractPackageNearby(allocator, data, i + 7)) |pkg| {
                        result.package_id = pkg;
                        found_count += 1;
                    }
                }
                i += 1;
            },
            'v' => {
                // Check for "versionCode" or "versionName"
                if (i + 11 < end) {
                    if (result.version_code == null and std.mem.eql(u8, data[i..][0..11], "versionCode")) {
                        if (extractVersionCodeNearby(allocator, data, i + 11)) |vc| {
                            result.version_code = vc;
                            found_count += 1;
                        }
                        i += 11;
                        continue;
                    }
                    if (result.version_name == null and std.mem.eql(u8, data[i..][0..11], "versionName")) {
                        if (extractVersionNameNearby(allocator, data, i + 11)) |vn| {
                            result.version_name = vn;
                            found_count += 1;
                        }
                        i += 11;
                        continue;
                    }
                }
                i += 1;
            },
            'm' => {
                // Check for "minSdkVersion" or "maxSdkVersion"
                if (result.min_sdk == null and i + 13 < end and
                    std.mem.eql(u8, data[i..][0..13], "minSdkVersion"))
                {
                    if (extractSdkNearby(allocator, data, i + 13)) |sdk| {
                        result.min_sdk = sdk;
                        found_count += 1;
                    }
                }
                i += 1;
            },
            't' => {
                // Check for "targetSdkVersion"
                if (result.target_sdk == null and i + 16 < end and
                    std.mem.eql(u8, data[i..][0..16], "targetSdkVersion"))
                {
                    if (extractSdkNearby(allocator, data, i + 16)) |sdk| {
                        result.target_sdk = sdk;
                        found_count += 1;
                    }
                }
                i += 1;
            },
            'd' => {
                // Check for "debuggable"
                if (i + 10 < end and std.mem.eql(u8, data[i..][0..10], "debuggable")) {
                    // Look for "true" or non-zero value nearby
                    if (extractDebuggableNearby(data, i + 10)) {
                        result.is_debuggable = true;
                    }
                }
                i += 1;
            },
            'l' => {
                // Check for "label" (application label)
                if (result.app_name == null and i + 5 < end and
                    std.mem.eql(u8, data[i..][0..5], "label"))
                {
                    if (extractLabelNearby(allocator, data, i + 5)) |label| {
                        result.app_name = label;
                        found_count += 1;
                    }
                }
                i += 1;
            },
            'a' => {
                // Check for "android.permission." or "android.hardware." or "android.software."
                if (i + 19 < end and data[i + 1] == 'n' and data[i + 2] == 'd') {
                    if (std.mem.eql(u8, data[i..][0..19], "android.permission.")) {
                        if (extractPermissionAt(allocator, data, i, seen_permissions)) |perm| {
                            permissions.appendAssumeCapacity(perm);
                        }
                    } else if (i + 17 < end and std.mem.eql(u8, data[i..][0..17], "android.hardware.")) {
                        if (extractFeatureAt(allocator, data, i, seen_features)) |feat| {
                            features.appendAssumeCapacity(feat);
                        }
                    } else if (i + 17 < end and std.mem.eql(u8, data[i..][0..17], "android.software.")) {
                        if (extractFeatureAt(allocator, data, i, seen_features)) |feat| {
                            features.appendAssumeCapacity(feat);
                        }
                    }
                }
                i += 1;
            },
            else => {
                // Check for length-prefixed package names (alternative detection)
                if (result.package_id == null and c > 10 and c < 80) {
                    const len = c;
                    if (i + 1 + len <= end) {
                        const potential = data[i + 1 .. i + 1 + len];
                        if (isValidPackageName(potential) and countDots(potential) >= 2) {
                            result.package_id = allocator.dupe(u8, potential) catch null;
                            if (result.package_id != null) found_count += 1;
                        }
                    }
                }
                i += 1;
            },
        }

        // Early termination if we found all basic fields
        // (permissions and features can continue to be collected)
        if (found_count >= max_basic_fields) {
            // Continue scanning for permissions and features only
            while (i < end) {
                if (data[i] == 'a' and i + 19 < end and data[i + 1] == 'n' and data[i + 2] == 'd') {
                    if (std.mem.eql(u8, data[i..][0..19], "android.permission.")) {
                        if (extractPermissionAt(allocator, data, i, seen_permissions)) |perm| {
                            try permissions.append(allocator, perm);
                        }
                    } else if (i + 17 < end) {
                        if (std.mem.eql(u8, data[i..][0..17], "android.hardware.") or
                            std.mem.eql(u8, data[i..][0..17], "android.software."))
                        {
                            if (extractFeatureAt(allocator, data, i, seen_features)) |feat| {
                                try features.append(allocator, feat);
                            }
                        }
                    }
                }
                i += 1;
            }
            break;
        }
    }
}

/// Extract package name near a "package" keyword
fn extractPackageNearby(allocator: std.mem.Allocator, data: []const u8, start: usize) ?[]u8 {
    const scan_limit = @min(start + 100, data.len);
    var j = start;
    while (j < scan_limit) {
        if (data[j] > 5 and data[j] < 100) {
            const potential_len = data[j];
            if (j + 1 + potential_len <= data.len) {
                const potential_pkg = data[j + 1 .. j + 1 + potential_len];
                if (isValidPackageName(potential_pkg)) {
                    return allocator.dupe(u8, potential_pkg) catch null;
                }
            }
        }
        j += 1;
    }
    return null;
}

/// Extract version code near a "versionCode" keyword
fn extractVersionCodeNearby(allocator: std.mem.Allocator, data: []const u8, start: usize) ?[]u8 {
    const scan_limit = @min(start + 30, data.len);
    var j = start;
    while (j < scan_limit) {
        // Check for digit string
        if (is_digit_lut[data[j]]) {
            var end_idx = j;
            while (end_idx < data.len and is_digit_lut[data[end_idx]]) {
                end_idx += 1;
            }
            if (end_idx > j and end_idx - j < 15) {
                return allocator.dupe(u8, data[j..end_idx]) catch null;
            }
        }
        // Check for varint
        if (data[j] > 0 and data[j] < 128) {
            if (j + 1 < data.len and data[j + 1] < 128 and data[j + 1] > 0) {
                const decoded = decodeVarint(data[j..@min(j + 5, data.len)]);
                if (decoded.value > 0 and decoded.value < 1000000000) {
                    return std.fmt.allocPrint(allocator, "{d}", .{decoded.value}) catch null;
                }
            }
        }
        j += 1;
    }
    return null;
}

/// Extract version name near a "versionName" keyword
fn extractVersionNameNearby(allocator: std.mem.Allocator, data: []const u8, start: usize) ?[]u8 {
    const scan_limit = @min(start + 50, data.len);
    var j = start;
    while (j < scan_limit) {
        if (data[j] > 0 and data[j] < 50) {
            const len = data[j];
            if (j + 1 + len <= data.len) {
                const potential = data[j + 1 .. j + 1 + len];
                if (isValidVersionName(potential)) {
                    return allocator.dupe(u8, potential) catch null;
                }
            }
        }
        j += 1;
    }
    return null;
}

/// Extract SDK version near a keyword
fn extractSdkNearby(allocator: std.mem.Allocator, data: []const u8, start: usize) ?[]u8 {
    const scan_limit = @min(start + 20, data.len);
    var j = start;
    while (j < scan_limit) {
        // SDK versions are typically 1-35
        if (data[j] >= '0' and data[j] <= '9') {
            var end_idx = j;
            while (end_idx < data.len and data[end_idx] >= '0' and data[end_idx] <= '9') {
                end_idx += 1;
            }
            if (end_idx > j and end_idx - j <= 2) {
                const val = std.fmt.parseInt(u32, data[j..end_idx], 10) catch {
                    j += 1;
                    continue;
                };
                if (val >= 1 and val <= 50) {
                    return allocator.dupe(u8, data[j..end_idx]) catch null;
                }
            }
        }
        // Check for varint encoding
        if (data[j] >= 1 and data[j] <= 50) {
            const next_is_continuation = j + 1 < data.len and (data[j + 1] & 0x80) != 0;
            if (!next_is_continuation) {
                return std.fmt.allocPrint(allocator, "{d}", .{data[j]}) catch null;
            }
        }
        j += 1;
    }
    return null;
}

/// Extract debuggable flag near a "debuggable" keyword
fn extractDebuggableNearby(data: []const u8, start: usize) bool {
    const scan_limit = @min(start + 20, data.len);
    var j = start;
    while (j < scan_limit) {
        // Check for "true" string
        if (j + 4 <= data.len and std.mem.eql(u8, data[j..][0..4], "true")) {
            return true;
        }
        // Check for non-zero byte (boolean true in protobuf)
        if (data[j] == 1) {
            return true;
        }
        j += 1;
    }
    return false;
}

/// Extract application label near a "label" keyword
fn extractLabelNearby(allocator: std.mem.Allocator, data: []const u8, start: usize) ?[]u8 {
    const scan_limit = @min(start + 100, data.len);
    var j = start;
    while (j < scan_limit) {
        // Look for length-prefixed string
        if (data[j] > 0 and data[j] < 100) {
            const len = data[j];
            if (j + 1 + len <= data.len) {
                const potential = data[j + 1 .. j + 1 + len];
                if (isValidLabel(potential)) {
                    return allocator.dupe(u8, potential) catch null;
                }
            }
        }
        j += 1;
    }
    return null;
}

/// Extract permission at position with maxSdkVersion support
fn extractPermissionAt(
    allocator: std.mem.Allocator,
    data: []const u8,
    start: usize,
    seen: *std.StringHashMap(void),
) ?PbManifestParser.Permission {
    var end_idx = start + 19; // After "android.permission."
    while (end_idx < data.len and permission_char_lut[data[end_idx]]) {
        end_idx += 1;
    }
    if (end_idx > start + 19) {
        const perm_name = data[start..end_idx];
        if (!seen.contains(perm_name)) {
            const duped = allocator.dupe(u8, perm_name) catch return null;
            seen.put(duped, {}) catch {
                allocator.free(duped);
                return null;
            };

            // Try to extract maxSdkVersion nearby
            const max_sdk = extractMaxSdkVersionNearby(data, end_idx);

            return .{
                .name = duped,
                .max_sdk_version = max_sdk,
            };
        }
    }
    return null;
}

/// Extract maxSdkVersion value near a permission
fn extractMaxSdkVersionNearby(data: []const u8, start: usize) ?u32 {
    const scan_limit = @min(start + 50, data.len);
    var j = start;

    // Look for "maxSdkVersion" keyword
    while (j + 13 < scan_limit) {
        if (std.mem.eql(u8, data[j..][0..13], "maxSdkVersion")) {
            // Found maxSdkVersion, now extract the value
            var k = j + 13;
            while (k < @min(j + 30, data.len)) {
                // Check for digit string
                if (data[k] >= '0' and data[k] <= '9') {
                    var end_idx = k;
                    while (end_idx < data.len and data[end_idx] >= '0' and data[end_idx] <= '9') {
                        end_idx += 1;
                    }
                    if (end_idx > k and end_idx - k <= 2) {
                        return std.fmt.parseInt(u32, data[k..end_idx], 10) catch null;
                    }
                }
                // Check for varint encoding
                if (data[k] >= 1 and data[k] <= 50) {
                    const next_is_continuation = k + 1 < data.len and (data[k + 1] & 0x80) != 0;
                    if (!next_is_continuation) {
                        return data[k];
                    }
                }
                k += 1;
            }
        }
        j += 1;
    }
    return null;
}

/// Extract feature at position with required flag
fn extractFeatureAt(
    allocator: std.mem.Allocator,
    data: []const u8,
    start: usize,
    seen: *std.StringHashMap(void),
) ?PbManifestParser.Feature {
    // Determine prefix length (hardware or software)
    const prefix_len: usize = if (data.len > start + 17 and std.mem.eql(u8, data[start..][0..17], "android.hardware."))
        17
    else if (data.len > start + 17 and std.mem.eql(u8, data[start..][0..17], "android.software."))
        17
    else
        return null;

    var end_idx = start + prefix_len;
    while (end_idx < data.len and feature_char_lut[data[end_idx]]) {
        end_idx += 1;
    }
    if (end_idx > start + prefix_len) {
        const feat_name = data[start..end_idx];
        if (!seen.contains(feat_name)) {
            const duped = allocator.dupe(u8, feat_name) catch return null;
            seen.put(duped, {}) catch {
                allocator.free(duped);
                return null;
            };

            // Try to extract required flag nearby (default to true)
            const required = extractRequiredFlagNearby(data, end_idx);

            return .{
                .name = duped,
                .required = required,
            };
        }
    }
    return null;
}

/// Extract required flag near a feature
fn extractRequiredFlagNearby(data: []const u8, start: usize) bool {
    const scan_limit = @min(start + 50, data.len);
    var j = start;

    // Look for "required" keyword
    while (j + 8 < scan_limit) {
        if (std.mem.eql(u8, data[j..][0..8], "required")) {
            // Found required, now extract the value
            var k = j + 8;
            while (k < @min(j + 20, data.len)) {
                // Check for "false" string
                if (k + 5 <= data.len and std.mem.eql(u8, data[k..][0..5], "false")) {
                    return false;
                }
                // Check for "true" string
                if (k + 4 <= data.len and std.mem.eql(u8, data[k..][0..4], "true")) {
                    return true;
                }
                // Check for boolean byte (0 = false, 1 = true)
                if (data[k] == 0) {
                    return false;
                }
                if (data[k] == 1) {
                    return true;
                }
                k += 1;
            }
        }
        j += 1;
    }
    // Default to true if not found (Android default)
    return true;
}

/// Count dots in a string
fn countDots(s: []const u8) usize {
    var count: usize = 0;
    for (s) |c| {
        if (c == '.') count += 1;
    }
    return count;
}

/// Comptime lookup table for valid package name characters
const package_char_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('a'..'z' + 1) |c| lut[c] = true;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    for ('0'..'9' + 1) |c| lut[c] = true;
    lut['_'] = true;
    lut['.'] = true;
    break :blk lut;
};

/// Comptime lookup table for digits
const is_digit_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('0'..'9' + 1) |c| lut[c] = true;
    break :blk lut;
};

/// Comptime lookup table for valid version name characters
const version_char_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('0'..'9' + 1) |c| lut[c] = true;
    for ('a'..'z' + 1) |c| lut[c] = true;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    lut['.'] = true;
    lut['-'] = true;
    lut['_'] = true;
    lut[' '] = true;
    break :blk lut;
};

/// Lookup table for permission characters (A-Z, a-z, _, .)
const permission_char_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    for ('a'..'z' + 1) |c| lut[c] = true;
    lut['_'] = true;
    lut['.'] = true;
    break :blk lut;
};

/// Lookup table for feature characters (a-z, A-Z, _, .)
const feature_char_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('a'..'z' + 1) |c| lut[c] = true;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    lut['_'] = true;
    lut['.'] = true;
    break :blk lut;
};

/// Lookup table for valid label characters
const label_char_lut = blk: {
    var lut: [256]bool = [_]bool{false} ** 256;
    for ('a'..'z' + 1) |c| lut[c] = true;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    for ('0'..'9' + 1) |c| lut[c] = true;
    lut[' '] = true;
    lut['-'] = true;
    lut['_'] = true;
    lut['.'] = true;
    lut['!'] = true;
    lut['@'] = true;
    lut['#'] = true;
    lut['$'] = true;
    lut['%'] = true;
    lut['&'] = true;
    lut['('] = true;
    lut[')'] = true;
    lut['+'] = true;
    lut['='] = true;
    lut[':'] = true;
    lut[';'] = true;
    lut[','] = true;
    lut['\''] = true;
    lut['"'] = true;
    break :blk lut;
};

/// Check if string looks like a valid Android package name
fn isValidPackageName(s: []const u8) bool {
    if (s.len < 3) return false;

    var has_dot = false;
    var prev_was_dot = true; // Treat start as "after dot" to catch leading dot

    for (s) |c| {
        if (!package_char_lut[c]) return false;

        if (c == '.') {
            if (prev_was_dot) return false; // Consecutive dots or leading dot
            has_dot = true;
            prev_was_dot = true;
        } else {
            prev_was_dot = false;
        }
    }

    // Can't end with dot
    if (prev_was_dot) return false;

    return has_dot;
}

/// Check if string looks like a valid version name
fn isValidVersionName(s: []const u8) bool {
    if (s.len == 0 or s.len > 30) return false;

    var has_digit = false;
    for (s) |c| {
        if (!version_char_lut[c]) return false;
        if (is_digit_lut[c]) has_digit = true;
    }

    return has_digit;
}

/// Check if string looks like a valid application label
fn isValidLabel(s: []const u8) bool {
    if (s.len == 0 or s.len > 80) return false;

    var has_letter = false;
    for (s) |c| {
        if (!label_char_lut[c]) return false;
        if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')) has_letter = true;
    }

    return has_letter;
}

/// Decode a varint from data
fn decodeVarint(data: []const u8) struct { value: u64, bytes: usize } {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes: usize = 0;

    for (data) |byte| {
        bytes += 1;
        result |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) break;
        shift +|= 7;
        if (shift >= 64) break;
    }

    return .{ .value = result, .bytes = bytes };
}

// Unit tests
test "isValidPackageName" {
    try std.testing.expect(isValidPackageName("com.example.app"));
    try std.testing.expect(isValidPackageName("com.example.myapp123"));
    try std.testing.expect(!isValidPackageName("com"));
    try std.testing.expect(!isValidPackageName(""));
    try std.testing.expect(!isValidPackageName(".com.example"));
    try std.testing.expect(!isValidPackageName("com.example."));
}

test "isValidVersionName" {
    try std.testing.expect(isValidVersionName("1.0.0"));
    try std.testing.expect(isValidVersionName("1.2.3-beta"));
    try std.testing.expect(isValidVersionName("2.0"));
    try std.testing.expect(!isValidVersionName(""));
    try std.testing.expect(!isValidVersionName("abc"));
}

test "isValidLabel" {
    try std.testing.expect(isValidLabel("My App"));
    try std.testing.expect(isValidLabel("App123"));
    try std.testing.expect(isValidLabel("My-App_Name"));
    try std.testing.expect(!isValidLabel(""));
    try std.testing.expect(!isValidLabel("123"));
}

test "decodeVarint" {
    const data1 = [_]u8{0x01};
    const result1 = decodeVarint(&data1);
    try std.testing.expectEqual(@as(u64, 1), result1.value);

    const data2 = [_]u8{ 0xAC, 0x02 };
    const result2 = decodeVarint(&data2);
    try std.testing.expectEqual(@as(u64, 300), result2.value);
}

test "PbManifestParser.extractMetadata returns correct structure" {
    const allocator = std.testing.allocator;

    // Create a minimal parser with test data
    var parser = PbManifestParser{
        .package_id = try allocator.dupe(u8, "com.example.app"),
        .version_code = try allocator.dupe(u8, "42"),
        .version_name = try allocator.dupe(u8, "1.2.3"),
        .min_sdk_version = try allocator.dupe(u8, "21"),
        .target_sdk_version = try allocator.dupe(u8, "34"),
        .app_name = try allocator.dupe(u8, "My App"),
        .is_debuggable = true,
        .permissions = &[_]PbManifestParser.Permission{
            .{ .name = "android.permission.INTERNET", .max_sdk_version = null },
            .{ .name = "android.permission.CAMERA", .max_sdk_version = 28 },
        },
        .features = &[_]PbManifestParser.Feature{
            .{ .name = "android.hardware.camera", .required = true },
            .{ .name = "android.hardware.bluetooth", .required = false },
        },
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
    try std.testing.expectEqual(@as(usize, 2), metadata.permissions.len);
    try std.testing.expectEqual(@as(usize, 2), metadata.features.len);
}

test "Permission struct has maxSdkVersion" {
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

test "Feature struct with required flag" {
    const feat_required = PbManifestParser.Feature{
        .name = "android.hardware.camera",
        .required = true,
    };
    try std.testing.expectEqualStrings("android.hardware.camera", feat_required.name);
    try std.testing.expect(feat_required.required);

    const feat_optional = PbManifestParser.Feature{
        .name = "android.hardware.bluetooth",
        .required = false,
    };
    try std.testing.expectEqualStrings("android.hardware.bluetooth", feat_optional.name);
    try std.testing.expect(!feat_optional.required);
}

test "extractDebuggableNearby finds true" {
    const data_true = "debuggabletrue";
    try std.testing.expect(extractDebuggableNearby(data_true, 10));

    const data_byte = "debuggable\x01";
    try std.testing.expect(extractDebuggableNearby(data_byte, 10));
}

test "extractDebuggableNearby returns false when not found" {
    const data_false = "debuggablefalse";
    try std.testing.expect(!extractDebuggableNearby(data_false, 10));

    const data_zero = "debuggable\x00";
    try std.testing.expect(!extractDebuggableNearby(data_zero, 10));
}

test "extractRequiredFlagNearby finds false" {
    const data_false = "featurerequiredfalse";
    try std.testing.expect(!extractRequiredFlagNearby(data_false, 7));
}

test "extractRequiredFlagNearby defaults to true" {
    const data_no_required = "featurename";
    try std.testing.expect(extractRequiredFlagNearby(data_no_required, 7));
}
