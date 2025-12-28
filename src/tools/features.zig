//! Feature Analyzer
//!
//! Analyzes features used by an APK that trigger Play Store filtering.
//! Supports both explicitly declared features and implied features from permissions.
//!
//! ## Play Store Filtering
//!
//! The Play Store uses features to filter which devices can install an app.
//! Features can be:
//! - Explicitly declared via `<uses-feature>` in AndroidManifest.xml
//! - Implied by permissions (e.g., CAMERA permission implies camera feature)
//!
//! ## Usage
//!
//! ```zig
//! const features = @import("features.zig");
//!
//! var analyzer = features.FeatureAnalyzer.init(allocator);
//! defer analyzer.deinit();
//!
//! const result = try analyzer.analyze(apk_data, .{ .include_not_required = true });
//!
//! for (result.features) |feature| {
//!     std.debug.print("{s}", .{feature.name});
//!     if (feature.implied_by) |perm| {
//!         std.debug.print(" implied: requested {s} permission", .{perm});
//!     }
//!     std.debug.print("\n", .{});
//! }
//! ```

const std = @import("std");
const zip = @import("../parsers/zip.zig");
const axml = @import("../parsers/axml.zig");
const pb_manifest = @import("../parsers/pb_manifest.zig");

/// A feature that triggers Play Store filtering
pub const FilteringFeature = struct {
    /// Feature name (e.g., "android.hardware.camera")
    name: []const u8,
    /// Whether the feature is required (true) or optional (false)
    required: bool,
    /// If implied, the permission that implies this feature
    implied_by: ?[]const u8,
    /// GL ES version requirement (if applicable)
    gl_es_version: ?u32,
};

/// Feature analysis result
pub const FeatureAnalysisResult = struct {
    /// All features that trigger Play Store filtering
    features: []FilteringFeature,
    /// Required GL ES version (0 if not specified)
    gl_es_version: u32,
    /// Allocator for cleanup
    allocator: std.mem.Allocator,

    pub fn deinit(self: *FeatureAnalysisResult) void {
        self.allocator.free(self.features);
    }
};

/// Options for feature analysis
pub const FeatureAnalysisOptions = struct {
    /// Include features marked as not required (android:required="false")
    include_not_required: bool = false,
};

/// Analyzes features used by an APK
pub const FeatureAnalyzer = struct {
    allocator: std.mem.Allocator,

    /// Permission to implied feature mapping
    /// Based on Android documentation for implicit feature requirements
    const PERMISSION_FEATURE_MAP = [_]struct {
        permission: []const u8,
        feature: []const u8,
    }{
        // Camera permissions
        .{ .permission = "android.permission.CAMERA", .feature = "android.hardware.camera" },
        // Audio permissions
        .{ .permission = "android.permission.RECORD_AUDIO", .feature = "android.hardware.microphone" },
        // Location permissions
        .{ .permission = "android.permission.ACCESS_FINE_LOCATION", .feature = "android.hardware.location.gps" },
        .{ .permission = "android.permission.ACCESS_COARSE_LOCATION", .feature = "android.hardware.location.network" },
        .{ .permission = "android.permission.ACCESS_MOCK_LOCATION", .feature = "android.hardware.location" },
        // Bluetooth permissions
        .{ .permission = "android.permission.BLUETOOTH", .feature = "android.hardware.bluetooth" },
        .{ .permission = "android.permission.BLUETOOTH_ADMIN", .feature = "android.hardware.bluetooth" },
        // Telephony permissions
        .{ .permission = "android.permission.CALL_PHONE", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.CALL_PRIVILEGED", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.MODIFY_PHONE_STATE", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.PROCESS_OUTGOING_CALLS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.READ_SMS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.RECEIVE_SMS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.RECEIVE_MMS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.RECEIVE_WAP_PUSH", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.SEND_SMS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.WRITE_APN_SETTINGS", .feature = "android.hardware.telephony" },
        .{ .permission = "android.permission.WRITE_SMS", .feature = "android.hardware.telephony" },
        // WiFi permissions
        .{ .permission = "android.permission.ACCESS_WIFI_STATE", .feature = "android.hardware.wifi" },
        .{ .permission = "android.permission.CHANGE_WIFI_STATE", .feature = "android.hardware.wifi" },
        .{ .permission = "android.permission.CHANGE_WIFI_MULTICAST_STATE", .feature = "android.hardware.wifi" },
        // NFC permissions
        .{ .permission = "android.permission.NFC", .feature = "android.hardware.nfc" },
        // Sensor permissions (implicit)
        .{ .permission = "android.permission.BODY_SENSORS", .feature = "android.hardware.sensor.heartrate" },
    };

    pub fn init(allocator: std.mem.Allocator) FeatureAnalyzer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FeatureAnalyzer) void {
        _ = self;
    }

    /// Analyze features from APK data
    pub fn analyze(self: *FeatureAnalyzer, data: []const u8, options: FeatureAnalysisOptions) !FeatureAnalysisResult {
        // Parse ZIP archive
        var archive = zip.ZipParser.parse(self.allocator, data) catch {
            return error.InvalidArchive;
        };
        defer archive.deinit();

        return self.analyzeFromArchive(&archive, options);
    }

    /// Analyze features from file path
    pub fn analyzeFile(self: *FeatureAnalyzer, path: []const u8, options: FeatureAnalysisOptions) !FeatureAnalysisResult {
        const file = std.fs.cwd().openFile(path, .{}) catch {
            return error.FileNotFound;
        };
        defer file.close();

        const data = file.readToEndAlloc(self.allocator, 200 * 1024 * 1024) catch {
            return error.OutOfMemory;
        };
        defer self.allocator.free(data);

        return self.analyze(data, options);
    }

    /// Internal analysis from parsed archive
    fn analyzeFromArchive(self: *FeatureAnalyzer, archive: *zip.ZipParser, options: FeatureAnalysisOptions) !FeatureAnalysisResult {
        // Detect artifact type and parse manifest
        const is_aab = archive.findFile("base/manifest/AndroidManifest.xml") != null;

        // Build feature list
        var features = std.ArrayListUnmanaged(FilteringFeature){};
        errdefer features.deinit(self.allocator);

        // Track which features we've already added (to avoid duplicates)
        var seen_features = std.StringHashMap(void).init(self.allocator);
        defer seen_features.deinit();

        var gl_es_version: u32 = 0;

        if (is_aab) {
            // Parse AAB protobuf manifest
            const manifest_entry = archive.findFile("base/manifest/AndroidManifest.xml") orelse {
                return error.MissingManifest;
            };

            const manifest_data = archive.getDecompressedData(self.allocator, manifest_entry) catch {
                return error.InvalidManifest;
            };
            defer self.allocator.free(manifest_data);

            var parser = pb_manifest.PbManifestParser.parse(self.allocator, manifest_data) catch {
                return error.InvalidManifest;
            };
            defer parser.deinit();

            const metadata = parser.extractMetadata();

            // Add declared features from protobuf manifest
            for (metadata.features) |feat| {
                if (!options.include_not_required and !feat.required) {
                    continue;
                }

                try seen_features.put(feat.name, {});
                try features.append(self.allocator, .{
                    .name = feat.name,
                    .required = feat.required,
                    .implied_by = null,
                    .gl_es_version = null,
                });
            }

            // Add implied features from permissions
            for (metadata.permissions) |perm| {
                for (PERMISSION_FEATURE_MAP) |mapping| {
                    if (std.mem.eql(u8, perm.name, mapping.permission)) {
                        // Check if this feature was already declared
                        if (!seen_features.contains(mapping.feature)) {
                            try seen_features.put(mapping.feature, {});
                            try features.append(self.allocator, .{
                                .name = mapping.feature,
                                .required = true, // Implied features are always required
                                .implied_by = perm.name,
                                .gl_es_version = null,
                            });
                        }
                    }
                }
            }
        } else {
            // Parse APK binary XML manifest
            const manifest_entry = archive.findFile("AndroidManifest.xml") orelse {
                return error.MissingManifest;
            };

            const manifest_data = archive.getDecompressedData(self.allocator, manifest_entry) catch {
                return error.InvalidManifest;
            };
            defer self.allocator.free(manifest_data);

            var parser = axml.AxmlParser.parse(self.allocator, manifest_data) catch {
                return error.InvalidManifest;
            };
            defer parser.deinit();

            const metadata = parser.extractManifestMetadata(self.allocator) catch {
                return error.OutOfMemory;
            };

            // Add declared features from AXML manifest
            for (metadata.features) |feat| {
                if (!options.include_not_required and !feat.required) {
                    continue;
                }

                try seen_features.put(feat.name, {});
                try features.append(self.allocator, .{
                    .name = feat.name,
                    .required = feat.required,
                    .implied_by = null,
                    .gl_es_version = null,
                });
            }

            // Add implied features from permissions
            for (metadata.permissions) |perm| {
                for (PERMISSION_FEATURE_MAP) |mapping| {
                    if (std.mem.eql(u8, perm.name, mapping.permission)) {
                        // Check if this feature was already declared
                        if (!seen_features.contains(mapping.feature)) {
                            try seen_features.put(mapping.feature, {});
                            try features.append(self.allocator, .{
                                .name = mapping.feature,
                                .required = true, // Implied features are always required
                                .implied_by = perm.name,
                                .gl_es_version = null,
                            });
                        }
                    }
                }
            }

            // Extract GL ES version from uses-feature with glEsVersion attribute
            gl_es_version = self.extractGlEsVersion(&parser);
        }

        return FeatureAnalysisResult{
            .features = try features.toOwnedSlice(self.allocator),
            .gl_es_version = gl_es_version,
            .allocator = self.allocator,
        };
    }

    /// Extract GL ES version from manifest
    fn extractGlEsVersion(self: *FeatureAnalyzer, parser: *axml.AxmlParser) u32 {
        _ = self;
        // Look for uses-feature with glEsVersion attribute
        for (parser.elements) |*elem| {
            if (std.mem.eql(u8, elem.name, "uses-feature")) {
                for (elem.attributes) |*attr| {
                    if (std.mem.eql(u8, attr.name, "glEsVersion")) {
                        // GL ES version is encoded as 0xMMMMmmmm where M=major, m=minor
                        return std.fmt.parseInt(u32, attr.value, 0) catch 0;
                    }
                }
            }
        }
        return 0;
    }

    /// Format GL ES version as human-readable string (e.g., "3.2")
    pub fn formatGlEsVersion(version: u32) [8]u8 {
        var buf: [8]u8 = undefined;
        @memset(&buf, 0);

        if (version == 0) {
            return buf;
        }

        const major = (version >> 16) & 0xFFFF;
        const minor = version & 0xFFFF;

        _ = std.fmt.bufPrint(&buf, "{d}.{d}", .{ major, minor }) catch {};
        return buf;
    }

    /// Write features to writer in apkanalyzer-compatible format
    pub fn writeFeatures(
        features: []const FilteringFeature,
        writer: anytype,
        include_not_required: bool,
    ) !void {
        for (features) |feature| {
            if (!include_not_required and !feature.required) {
                continue;
            }

            try writer.writeAll(feature.name);

            if (!feature.required) {
                try writer.writeAll(" not-required");
            }

            try writer.writeAll("\n");

            if (feature.implied_by) |perm| {
                try writer.writeAll("implied: requested ");
                try writer.writeAll(perm);
                try writer.writeAll(" permission\n");
            }
        }
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "FeatureAnalyzer.formatGlEsVersion formats version correctly" {
    // GL ES 3.2 = 0x00030002
    const version = FeatureAnalyzer.formatGlEsVersion(0x00030002);
    try std.testing.expect(std.mem.indexOf(u8, &version, "3.2") != null);
}

test "FeatureAnalyzer.formatGlEsVersion handles zero" {
    const version = FeatureAnalyzer.formatGlEsVersion(0);
    try std.testing.expectEqual(@as(u8, 0), version[0]);
}

test "PERMISSION_FEATURE_MAP contains camera mapping" {
    var found = false;
    for (FeatureAnalyzer.PERMISSION_FEATURE_MAP) |mapping| {
        if (std.mem.eql(u8, mapping.permission, "android.permission.CAMERA")) {
            try std.testing.expectEqualStrings("android.hardware.camera", mapping.feature);
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "PERMISSION_FEATURE_MAP contains microphone mapping" {
    var found = false;
    for (FeatureAnalyzer.PERMISSION_FEATURE_MAP) |mapping| {
        if (std.mem.eql(u8, mapping.permission, "android.permission.RECORD_AUDIO")) {
            try std.testing.expectEqualStrings("android.hardware.microphone", mapping.feature);
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}
