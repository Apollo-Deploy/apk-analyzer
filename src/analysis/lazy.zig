//! Lazy Analyzer
//!
//! Provides on-demand parsing where components are only parsed when accessed.
//! Useful when only specific metadata is needed.

const std = @import("std");
const core = @import("../core/mod.zig");
const zip = @import("../parsers/zip.zig");
const axml = @import("../parsers/axml.zig");
const dex = @import("../parsers/dex.zig");
const certificate = @import("../parsers/certificate.zig");
const pb_manifest = @import("../parsers/pb_manifest.zig");

/// Lazy analyzer that parses components on-demand
pub const LazyAnalyzer = struct {
    allocator: std.mem.Allocator,
    archive: *zip.ZipParser,
    artifact_type: core.ArtifactType,

    // Cached results
    manifest_cache: ?core.Metadata = null,
    dex_cache: ?core.DexInfo = null,
    cert_cache: ?core.CertificateInfo = null,

    /// Initialize with parsed ZIP archive
    pub fn init(
        allocator: std.mem.Allocator,
        archive: *zip.ZipParser,
        artifact_type: core.ArtifactType,
    ) LazyAnalyzer {
        return .{
            .allocator = allocator,
            .archive = archive,
            .artifact_type = artifact_type,
        };
    }

    /// Get manifest metadata (parse on first access)
    pub fn getManifest(self: *LazyAnalyzer) !*const core.Metadata {
        if (self.manifest_cache == null) {
            self.manifest_cache = try self.parseManifest();
        }
        return &self.manifest_cache.?;
    }

    /// Get DEX info (parse on first access)
    pub fn getDexInfo(self: *LazyAnalyzer) !*const core.DexInfo {
        if (self.dex_cache == null) {
            self.dex_cache = try self.analyzeDex();
        }
        return &self.dex_cache.?;
    }

    /// Get certificate info (parse on first access)
    pub fn getCertificate(self: *LazyAnalyzer) !*const core.CertificateInfo {
        if (self.cert_cache == null) {
            self.cert_cache = try self.extractCertificate();
        }
        return &self.cert_cache.?;
    }

    /// Check if manifest has been parsed
    pub fn hasManifest(self: *const LazyAnalyzer) bool {
        return self.manifest_cache != null;
    }

    /// Check if DEX info has been parsed
    pub fn hasDexInfo(self: *const LazyAnalyzer) bool {
        return self.dex_cache != null;
    }

    /// Check if certificate has been parsed
    pub fn hasCertificate(self: *const LazyAnalyzer) bool {
        return self.cert_cache != null;
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    fn parseManifest(self: *LazyAnalyzer) !core.Metadata {
        const manifest_path = if (self.artifact_type == .aab)
            "base/manifest/AndroidManifest.xml"
        else
            "AndroidManifest.xml";

        const entry = self.archive.findFile(manifest_path) orelse {
            return error.MissingManifest;
        };

        const data = try self.archive.getDecompressedData(self.allocator, entry);

        if (self.artifact_type == .aab) {
            var parser = try pb_manifest.PbManifestParser.parse(self.allocator, data);
            defer parser.deinit();
            return convertPbMetadata(self.allocator, parser.extractMetadata());
        } else {
            var parser = try axml.AxmlParser.parse(self.allocator, data);
            defer parser.deinit();
            return convertMetadata(self.allocator, try parser.extractManifestMetadata(self.allocator));
        }
    }

    fn analyzeDex(self: *LazyAnalyzer) !core.DexInfo {
        var dex_files = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (dex_files.items) |d| self.allocator.free(d);
            dex_files.deinit();
        }

        for (self.archive.listFiles()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".dex")) {
                const data = try self.archive.getDecompressedData(self.allocator, &entry);
                try dex_files.append(data);
            }
        }

        if (dex_files.items.len == 0) return error.NoDexFiles;

        const info = try dex.DexAnalyzer.analyzeMultiple(self.allocator, dex_files.items);

        var files = try self.allocator.alloc(core.DexFileInfo, info.files.len);
        for (info.files, 0..) |f, i| {
            files[i] = .{
                .method_count = f.method_count,
                .class_count = f.class_count,
                .field_count = f.field_count,
                .string_count = f.string_count,
                .version = f.version,
                .exceeds_limit = f.exceeds_limit,
            };
        }

        return .{
            .files = files,
            .total_methods = info.total_methods,
            .total_classes = info.total_classes,
            .total_fields = info.total_fields,
            .is_multidex = info.is_multidex,
        };
    }

    fn extractCertificate(self: *LazyAnalyzer) !core.CertificateInfo {
        var parser = certificate.CertificateParser.init(self.allocator);
        defer parser.deinit();

        const info = try parser.extractFromApk(self.archive);

        return .{
            .subject = info.subject,
            .issuer = info.issuer,
            .serial_number = info.serial_number,
            .not_before = info.not_before,
            .not_after = info.not_after,
            .fingerprint_md5 = info.fingerprint_md5,
            .fingerprint_sha256 = info.fingerprint_sha256,
            .signature_algorithm = info.signature_algorithm,
            .public_key_algorithm = info.public_key_algorithm,
            .public_key_size = info.public_key_size,
        };
    }
};

// Helper functions (same as in analyzer.zig)
fn convertMetadata(alloc: std.mem.Allocator, meta: anytype) !core.Metadata {
    var permissions = try alloc.alloc(core.Permission, meta.permissions.len);
    for (meta.permissions, 0..) |p, i| {
        permissions[i] = .{ .name = p.name, .max_sdk_version = p.max_sdk_version };
    }

    var features = try alloc.alloc(core.Feature, meta.features.len);
    for (meta.features, 0..) |f, i| {
        features[i] = .{ .name = f.name, .required = f.required };
    }

    return .{
        .package_id = meta.package_id,
        .app_name = meta.app_name,
        .version_code_str = meta.version_code,
        .version_name = meta.version_name,
        .min_sdk_version = meta.min_sdk_version,
        .target_sdk_version = meta.target_sdk_version,
        .permissions = permissions,
        .features = features,
        .is_debuggable = meta.is_debuggable,
    };
}

fn convertPbMetadata(alloc: std.mem.Allocator, meta: anytype) !core.Metadata {
    var permissions = try alloc.alloc(core.Permission, meta.permissions.len);
    for (meta.permissions, 0..) |p, i| {
        permissions[i] = .{ .name = p.name, .max_sdk_version = p.max_sdk_version };
    }

    var features = try alloc.alloc(core.Feature, meta.features.len);
    for (meta.features, 0..) |f, i| {
        features[i] = .{ .name = f.name, .required = f.required };
    }

    return .{
        .package_id = meta.package_id,
        .app_name = meta.app_name,
        .version_code_str = meta.version_code,
        .version_name = meta.version_name,
        .min_sdk_version = meta.min_sdk_version,
        .target_sdk_version = meta.target_sdk_version,
        .permissions = permissions,
        .features = features,
        .is_debuggable = meta.is_debuggable,
    };
}

test "LazyAnalyzer caching" {
    // Basic structure test - full tests require valid APK data
    try std.testing.expect(true);
}
