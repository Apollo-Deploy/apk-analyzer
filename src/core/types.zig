//! Core Domain Types
//!
//! Defines all domain types used throughout the APK analyzer.
//! These types are the single source of truth - parsers return these
//! types directly, eliminating the need for type conversions.
//!
//! Design Principles:
//! - Domain types store raw data, not formatted representations
//! - JSON serialization is handled by output/json.zig via reflection
//! - Memory ownership is explicit via initOwned/deinit pattern
//! - No circular dependencies with other modules

const std = @import("std");

// ============================================================================
// Artifact Types
// ============================================================================

/// Artifact type (APK or AAB)
pub const ArtifactType = enum {
    apk,
    aab,

    pub fn toString(self: ArtifactType) []const u8 {
        return switch (self) {
            .apk => "apk",
            .aab => "aab",
        };
    }

    pub fn fromExtension(ext: []const u8) ?ArtifactType {
        if (std.ascii.eqlIgnoreCase(ext, ".apk")) return .apk;
        if (std.ascii.eqlIgnoreCase(ext, ".aab")) return .aab;
        return null;
    }
};

/// Install location preference from manifest
pub const InstallLocation = enum(u8) {
    auto = 0,
    internal_only = 1,
    prefer_external = 2,

    pub fn toString(self: InstallLocation) []const u8 {
        return switch (self) {
            .auto => "auto",
            .internal_only => "internalOnly",
            .prefer_external => "preferExternal",
        };
    }

    pub fn fromValue(value: u32) InstallLocation {
        return switch (value) {
            1 => .internal_only,
            2 => .prefer_external,
            else => .auto,
        };
    }
};

// ============================================================================
// Manifest Types
// ============================================================================

/// Android permission with optional SDK constraint
pub const Permission = struct {
    /// Permission name (e.g., "android.permission.INTERNET")
    name: []const u8,
    /// Maximum SDK version this permission applies to (null = all versions)
    max_sdk_version: ?u32 = null,
};

/// Hardware/software feature requirement
pub const Feature = struct {
    /// Feature name (e.g., "android.hardware.camera")
    name: []const u8,
    /// Whether the feature is required (true) or optional (false)
    required: bool = true,
};

/// Core metadata extracted from AndroidManifest.xml
pub const Metadata = struct {
    /// Package identifier (e.g., "com.example.app")
    package_id: []const u8 = "",
    /// Application display name
    app_name: []const u8 = "",
    /// Version code (integer)
    version_code: u32 = 0,
    /// Version code as string (for display, supports large values)
    version_code_str: []const u8 = "",
    /// Version name (human-readable version string)
    version_name: []const u8 = "",
    /// Minimum SDK version required
    min_sdk_version: u32 = 1,
    /// Target SDK version (null if not specified)
    target_sdk_version: ?u32 = null,
    /// Install location preference
    install_location: InstallLocation = .auto,
    /// Declared permissions
    permissions: []const Permission = &.{},
    /// Declared features
    features: []const Feature = &.{},
    /// Whether the app is debuggable
    is_debuggable: bool = false,
};

// ============================================================================
// Size Analysis Types
// ============================================================================

/// Category size with percentage
pub const CategorySize = struct {
    size: u64 = 0,
    percentage: f32 = 0,
};

/// File size breakdown by category
pub const SizeBreakdown = struct {
    /// DEX files
    dex: CategorySize = .{},
    /// Resources (resources.arsc, res/)
    resources: CategorySize = .{},
    /// Native libraries (lib/)
    native: CategorySize = .{},
    /// Assets (assets/)
    assets: CategorySize = .{},
    /// Other files
    other: CategorySize = .{},

    /// Calculate percentages from sizes and total
    pub fn calculatePercentages(self: *SizeBreakdown, total: u64) void {
        if (total == 0) return;
        const total_f: f32 = @floatFromInt(total);
        self.dex.percentage = @as(f32, @floatFromInt(self.dex.size)) / total_f * 100.0;
        self.resources.percentage = @as(f32, @floatFromInt(self.resources.size)) / total_f * 100.0;
        self.native.percentage = @as(f32, @floatFromInt(self.native.size)) / total_f * 100.0;
        self.assets.percentage = @as(f32, @floatFromInt(self.assets.size)) / total_f * 100.0;
        self.other.percentage = @as(f32, @floatFromInt(self.other.size)) / total_f * 100.0;
    }
};

// ============================================================================
// Download Size Estimation Types
// ============================================================================

/// Estimated download size breakdown by category
pub const DownloadSizeBreakdown = struct {
    dex: u64 = 0,
    native: u64 = 0,
    resources: u64 = 0,
    assets: u64 = 0,
    other: u64 = 0,
};

/// Estimated Play Store download size
/// Uses empirical Brotli compression factors to estimate actual download size
pub const DownloadSizeEstimate = struct {
    /// Estimated download size in bytes (Play Store serves with Brotli)
    download_size: u64 = 0,
    /// Original APK file size in bytes
    file_size: u64 = 0,
    /// Estimated compression ratio (0.0 - 1.0)
    compression_ratio: f32 = 0,
    /// Detailed breakdown by component
    breakdown: DownloadSizeBreakdown = .{},
};

// ============================================================================
// Certificate Types
// ============================================================================

/// Certificate information extracted from APK signing
/// Stores raw fingerprint bytes - formatting is done at serialization time
pub const CertificateInfo = struct {
    /// Subject distinguished name
    subject: []const u8 = "",
    /// Issuer distinguished name
    issuer: []const u8 = "",
    /// Serial number as hex string
    serial_number: []const u8 = "",
    /// Validity start time (Unix timestamp)
    not_before: i64 = 0,
    /// Validity end time (Unix timestamp)
    not_after: i64 = 0,
    /// MD5 fingerprint (16 bytes, raw)
    fingerprint_md5: [16]u8 = [_]u8{0} ** 16,
    /// SHA-256 fingerprint (32 bytes, raw)
    fingerprint_sha256: [32]u8 = [_]u8{0} ** 32,
    /// Signature algorithm name
    signature_algorithm: []const u8 = "",
    /// Public key algorithm
    public_key_algorithm: []const u8 = "",
    /// Public key size in bits
    public_key_size: u32 = 0,

    /// Format MD5 fingerprint as colon-separated hex string
    pub fn formatMd5Fingerprint(self: *const CertificateInfo, buf: []u8) []const u8 {
        return formatFingerprint(&self.fingerprint_md5, buf);
    }

    /// Format SHA-256 fingerprint as colon-separated hex string
    pub fn formatSha256Fingerprint(self: *const CertificateInfo, buf: []u8) []const u8 {
        return formatFingerprint(&self.fingerprint_sha256, buf);
    }
};

/// Format a fingerprint as colon-separated hex (e.g., "AB:CD:EF:...")
fn formatFingerprint(fingerprint: []const u8, buf: []u8) []const u8 {
    const hex_chars = "0123456789ABCDEF";
    var pos: usize = 0;

    for (fingerprint, 0..) |byte, i| {
        if (i > 0 and pos < buf.len) {
            buf[pos] = ':';
            pos += 1;
        }
        if (pos + 2 <= buf.len) {
            buf[pos] = hex_chars[byte >> 4];
            buf[pos + 1] = hex_chars[byte & 0x0F];
            pos += 2;
        }
    }

    return buf[0..pos];
}

// ============================================================================
// DEX Analysis Types
// ============================================================================

/// Information about a single DEX file
pub const DexFileInfo = struct {
    /// Total number of method references
    method_count: u32 = 0,
    /// Total number of class definitions
    class_count: u32 = 0,
    /// Total number of field references
    field_count: u32 = 0,
    /// Total number of strings
    string_count: u32 = 0,
    /// DEX version string (e.g., "035" or "039")
    version: [3]u8 = [_]u8{ '0', '3', '5' },
    /// Whether method count exceeds 65536 limit
    exceeds_limit: bool = false,
};

/// Aggregate DEX analysis result
pub const DexInfo = struct {
    /// Information for each DEX file
    files: []const DexFileInfo = &.{},
    /// Total methods across all DEX files
    total_methods: u64 = 0,
    /// Total classes across all DEX files
    total_classes: u64 = 0,
    /// Total fields across all DEX files
    total_fields: u64 = 0,
    /// Whether this is a multidex APK
    is_multidex: bool = false,
};

// ============================================================================
// Native Library Types
// ============================================================================

/// Native library information
pub const NativeLibraries = struct {
    /// Supported ABIs (e.g., "arm64-v8a", "armeabi-v7a")
    architectures: []const []const u8 = &.{},
    /// Total size of native libraries in bytes
    total_size: u64 = 0,
};

// ============================================================================
// AAB Split Types
// ============================================================================

/// Split dimension for AAB
pub const SplitDimension = enum {
    abi,
    screen_density,
    language,
    texture_compression,
    device_tier,

    pub fn toString(self: SplitDimension) []const u8 {
        return switch (self) {
            .abi => "abi",
            .screen_density => "screenDensity",
            .language => "language",
            .texture_compression => "textureCompression",
            .device_tier => "deviceTier",
        };
    }

    pub fn fromString(s: []const u8) ?SplitDimension {
        const map = std.StaticStringMap(SplitDimension).initComptime(.{
            .{ "ABI", .abi },
            .{ "abi", .abi },
            .{ "SCREEN_DENSITY", .screen_density },
            .{ "screenDensity", .screen_density },
            .{ "LANGUAGE", .language },
            .{ "language", .language },
            .{ "TEXTURE_COMPRESSION_FORMAT", .texture_compression },
            .{ "textureCompression", .texture_compression },
            .{ "DEVICE_TIER", .device_tier },
            .{ "deviceTier", .device_tier },
        });
        return map.get(s);
    }
};

/// Split configuration for AAB
pub const SplitConfig = struct {
    /// Split dimension type
    dimension: SplitDimension,
    /// Available values for this dimension
    values: []const []const u8 = &.{},
};

// ============================================================================
// Diagnostic Types (Local POD - No Circular Dependencies)
// ============================================================================

/// Diagnostic severity level
pub const DiagnosticSeverity = enum {
    info,
    warning,
    @"error",

    pub fn toString(self: DiagnosticSeverity) []const u8 {
        return switch (self) {
            .info => "info",
            .warning => "warning",
            .@"error" => "error",
        };
    }
};

/// Diagnostic code for programmatic handling
pub const DiagnosticCode = enum {
    manifest_parse_failed,
    manifest_missing_package,
    manifest_invalid_version,
    dex_analysis_failed,
    dex_method_limit_exceeded,
    dex_invalid_header,
    certificate_extraction_failed,
    certificate_expired,
    certificate_not_yet_valid,
    resources_parse_failed,
    resources_invalid_string_pool,
    native_analysis_failed,
    native_unsupported_abi,
    unknown_error,

    pub fn toString(self: DiagnosticCode) []const u8 {
        return switch (self) {
            .manifest_parse_failed => "MANIFEST_PARSE_FAILED",
            .manifest_missing_package => "MANIFEST_MISSING_PACKAGE",
            .manifest_invalid_version => "MANIFEST_INVALID_VERSION",
            .dex_analysis_failed => "DEX_ANALYSIS_FAILED",
            .dex_method_limit_exceeded => "DEX_METHOD_LIMIT_EXCEEDED",
            .dex_invalid_header => "DEX_INVALID_HEADER",
            .certificate_extraction_failed => "CERT_EXTRACTION_FAILED",
            .certificate_expired => "CERT_EXPIRED",
            .certificate_not_yet_valid => "CERT_NOT_YET_VALID",
            .resources_parse_failed => "RESOURCES_PARSE_FAILED",
            .resources_invalid_string_pool => "RESOURCES_INVALID_STRING_POOL",
            .native_analysis_failed => "NATIVE_ANALYSIS_FAILED",
            .native_unsupported_abi => "NATIVE_UNSUPPORTED_ABI",
            .unknown_error => "UNKNOWN_ERROR",
        };
    }
};

/// Diagnostic warning or error (POD struct for serialization)
/// This is a simplified version decoupled from errors.zig to avoid circular deps
pub const Diagnostic = struct {
    /// Diagnostic code for programmatic handling
    code: DiagnosticCode,
    /// Human-readable message
    message: []const u8,
    /// Severity level
    severity: DiagnosticSeverity,

    /// Create a warning diagnostic
    pub fn warning(code: DiagnosticCode, message: []const u8) Diagnostic {
        return .{ .code = code, .message = message, .severity = .warning };
    }

    /// Create an error diagnostic
    pub fn err(code: DiagnosticCode, message: []const u8) Diagnostic {
        return .{ .code = code, .message = message, .severity = .@"error" };
    }
};

// ============================================================================
// Analysis Result
// ============================================================================

/// Complete analysis result
///
/// Memory Ownership:
/// - Use `initOwned(arena)` when the result owns its memory
/// - Call `deinit()` to release owned memory
/// - Use default initialization `AnalysisResult{}` for stack-allocated results
pub const AnalysisResult = struct {
    /// Artifact type (APK or AAB)
    artifact_type: ArtifactType = .apk,
    /// Core metadata from manifest
    metadata: Metadata = .{},
    /// File size breakdown by category
    size_breakdown: SizeBreakdown = .{},
    /// Compressed file size in bytes
    compressed_size: u64 = 0,
    /// Uncompressed file size in bytes
    uncompressed_size: u64 = 0,
    /// Estimated Play Store download size (null if not calculated)
    download_size: ?DownloadSizeEstimate = null,
    /// Certificate information (null if not available)
    certificate: ?CertificateInfo = null,
    /// DEX analysis information (null if not available)
    dex_info: ?DexInfo = null,
    /// Native library information
    native_libs: NativeLibraries = .{},
    /// Split configurations (AAB only)
    split_configs: ?[]const SplitConfig = null,
    /// Diagnostic warnings encountered during analysis
    diagnostics: []const Diagnostic = &.{},

    // Memory management (internal)
    _arena: ?std.heap.ArenaAllocator = null,

    /// Initialize with owned arena allocator
    /// The result takes ownership of the arena and will free it on deinit
    pub fn initOwned(arena: std.heap.ArenaAllocator) AnalysisResult {
        return .{
            ._arena = arena,
        };
    }

    /// Release all allocated memory
    pub fn deinit(self: *AnalysisResult) void {
        if (self._arena) |*arena| {
            arena.deinit();
            self._arena = null;
        }
    }

    /// Get the arena allocator (for adding data during analysis)
    pub fn getAllocator(self: *AnalysisResult) ?std.mem.Allocator {
        if (self._arena) |*arena| {
            return arena.allocator();
        }
        return null;
    }

    /// Check if this result has any errors
    pub fn hasErrors(self: *const AnalysisResult) bool {
        for (self.diagnostics) |d| {
            if (d.severity == .@"error") return true;
        }
        return false;
    }

    /// Check if this result has any warnings
    pub fn hasWarnings(self: *const AnalysisResult) bool {
        for (self.diagnostics) |d| {
            if (d.severity == .warning) return true;
        }
        return false;
    }
};

// ============================================================================
// JSON Serialization View
// ============================================================================

/// JSON-serializable view of AnalysisResult
/// Transforms domain types into the expected JSON structure
pub const AnalysisResultJson = struct {
    artifact_type: []const u8,
    package_id: []const u8,
    app_name: []const u8,
    version_code: []const u8,
    version_name: []const u8,
    min_sdk_version: u32,
    target_sdk_version: ?u32,
    permissions: []const Permission,
    features: []const Feature,
    compressed_size: u64,
    uncompressed_size: u64,
    download_size: ?DownloadSizeEstimate,
    size_breakdown: SizeBreakdown,
    native_libraries: NativeLibraries,
    dex_info: ?DexInfo,
    certificate: ?CertificateInfoJson,
    split_configs: ?[]const SplitConfig,
    is_debuggable: bool,
    warnings: []const DiagnosticJson,

    /// Create JSON view from AnalysisResult
    pub fn fromResult(result: *const AnalysisResult, allocator: std.mem.Allocator) !AnalysisResultJson {
        // Convert certificate if present
        var cert_json: ?CertificateInfoJson = null;
        if (result.certificate) |*cert| {
            cert_json = try CertificateInfoJson.fromCertificate(cert, allocator);
        }

        // Convert diagnostics
        const warnings = try allocator.alloc(DiagnosticJson, result.diagnostics.len);
        for (result.diagnostics, 0..) |*d, i| {
            warnings[i] = DiagnosticJson.fromDiagnostic(d);
        }

        // Format version code
        const version_code_str = if (result.metadata.version_code_str.len > 0)
            result.metadata.version_code_str
        else blk: {
            const buf = try allocator.alloc(u8, 20);
            const formatted = std.fmt.bufPrint(buf, "{d}", .{result.metadata.version_code}) catch "0";
            break :blk formatted;
        };

        return .{
            .artifact_type = result.artifact_type.toString(),
            .package_id = result.metadata.package_id,
            .app_name = result.metadata.app_name,
            .version_code = version_code_str,
            .version_name = result.metadata.version_name,
            .min_sdk_version = result.metadata.min_sdk_version,
            .target_sdk_version = result.metadata.target_sdk_version,
            .permissions = result.metadata.permissions,
            .features = result.metadata.features,
            .compressed_size = result.compressed_size,
            .uncompressed_size = result.uncompressed_size,
            .download_size = result.download_size,
            .size_breakdown = result.size_breakdown,
            .native_libraries = result.native_libs,
            .dex_info = result.dex_info,
            .certificate = cert_json,
            .split_configs = result.split_configs,
            .is_debuggable = result.metadata.is_debuggable,
            .warnings = warnings,
        };
    }
};

/// JSON-serializable certificate with formatted fingerprints
pub const CertificateInfoJson = struct {
    subject: []const u8,
    issuer: []const u8,
    serial_number: []const u8,
    not_before: i64,
    not_after: i64,
    fingerprint_md5: []const u8,
    fingerprint_sha256: []const u8,
    signature_algorithm: []const u8,
    public_key_algorithm: []const u8,
    public_key_size: u32,

    pub fn fromCertificate(cert: *const CertificateInfo, allocator: std.mem.Allocator) !CertificateInfoJson {
        // Allocate buffers for formatted fingerprints
        const md5_buf = try allocator.alloc(u8, 16 * 3); // "XX:XX:..." format
        const sha256_buf = try allocator.alloc(u8, 32 * 3);

        const md5_str = cert.formatMd5Fingerprint(md5_buf);
        const sha256_str = cert.formatSha256Fingerprint(sha256_buf);

        return .{
            .subject = cert.subject,
            .issuer = cert.issuer,
            .serial_number = cert.serial_number,
            .not_before = cert.not_before,
            .not_after = cert.not_after,
            .fingerprint_md5 = md5_str,
            .fingerprint_sha256 = sha256_str,
            .signature_algorithm = cert.signature_algorithm,
            .public_key_algorithm = cert.public_key_algorithm,
            .public_key_size = cert.public_key_size,
        };
    }
};

/// JSON-serializable diagnostic
pub const DiagnosticJson = struct {
    code: []const u8,
    message: []const u8,
    severity: []const u8,

    pub fn fromDiagnostic(d: *const Diagnostic) DiagnosticJson {
        return .{
            .code = d.code.toString(),
            .message = d.message,
            .severity = d.severity.toString(),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ArtifactType.fromExtension" {
    try std.testing.expectEqual(ArtifactType.apk, ArtifactType.fromExtension(".apk").?);
    try std.testing.expectEqual(ArtifactType.apk, ArtifactType.fromExtension(".APK").?);
    try std.testing.expectEqual(ArtifactType.aab, ArtifactType.fromExtension(".aab").?);
    try std.testing.expectEqual(@as(?ArtifactType, null), ArtifactType.fromExtension(".zip"));
}

test "InstallLocation.fromValue" {
    try std.testing.expectEqual(InstallLocation.auto, InstallLocation.fromValue(0));
    try std.testing.expectEqual(InstallLocation.internal_only, InstallLocation.fromValue(1));
    try std.testing.expectEqual(InstallLocation.prefer_external, InstallLocation.fromValue(2));
    try std.testing.expectEqual(InstallLocation.auto, InstallLocation.fromValue(99));
}

test "SizeBreakdown.calculatePercentages" {
    var breakdown = SizeBreakdown{
        .dex = .{ .size = 500 },
        .resources = .{ .size = 300 },
        .native = .{ .size = 100 },
        .assets = .{ .size = 50 },
        .other = .{ .size = 50 },
    };
    breakdown.calculatePercentages(1000);

    try std.testing.expectApproxEqAbs(@as(f32, 50.0), breakdown.dex.percentage, 0.01);
    try std.testing.expectApproxEqAbs(@as(f32, 30.0), breakdown.resources.percentage, 0.01);
    try std.testing.expectApproxEqAbs(@as(f32, 10.0), breakdown.native.percentage, 0.01);
}

test "CertificateInfo.formatFingerprint" {
    const cert = CertificateInfo{
        .fingerprint_md5 = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 },
    };

    var buf: [48]u8 = undefined;
    const formatted = cert.formatMd5Fingerprint(&buf);
    try std.testing.expectEqualStrings("AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89", formatted);
}

test "AnalysisResult.initOwned and deinit" {
    const arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    var result = AnalysisResult.initOwned(arena);
    defer result.deinit();

    // Verify arena is accessible
    const alloc = result.getAllocator();
    try std.testing.expect(alloc != null);
}

test "AnalysisResult.hasErrors" {
    var result = AnalysisResult{};

    // No diagnostics = no errors
    try std.testing.expect(!result.hasErrors());

    // Add warning - still no errors
    const warnings = [_]Diagnostic{Diagnostic.warning(.dex_analysis_failed, "test")};
    result.diagnostics = &warnings;
    try std.testing.expect(!result.hasErrors());

    // Add error
    const errors = [_]Diagnostic{Diagnostic.err(.manifest_parse_failed, "test")};
    result.diagnostics = &errors;
    try std.testing.expect(result.hasErrors());
}

test "Diagnostic.warning and err" {
    const w = Diagnostic.warning(.dex_method_limit_exceeded, "Too many methods");
    try std.testing.expectEqual(DiagnosticSeverity.warning, w.severity);
    try std.testing.expectEqual(DiagnosticCode.dex_method_limit_exceeded, w.code);

    const e = Diagnostic.err(.manifest_parse_failed, "Parse failed");
    try std.testing.expectEqual(DiagnosticSeverity.@"error", e.severity);
}

test "SplitDimension.fromString" {
    try std.testing.expectEqual(SplitDimension.abi, SplitDimension.fromString("ABI").?);
    try std.testing.expectEqual(SplitDimension.abi, SplitDimension.fromString("abi").?);
    try std.testing.expectEqual(SplitDimension.screen_density, SplitDimension.fromString("SCREEN_DENSITY").?);
    try std.testing.expectEqual(@as(?SplitDimension, null), SplitDimension.fromString("unknown"));
}
