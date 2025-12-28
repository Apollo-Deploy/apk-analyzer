//! Unified Error Handling
//!
//! Provides a consistent error model across all modules with:
//! - Typed error codes for programmatic handling
//! - Human-readable messages for debugging
//! - Severity levels for filtering
//! - Optional location context

const std = @import("std");

/// Analysis error type - covers all possible failure modes
pub const AnalysisError = error{
    // Archive errors
    InvalidArchive,
    TruncatedArchive,
    UnsupportedCompression,
    PathTraversal,

    // Manifest errors
    MissingManifest,
    InvalidManifest,
    UnsupportedManifestFormat,

    // DEX errors
    InvalidDexFile,
    NoDexFiles,

    // Certificate errors
    InvalidCertificate,
    NoCertificate,

    // Resource errors
    InvalidResources,

    // General errors
    OutOfMemory,
    IoError,
    FileTooLarge,
    MemoryBudgetExceeded,
    UnsupportedFormat,
};

/// Diagnostic severity level
pub const DiagnosticSeverity = enum {
    /// Informational message
    info,
    /// Warning - analysis continued but results may be incomplete
    warning,
    /// Error - analysis of this component failed
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
    // Manifest diagnostics
    manifest_parse_failed,
    manifest_missing_package,
    manifest_invalid_version,

    // DEX diagnostics
    dex_analysis_failed,
    dex_method_limit_exceeded,
    dex_invalid_header,

    // Certificate diagnostics
    certificate_extraction_failed,
    certificate_expired,
    certificate_not_yet_valid,

    // Resource diagnostics
    resources_parse_failed,
    resources_invalid_string_pool,

    // Native library diagnostics
    native_analysis_failed,
    native_unsupported_abi,

    // General diagnostics
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

/// Location context for diagnostics
pub const Location = struct {
    /// File path within the archive
    file: []const u8 = "",
    /// Byte offset within the file
    offset: ?u64 = null,
    /// Line number (for text formats)
    line: ?u32 = null,
    /// Column number (for text formats)
    column: ?u32 = null,
};

/// Diagnostic warning or error with context
pub const Diagnostic = struct {
    /// Diagnostic code for programmatic handling
    code: DiagnosticCode,
    /// Human-readable message
    message: []const u8,
    /// Severity level
    severity: DiagnosticSeverity,
    /// Optional location context
    location: ?Location = null,

    /// Create an info diagnostic
    pub fn info(code: DiagnosticCode, message: []const u8) Diagnostic {
        return .{ .code = code, .message = message, .severity = .info };
    }

    /// Create a warning diagnostic
    pub fn warning(code: DiagnosticCode, message: []const u8) Diagnostic {
        return .{ .code = code, .message = message, .severity = .warning };
    }

    /// Create an error diagnostic
    pub fn err(code: DiagnosticCode, message: []const u8) Diagnostic {
        return .{ .code = code, .message = message, .severity = .@"error" };
    }

    /// Add location context
    pub fn withLocation(self: Diagnostic, loc: Location) Diagnostic {
        var d = self;
        d.location = loc;
        return d;
    }
};

/// Diagnostic collector for accumulating warnings during analysis
pub const DiagnosticCollector = struct {
    allocator: std.mem.Allocator,
    diagnostics: std.ArrayListUnmanaged(Diagnostic),

    pub fn init(allocator: std.mem.Allocator) DiagnosticCollector {
        return .{
            .allocator = allocator,
            .diagnostics = .{},
        };
    }

    pub fn deinit(self: *DiagnosticCollector) void {
        self.diagnostics.deinit(self.allocator);
    }

    pub fn add(self: *DiagnosticCollector, diagnostic: Diagnostic) !void {
        try self.diagnostics.append(self.allocator, diagnostic);
    }

    pub fn addWarning(self: *DiagnosticCollector, code: DiagnosticCode, message: []const u8) !void {
        try self.add(Diagnostic.warning(code, message));
    }

    pub fn addError(self: *DiagnosticCollector, code: DiagnosticCode, message: []const u8) !void {
        try self.add(Diagnostic.err(code, message));
    }

    pub fn toOwnedSlice(self: *DiagnosticCollector) ![]const Diagnostic {
        return self.diagnostics.toOwnedSlice(self.allocator);
    }

    pub fn hasErrors(self: *const DiagnosticCollector) bool {
        for (self.diagnostics.items) |d| {
            if (d.severity == .@"error") return true;
        }
        return false;
    }

    pub fn count(self: *const DiagnosticCollector) usize {
        return self.diagnostics.items.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Diagnostic.warning creates warning" {
    const d = Diagnostic.warning(.dex_analysis_failed, "Failed to analyze DEX");
    try std.testing.expectEqual(DiagnosticSeverity.warning, d.severity);
    try std.testing.expectEqual(DiagnosticCode.dex_analysis_failed, d.code);
}

test "Diagnostic.withLocation adds location" {
    const d = Diagnostic.err(.manifest_parse_failed, "Parse error")
        .withLocation(.{ .file = "AndroidManifest.xml", .offset = 100 });

    try std.testing.expect(d.location != null);
    try std.testing.expectEqualStrings("AndroidManifest.xml", d.location.?.file);
    try std.testing.expectEqual(@as(u64, 100), d.location.?.offset.?);
}

test "DiagnosticCollector accumulates diagnostics" {
    var collector = DiagnosticCollector.init(std.testing.allocator);
    defer collector.deinit();

    try collector.addWarning(.dex_analysis_failed, "Warning 1");
    try collector.addError(.manifest_parse_failed, "Error 1");

    try std.testing.expectEqual(@as(usize, 2), collector.count());
    try std.testing.expect(collector.hasErrors());
}
