//! APK/AAB Analyzer Library
//!
//! A high-performance, zero-dependency Zig library for analyzing Android
//! application packages (APK) and Android App Bundles (AAB).
//!
//! ## Architecture
//!
//! The library follows a clean modular architecture:
//! - `core`: Domain types, errors, and utilities
//! - `analysis`: Orchestration layer (Analyzer, LazyAnalyzer)
//! - `parsers`: Format-specific parsers (ZIP, AXML, DEX, etc.)
//! - `tools`: Analysis tools (compare, download size, features)
//! - `output`: Serialization (JSON, text)
//! - `perf`: Performance utilities (buffer pool, SIMD)
//!
//! ## Quick Start
//!
//! ```zig
//! const apk = @import("apk-analyzer");
//! const std = @import("std");
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     defer _ = gpa.deinit();
//!     const allocator = gpa.allocator();
//!
//!     // Create analyzer with default options
//!     var analyzer = apk.Analyzer.init(allocator, .{});
//!
//!     // Read and analyze APK
//!     const data = try std.fs.cwd().readFileAlloc(allocator, "app.apk", 100 * 1024 * 1024);
//!     defer allocator.free(data);
//!
//!     var result = try analyzer.analyze(data);
//!     defer result.deinit();
//!
//!     // Access results
//!     std.debug.print("Package: {s}\n", .{result.metadata.package_id});
//!     std.debug.print("Version: {s}\n", .{result.metadata.version_name});
//!
//!     // Serialize to JSON
//!     const stdout = std.io.getStdOut().writer();
//!     try apk.output.toJson(&result, stdout, .{});
//! }
//! ```

const std = @import("std");

// ============================================================================
// Core Module - Domain types and errors
// ============================================================================

pub const core = @import("core/mod.zig");

// Re-export core types for convenience
pub const ArtifactType = core.ArtifactType;
pub const Metadata = core.Metadata;
pub const Permission = core.Permission;
pub const Feature = core.Feature;
pub const SizeBreakdown = core.SizeBreakdown;
pub const CategorySize = core.CategorySize;
pub const CertificateInfo = core.CertificateInfo;
pub const DexInfo = core.DexInfo;
pub const DexFileInfo = core.DexFileInfo;
pub const NativeLibraries = core.NativeLibraries;
pub const SplitConfig = core.SplitConfig;
pub const SplitDimension = core.SplitDimension;
pub const InstallLocation = core.InstallLocation;
pub const AnalysisResult = core.AnalysisResult;
pub const AnalysisResultJson = core.AnalysisResultJson;
pub const CertificateInfoJson = core.CertificateInfoJson;
pub const DiagnosticJson = core.DiagnosticJson;

// Re-export error types
pub const AnalysisError = core.AnalysisError;
pub const Diagnostic = core.Diagnostic;
pub const DiagnosticCode = core.DiagnosticCode;
pub const DiagnosticSeverity = core.DiagnosticSeverity;

// ============================================================================
// Analysis Module - Orchestration layer
// ============================================================================

pub const analysis = @import("analysis/mod.zig");

// Re-export main analyzer types
pub const Analyzer = analysis.Analyzer;
pub const LazyAnalyzer = analysis.LazyAnalyzer;
pub const StreamingAnalyzer = analysis.StreamingAnalyzer;
pub const Options = analysis.Options;

// ============================================================================
// Parsers Module - Format-specific parsers
// ============================================================================

pub const parsers = @import("parsers/mod.zig");

// Re-export commonly used parsers
pub const ZipParser = parsers.ZipParser;
pub const AxmlParser = parsers.AxmlParser;
pub const DexAnalyzer = parsers.DexAnalyzer;
pub const CertificateParser = parsers.CertificateParser;

// ============================================================================
// Tools Module - Analysis tools
// ============================================================================

pub const tools = @import("tools/mod.zig");

// Re-export tool types
pub const ApkComparator = tools.ApkComparator;
pub const StreamingApkComparator = tools.StreamingApkComparator;
pub const StreamingContentVerifier = tools.StreamingContentVerifier;
pub const ContentVerifyResult = tools.ContentVerifyResult;
pub const BatchVerifyResult = tools.BatchVerifyResult;
pub const CompareResult = tools.CompareResult;
pub const CompareEntry = tools.CompareEntry;
pub const CompareOptions = tools.CompareOptions;
pub const FileCategory = tools.FileCategory;
pub const CategoryBreakdown = tools.CategoryBreakdown;
pub const CompareSummary = tools.CompareSummary;
pub const LargestChange = tools.LargestChange;
pub const DownloadSizeEstimator = tools.DownloadSizeEstimator;
pub const DownloadSizeEstimate = tools.DownloadSizeEstimate;
pub const FeatureAnalyzer = tools.FeatureAnalyzer;
pub const FeatureAnalysisResult = tools.FeatureAnalysisResult;

// ============================================================================
// Output Module - Serialization
// ============================================================================

pub const output = @import("output/mod.zig");

// Re-export JSON serialization
pub const json = output.json;

// ============================================================================
// Performance Module - Utilities
// ============================================================================

pub const perf = @import("perf/mod.zig");

// Re-export performance utilities
pub const BufferPool = perf.BufferPool;

// ============================================================================
// Library Metadata
// ============================================================================

/// Library version
pub const version = "0.2.0";

/// Library version as struct for programmatic access
pub const Version = struct {
    major: u8 = 0,
    minor: u8 = 2,
    patch: u8 = 0,

    pub fn toString(self: Version) []const u8 {
        _ = self;
        return version;
    }
};

// ============================================================================
// Convenience Functions
// ============================================================================

/// Detect artifact type from filename and file data
pub fn detectArtifactType(filename: []const u8, data: []const u8) ArtifactType {
    // Check for ZIP magic bytes (PK\x03\x04)
    if (data.len < 4) return .apk; // Default to APK
    if (data[0] != 'P' or data[1] != 'K' or data[2] != 0x03 or data[3] != 0x04) {
        return .apk;
    }

    // Check file extension
    if (std.mem.endsWith(u8, filename, ".aab") or
        std.mem.endsWith(u8, filename, ".AAB"))
    {
        return .aab;
    }

    // Try to detect by internal structure
    // AAB has base/manifest/AndroidManifest.xml
    if (std.mem.indexOf(u8, data, "base/manifest/AndroidManifest.xml")) |_| {
        return .aab;
    }

    return .apk;
}

/// Quick analysis with default options
pub fn analyzeQuick(allocator: std.mem.Allocator, data: []const u8) AnalysisError!AnalysisResult {
    var analyzer = Analyzer.init(allocator, Options.fast);
    return analyzer.analyze(data);
}

/// Full analysis with all features
pub fn analyzeFull(allocator: std.mem.Allocator, data: []const u8) AnalysisError!AnalysisResult {
    var analyzer = Analyzer.init(allocator, Options.full);
    return analyzer.analyze(data);
}

// ============================================================================
// Tests
// ============================================================================

test "library exports" {
    // Verify all modules are accessible
    _ = core;
    _ = analysis;
    _ = parsers;
    _ = tools;
    _ = output;
    _ = perf;
}

test "version" {
    try std.testing.expectEqualStrings("0.2.0", version);
}

test "detectArtifactType" {
    const zip_header = [_]u8{ 'P', 'K', 0x03, 0x04 };
    try std.testing.expectEqual(ArtifactType.apk, detectArtifactType("app.apk", &zip_header));
    try std.testing.expectEqual(ArtifactType.aab, detectArtifactType("app.aab", &zip_header));
}

test {
    // Run all module tests
    std.testing.refAllDecls(@This());
}
