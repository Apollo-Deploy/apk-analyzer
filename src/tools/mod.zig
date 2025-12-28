//! Tools Module
//!
//! Analysis tools for APK/AAB files.
//!
//! ## Tools
//!
//! - `compare`: Compare two APK/AAB files for size changes
//! - `streaming_compare`: Memory-efficient comparison using mmap (for large APKs)
//! - `download_size`: Estimate download size with compression
//! - `features`: Analyze hardware/software feature requirements

const std = @import("std");

// Import tools from this directory
pub const compare = @import("compare.zig");
pub const streaming_compare = @import("streaming_compare.zig");
pub const download_size = @import("download_size.zig");
pub const features = @import("features.zig");

// ============================================================================
// Compare Tool
// ============================================================================

/// Compare two APK/AAB files
pub const ApkComparator = compare.ApkComparator;
pub const CompareResult = compare.CompareResult;
pub const CompareEntry = compare.CompareEntry;
pub const CompareOptions = compare.CompareOptions;
pub const FileCategory = compare.FileCategory;
pub const CategoryBreakdown = compare.CategoryBreakdown;
pub const CompareSummary = compare.CompareSummary;
pub const LargestChange = compare.LargestChange;

/// Categorize a file by its path
pub const categorizeFile = compare.categorizeFile;

// ============================================================================
// Streaming Compare Tool (Memory-Efficient)
// ============================================================================

/// Memory-efficient APK comparator using mmap
/// Use this for comparing large APKs (150MB+) to avoid high memory usage
pub const StreamingApkComparator = streaming_compare.StreamingApkComparator;

/// Streaming content verifier for byte-by-byte comparison
/// Use when CRC32 comparison isn't sufficient (e.g., verifying actual content)
pub const StreamingContentVerifier = streaming_compare.StreamingContentVerifier;

/// Result of streaming content verification
pub const ContentVerifyResult = streaming_compare.ContentVerifyResult;

/// Result of batch content verification
pub const BatchVerifyResult = streaming_compare.BatchVerifyResult;

// ============================================================================
// Download Size Tool
// ============================================================================

/// Estimate download size
pub const DownloadSizeEstimator = download_size.DownloadSizeEstimator;
pub const DownloadSizeEstimate = download_size.DownloadSizeEstimate;

// ============================================================================
// Features Tool
// ============================================================================

/// Analyze feature requirements
pub const FeatureAnalyzer = features.FeatureAnalyzer;
pub const FilteringFeature = features.FilteringFeature;
pub const FeatureAnalysisResult = features.FeatureAnalysisResult;
pub const FeatureAnalysisOptions = features.FeatureAnalysisOptions;

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}
