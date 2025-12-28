//! Core Module
//!
//! Provides foundational types, errors, and utilities used throughout
//! the APK analyzer library. This module defines the domain model that
//! all other modules depend on.

pub const types = @import("types.zig");
pub const errors = @import("errors.zig");

// Re-export commonly used types for convenience
pub const ArtifactType = types.ArtifactType;
pub const InstallLocation = types.InstallLocation;
pub const Permission = types.Permission;
pub const Feature = types.Feature;
pub const Metadata = types.Metadata;
pub const SizeBreakdown = types.SizeBreakdown;
pub const CategorySize = types.CategorySize;
pub const DownloadSizeEstimate = types.DownloadSizeEstimate;
pub const DownloadSizeBreakdown = types.DownloadSizeBreakdown;
pub const CertificateInfo = types.CertificateInfo;
pub const DexFileInfo = types.DexFileInfo;
pub const DexInfo = types.DexInfo;
pub const NativeLibraries = types.NativeLibraries;
pub const SplitDimension = types.SplitDimension;
pub const SplitConfig = types.SplitConfig;
pub const AnalysisResult = types.AnalysisResult;

// Re-export JSON view types
pub const AnalysisResultJson = types.AnalysisResultJson;
pub const CertificateInfoJson = types.CertificateInfoJson;
pub const DiagnosticJson = types.DiagnosticJson;

// Re-export domain diagnostic types (decoupled from errors module)
pub const Diagnostic = types.Diagnostic;
pub const DiagnosticCode = types.DiagnosticCode;
pub const DiagnosticSeverity = types.DiagnosticSeverity;

// Re-export error types
pub const AnalysisError = errors.AnalysisError;

test {
    @import("std").testing.refAllDecls(@This());
}
