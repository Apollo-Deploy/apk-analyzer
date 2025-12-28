//! Import tests for the new modular API
//!
//! Verifies all modules are accessible via the lib.zig entry point.

const std = @import("std");
const apk = @import("apk-analyzer");

test "package can be imported via @import" {
    // Verify all modules are accessible
    _ = apk.core;
    _ = apk.analysis;
    _ = apk.parsers;
    _ = apk.tools;
    _ = apk.output;
    _ = apk.perf;

    // Verify version is accessible
    try std.testing.expectEqualStrings("0.2.0", apk.version);
}

test "core types are accessible" {
    _ = apk.ArtifactType;
    _ = apk.Metadata;
    _ = apk.Permission;
    _ = apk.Feature;
    _ = apk.SizeBreakdown;
    _ = apk.CertificateInfo;
    _ = apk.DexInfo;
    _ = apk.DexFileInfo;
    _ = apk.NativeLibraries;
    _ = apk.SplitConfig;
    _ = apk.SplitDimension;
    _ = apk.InstallLocation;
    _ = apk.AnalysisResult;
}

test "error types are accessible" {
    _ = apk.AnalysisError;
    _ = apk.Diagnostic;
    _ = apk.DiagnosticCode;
    _ = apk.DiagnosticSeverity;
}

test "analyzer types are accessible" {
    _ = apk.Analyzer;
    _ = apk.LazyAnalyzer;
    _ = apk.Options;
}

test "parser types are accessible" {
    _ = apk.ZipParser;
    _ = apk.AxmlParser;
    _ = apk.DexAnalyzer;
    _ = apk.CertificateParser;
}

test "tool types are accessible" {
    _ = apk.ApkComparator;
    _ = apk.CompareResult;
    _ = apk.CompareOptions;
    _ = apk.DownloadSizeEstimator;
    _ = apk.DownloadSizeEstimate;
    _ = apk.FeatureAnalyzer;
    _ = apk.FeatureAnalysisResult;
}

test "performance utilities are accessible" {
    _ = apk.BufferPool;
}

test "convenience functions are accessible" {
    _ = apk.detectArtifactType;
    _ = apk.analyzeQuick;
    _ = apk.analyzeFull;
}
