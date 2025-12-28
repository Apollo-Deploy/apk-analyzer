//! Analysis Module
//!
//! Provides the main analysis orchestration layer.
//! This module coordinates parsers and aggregates results.

pub const Analyzer = @import("analyzer.zig").Analyzer;
pub const Options = @import("options.zig").Options;
pub const LazyAnalyzer = @import("lazy.zig").LazyAnalyzer;
pub const StreamingAnalyzer = @import("streaming.zig").StreamingAnalyzer;

test {
    @import("std").testing.refAllDecls(@This());
}
