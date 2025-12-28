//! Analysis Options
//!
//! Configuration for the analyzer behavior.

/// Analyzer configuration options
pub const Options = struct {
    /// Skip DEX analysis for faster parsing
    skip_dex_analysis: bool = false,

    /// Skip certificate extraction
    skip_certificate: bool = false,

    /// Maximum memory budget in bytes (0 = unlimited)
    max_memory: usize = 0,

    /// Enable streaming mode for large files
    streaming_mode: bool = true,

    /// Enable lazy parsing (parse components on-demand)
    lazy_parsing: bool = false,

    /// Enable SIMD optimizations
    use_simd: bool = true,

    /// Enable buffer pooling for decompression
    use_buffer_pool: bool = true,

    /// Preset configurations
    pub const fast = Options{
        .skip_dex_analysis = true,
        .skip_certificate = true,
        .lazy_parsing = true,
    };

    pub const full = Options{
        .skip_dex_analysis = false,
        .skip_certificate = false,
        .lazy_parsing = false,
    };

    pub const memory_constrained = Options{
        .max_memory = 50 * 1024 * 1024, // 50MB
        .streaming_mode = true,
        .lazy_parsing = true,
        .use_buffer_pool = true,
    };
};

test "Options presets" {
    const std = @import("std");

    // Fast preset skips expensive operations
    try std.testing.expect(Options.fast.skip_dex_analysis);
    try std.testing.expect(Options.fast.skip_certificate);
    try std.testing.expect(Options.fast.lazy_parsing);

    // Full preset analyzes everything
    try std.testing.expect(!Options.full.skip_dex_analysis);
    try std.testing.expect(!Options.full.skip_certificate);

    // Memory constrained has limits
    try std.testing.expect(Options.memory_constrained.max_memory > 0);
}
