//! Performance Module
//!
//! Performance utilities for optimized analysis.
//!
//! ## Components
//!
//! - `buffer_pool`: Reusable buffer pool for decompression
//! - SIMD utilities for string scanning (in buffer_pool)

const std = @import("std");

// Import performance utilities
pub const buffer_pool = @import("buffer_pool.zig");

// ============================================================================
// Buffer Pool
// ============================================================================

/// Reusable buffer pool for decompression operations
pub const BufferPool = buffer_pool.BufferPool;

/// SIMD-optimized string operations
pub const SimdString = buffer_pool.SimdString;

// ============================================================================
// Memory Utilities
// ============================================================================

/// Calculate optimal buffer size for given data size
pub fn optimalBufferSize(data_size: usize) usize {
    // Use power-of-2 sizes for better memory alignment
    const min_size: usize = 4096; // 4KB minimum
    const max_size: usize = 1024 * 1024; // 1MB maximum

    if (data_size <= min_size) return min_size;
    if (data_size >= max_size) return max_size;

    // Round up to next power of 2
    var size: usize = min_size;
    while (size < data_size) {
        size *= 2;
    }
    return size;
}

/// Memory budget calculator for analysis
pub const MemoryBudget = struct {
    /// Total budget in bytes
    total: usize,
    /// Reserved for ZIP parsing
    zip_reserved: usize,
    /// Reserved for decompression buffers
    decompress_reserved: usize,
    /// Available for analysis
    available: usize,

    /// Create budget from total memory limit
    pub fn fromTotal(total: usize) MemoryBudget {
        const zip_reserved = @min(total / 4, 50 * 1024 * 1024); // 25% or 50MB max
        const decompress_reserved = @min(total / 4, 100 * 1024 * 1024); // 25% or 100MB max
        const available = total - zip_reserved - decompress_reserved;

        return .{
            .total = total,
            .zip_reserved = zip_reserved,
            .decompress_reserved = decompress_reserved,
            .available = available,
        };
    }

    /// Default budget (200MB)
    pub const default = fromTotal(200 * 1024 * 1024);

    /// Constrained budget (50MB)
    pub const constrained = fromTotal(50 * 1024 * 1024);
};

// ============================================================================
// Tests
// ============================================================================

test "optimalBufferSize" {
    try std.testing.expectEqual(@as(usize, 4096), optimalBufferSize(100));
    try std.testing.expectEqual(@as(usize, 4096), optimalBufferSize(4096));
    try std.testing.expectEqual(@as(usize, 8192), optimalBufferSize(5000));
    try std.testing.expectEqual(@as(usize, 1024 * 1024), optimalBufferSize(2 * 1024 * 1024));
}

test "MemoryBudget" {
    const budget = MemoryBudget.fromTotal(100 * 1024 * 1024);
    try std.testing.expect(budget.zip_reserved > 0);
    try std.testing.expect(budget.decompress_reserved > 0);
    try std.testing.expect(budget.available > 0);
    try std.testing.expectEqual(budget.total, budget.zip_reserved + budget.decompress_reserved + budget.available);
}

test {
    std.testing.refAllDecls(@This());
}
