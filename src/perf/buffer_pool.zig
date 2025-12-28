const std = @import("std");

/// A Ring-Buffer Pool for temporary scratch memory.
///
/// NOTE: This pool uses a ring-buffer strategy. If you request more buffers
/// than available, it wraps around and overwrites the oldest ones.
pub const BufferPool = struct {
    allocator: std.mem.Allocator,

    // We use a single contiguous backing slice for each category to reduce allocator pressure
    // and improve cache locality.
    small_backing: []u8, // 16 * 4096
    medium_backing: []u8, // 4 * 65536
    large_backing: []u8, // 1 * 1MB

    small_idx: usize = 0,
    medium_idx: usize = 0,
    large_idx: usize = 0,

    const SMALL_COUNT = 16;
    const SMALL_SIZE = 4096;
    const MEDIUM_COUNT = 4;
    const MEDIUM_SIZE = 65536;
    const LARGE_COUNT = 1;
    const LARGE_SIZE = 1048576;

    /// Initialize the pool by allocating backing memory on the heap.
    /// This prevents Stack Overflows caused by large struct sizes.
    pub fn init(allocator: std.mem.Allocator) !BufferPool {
        const small = try allocator.alloc(u8, SMALL_COUNT * SMALL_SIZE);
        errdefer allocator.free(small);

        const medium = try allocator.alloc(u8, MEDIUM_COUNT * MEDIUM_SIZE);
        errdefer allocator.free(medium);

        const large = try allocator.alloc(u8, LARGE_COUNT * LARGE_SIZE);
        errdefer {
            allocator.free(medium);
            allocator.free(small);
        }

        return .{
            .allocator = allocator,
            .small_backing = small,
            .medium_backing = medium,
            .large_backing = large,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        self.allocator.free(self.small_backing);
        self.allocator.free(self.medium_backing);
        self.allocator.free(self.large_backing);
    }

    /// Reset indices to start reusing buffers from the beginning immediately.
    pub fn reset(self: *BufferPool) void {
        self.small_idx = 0;
        self.medium_idx = 0;
        self.large_idx = 0;
    }

    /// Get a small buffer (4KB). Wraps around if pool is exhausted.
    pub fn getSmall(self: *BufferPool) []u8 {
        const idx = self.small_idx % SMALL_COUNT;
        const start = idx * SMALL_SIZE;
        self.small_idx +%= 1;
        return self.small_backing[start..][0..SMALL_SIZE];
    }

    /// Get a medium buffer (64KB). Wraps around if pool is exhausted.
    pub fn getMedium(self: *BufferPool) []u8 {
        const idx = self.medium_idx % MEDIUM_COUNT;
        const start = idx * MEDIUM_SIZE;
        self.medium_idx +%= 1;
        return self.medium_backing[start..][0..MEDIUM_SIZE];
    }

    /// Get a large buffer (1MB).
    pub fn getLarge(self: *BufferPool) []u8 {
        // Even with count=1, we use logic that supports expansion later
        const idx = self.large_idx % LARGE_COUNT;
        const start = idx * LARGE_SIZE;
        self.large_idx +%= 1;
        return self.large_backing[start..][0..LARGE_SIZE];
    }
};

/// SIMD-optimized string operations.
///
/// checks: Native vector size support, correct masking, and alignment safety.
pub const SimdString = struct {
    // We explicitly ask for a 16-byte vector (128-bit), supported by SSE2/NEON/etc.
    const Vector = @Vector(16, u8);
    const VECTOR_SIZE = 16;

    /// Find null terminator.
    /// Optimization: Uses std.mem.indexOfScalar which is highly optimized (SWAR/SIMD).
    pub fn findNullTerminator(data: []const u8) usize {
        return std.mem.indexOfScalar(u8, data, 0) orelse data.len;
    }

    /// Find byte using manual SIMD (Corrected).
    pub fn findByte(data: []const u8, byte: u8) ?usize {
        if (data.len == 0) return null;

        const target: Vector = @splat(byte);
        var i: usize = 0;

        // Vector Loop
        while (i + VECTOR_SIZE <= data.len) : (i += VECTOR_SIZE) {
            // Load vector
            const chunk: Vector = data[i..][0..VECTOR_SIZE].*;
            // Compare: produces vector of bools
            const matches = chunk == target;

            // Check if ANY byte matched (Reduction)
            if (@reduce(.Or, matches)) {
                // Determine exact index.
                // We create a bitmask from the bool vector.
                // In Zig, we can't simple @bitCast a bool vector to int safely across all backends.
                // We iterate the small vector array (unrolled by compiler) or use std.simd if strictly needed.
                // For simplicity/portability in raw Zig:
                const arr: [VECTOR_SIZE]u8 = chunk;
                for (arr, 0..) |b, offset| {
                    if (b == byte) return i + offset;
                }
            }
        }

        // Scalar fallback
        while (i < data.len) : (i += 1) {
            if (data[i] == byte) return i;
        }
        return null;
    }

    /// Compare strings using manual SIMD (Corrected).
    pub fn equals(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        if (a.ptr == b.ptr) return true; // Same memory
        if (a.len == 0) return true;

        var i: usize = 0;

        // Vector Loop
        while (i + VECTOR_SIZE <= a.len) : (i += VECTOR_SIZE) {
            const chunk_a: Vector = a[i..][0..VECTOR_SIZE].*;
            const chunk_b: Vector = b[i..][0..VECTOR_SIZE].*;

            // Compare
            const equal_mask = chunk_a == chunk_b;

            // Reduction: If ALL lanes are true, result is true.
            // If !ALL are true, we found a mismatch.
            if (!@reduce(.And, equal_mask)) return false;
        }

        // Scalar fallback
        while (i < a.len) : (i += 1) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
};

test "BufferPool allocates on heap and returns distinct buffers" {
    // Use testing allocator to detect leaks automatically
    var pool = try BufferPool.init(std.testing.allocator);
    defer pool.deinit();

    const buf1 = pool.getSmall();
    const buf2 = pool.getSmall();

    try std.testing.expect(buf1.ptr != buf2.ptr);
    try std.testing.expectEqual(@as(usize, 4096), buf1.len);

    // Test large buffer
    const large = pool.getLarge();
    try std.testing.expectEqual(@as(usize, 1048576), large.len);
}

test "BufferPool wrapping behavior" {
    var pool = try BufferPool.init(std.testing.allocator);
    defer pool.deinit();

    const first_ptr = pool.getSmall().ptr;

    // Exhaust the small pool (16 slots)
    var i: usize = 0;
    while (i < 15) : (i += 1) {
        _ = pool.getSmall();
    }

    // The 17th request should wrap around to the first pointer
    const wrapped_ptr = pool.getSmall().ptr;
    try std.testing.expectEqual(first_ptr, wrapped_ptr);
}

test "SimdString functionality" {
    const data = "hello world";

    // Null terminator
    try std.testing.expectEqual(@as(usize, 11), SimdString.findNullTerminator(data));
    const data_null = "hello\x00world";
    try std.testing.expectEqual(@as(usize, 5), SimdString.findNullTerminator(data_null));

    // Find byte
    try std.testing.expectEqual(@as(usize, 6), SimdString.findByte(data, 'w').?);
    try std.testing.expect(SimdString.findByte(data, 'z') == null);

    // Equals
    try std.testing.expect(SimdString.equals(data, "hello world"));
    try std.testing.expect(!SimdString.equals(data, "hello there"));
}
