//! Cross-platform memory mapping utilities
//!
//! Provides a unified interface for memory-mapped file I/O that works
//! on both POSIX systems (Linux, macOS) and Windows.

const std = @import("std");
const builtin = @import("builtin");

// Use the system's minimum page size for alignment
const page_size = std.heap.page_size_min;

/// Memory-mapped file data
pub const MappedFile = struct {
    /// The mapped data - for mmap this is page-aligned, for regular reads it's not
    data: []const u8,
    /// Raw pointer for munmap (preserves alignment)
    mmap_ptr: ?[*]align(page_size) u8,
    mmap_len: usize,
    is_mmap: bool,
    allocator: ?std.mem.Allocator,

    /// Unmap or free the memory
    pub fn deinit(self: *MappedFile) void {
        if (self.is_mmap) {
            if (builtin.os.tag != .windows) {
                if (self.mmap_ptr) |ptr| {
                    std.posix.munmap(ptr[0..self.mmap_len]);
                }
            }
        } else if (self.allocator) |alloc| {
            if (self.data.len > 0) {
                alloc.free(@constCast(self.data));
            }
        }
    }

    /// Get the mapped data as a slice
    pub fn slice(self: *const MappedFile) []const u8 {
        return self.data;
    }
};

/// Memory-map a file for read-only access.
/// On Windows, falls back to regular file reading since mmap is not available.
/// On POSIX systems, uses mmap with sequential access hints.
pub fn mapFile(file: std.fs.File, file_size: u64, allocator: std.mem.Allocator) !MappedFile {
    if (builtin.os.tag == .windows) {
        // Windows: fall back to regular file read
        return mapFileRegular(file, file_size, allocator);
    } else {
        // POSIX: use mmap
        return mapFileMmap(file, file_size, allocator);
    }
}

/// Memory-map using POSIX mmap (Linux, macOS, BSD)
fn mapFileMmap(file: std.fs.File, file_size: u64, allocator: std.mem.Allocator) !MappedFile {
    const size: usize = @intCast(file_size);

    const mapped_data = std.posix.mmap(
        null,
        size,
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        file.handle,
        0,
    ) catch {
        // Fall back to regular file read if mmap fails
        return mapFileRegular(file, file_size, allocator);
    };

    // Advise the kernel for sequential access (improves prefetching)
    // MADV_SEQUENTIAL = 2 on most Unix systems
    std.posix.madvise(mapped_data.ptr, mapped_data.len, 2) catch {};

    return MappedFile{
        .data = mapped_data,
        .mmap_ptr = mapped_data.ptr,
        .mmap_len = mapped_data.len,
        .is_mmap = true,
        .allocator = null,
    };
}

/// Regular file read fallback (used on Windows or when mmap fails)
fn mapFileRegular(file: std.fs.File, file_size: u64, allocator: std.mem.Allocator) !MappedFile {
    const size: usize = @intCast(file_size);

    // Allocate buffer
    const data = try allocator.alloc(u8, size);
    errdefer allocator.free(data);

    // Read entire file
    file.seekTo(0) catch {};
    const bytes_read = try file.readAll(data);
    if (bytes_read != size) {
        return error.IncompleteRead;
    }

    return MappedFile{
        .data = data,
        .mmap_ptr = null,
        .mmap_len = 0,
        .is_mmap = false,
        .allocator = allocator,
    };
}

/// Check if memory mapping is supported on the current platform
pub fn isMmapSupported() bool {
    return builtin.os.tag != .windows;
}
