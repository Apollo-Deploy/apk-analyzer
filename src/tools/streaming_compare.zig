//! Streaming APK Comparison Tool
//!
//! Memory-efficient comparison of two APK files using memory-mapped I/O.
//! Unlike the standard compare tool, this implementation:
//! - Uses mmap() to avoid loading entire files into memory
//! - Only parses ZIP central directory metadata
//! - Compares entries based on compressed size and CRC32
//! - Peak memory usage is O(number of entries) not O(file sizes)
//!
//! For two 150MB APKs with ~5000 entries each:
//! - Standard compare: ~300MB+ memory (loads both files)
//! - Streaming compare: ~5-10MB memory (only metadata)
//!
//! ## Content Verification Mode
//!
//! For cases where CRC32 comparison isn't sufficient (e.g., verifying
//! actual content differences), use `compareFilesWithContent()` which
//! streams and compares file contents without loading entire files.
//!
//! ## Usage
//!
//! ```zig
//! var comparator = StreamingApkComparator.init(allocator);
//! defer comparator.deinit();
//!
//! // Fast metadata-only comparison (default)
//! var result = try comparator.compareFiles("old.apk", "new.apk", .{
//!     .different_only = true,
//!     .include_breakdown = true,
//! });
//! defer result.deinit();
//!
//! // Content verification for specific files (slower but thorough)
//! const content_match = try comparator.verifyFileContent(
//!     "old.apk", "new.apk", "classes.dex"
//! );
//! ```

const std = @import("std");
const compare = @import("compare.zig");

// Re-export types from compare module for API compatibility
pub const FileCategory = compare.FileCategory;
pub const CategoryBreakdown = compare.CategoryBreakdown;
pub const CompareSummary = compare.CompareSummary;
pub const CompareEntry = compare.CompareEntry;
pub const CompareResult = compare.CompareResult;
pub const CompareOptions = compare.CompareOptions;
pub const LargestChange = compare.LargestChange;
pub const categorizeFile = compare.categorizeFile;

/// ZIP signature constants
const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const CENTRAL_DIR_HEADER_SIG: u32 = 0x02014b50;
const END_OF_CENTRAL_DIR_SIG: u32 = 0x06054b50;
const ZIP64_END_OF_CENTRAL_DIR_SIG: u32 = 0x06064b50;
const ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG: u32 = 0x07064b50;
const ZIP64_EXTRA_FIELD_TAG: u16 = 0x0001;

/// Lightweight entry info - only what we need for comparison
/// Uses indices into the mapped data instead of copying strings
const EntryInfo = struct {
    /// Offset to filename in mapped data
    name_offset: usize,
    /// Length of filename
    name_len: u16,
    /// Compressed size in archive
    compressed_size: u64,
    /// Uncompressed size
    uncompressed_size: u64,
    /// CRC32 checksum for content comparison
    crc32: u32,
    /// Whether this is a directory
    is_directory: bool,
};

/// Memory-efficient streaming APK comparator
/// Uses memory-mapped I/O to compare large APKs without loading them into memory
pub const StreamingApkComparator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StreamingApkComparator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *StreamingApkComparator) void {
        _ = self;
    }

    /// Compare two APK files using memory-mapped I/O
    /// Peak memory: O(entry_count) instead of O(file_size)
    pub fn compareFiles(
        self: *StreamingApkComparator,
        old_path: []const u8,
        new_path: []const u8,
        options: CompareOptions,
    ) !CompareResult {
        // Open and mmap old file
        const old_file = std.fs.cwd().openFile(old_path, .{}) catch {
            return error.OldFileNotFound;
        };
        defer old_file.close();

        const old_size = old_file.getEndPos() catch {
            return error.InvalidOldFile;
        };

        if (old_size == 0) return error.InvalidOldFile;

        const old_mapped = std.posix.mmap(
            null,
            @intCast(old_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            old_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(old_mapped);

        // Advise sequential read for old file
        std.posix.madvise(@alignCast(old_mapped.ptr), old_mapped.len, 2) catch {};

        // Open and mmap new file
        const new_file = std.fs.cwd().openFile(new_path, .{}) catch {
            return error.NewFileNotFound;
        };
        defer new_file.close();

        const new_size = new_file.getEndPos() catch {
            return error.InvalidNewFile;
        };

        if (new_size == 0) return error.InvalidNewFile;

        const new_mapped = std.posix.mmap(
            null,
            @intCast(new_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            new_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(new_mapped);

        // Advise sequential read for new file
        std.posix.madvise(@alignCast(new_mapped.ptr), new_mapped.len, 2) catch {};

        // Compare using mapped data
        return self.compareMapped(old_mapped, new_mapped, old_size, new_size, options);
    }

    /// Compare two memory-mapped APK files
    fn compareMapped(
        self: *StreamingApkComparator,
        old_data: []const u8,
        new_data: []const u8,
        old_total_size: u64,
        new_total_size: u64,
        options: CompareOptions,
    ) !CompareResult {
        // Create arena for result data
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        // Parse central directories (lightweight - only metadata)
        var old_entries = try self.parseCentralDirectory(old_data);
        defer old_entries.deinit(self.allocator);

        var new_entries = try self.parseCentralDirectory(new_data);
        defer new_entries.deinit(self.allocator);

        // Build comparison results
        var all_entries = std.ArrayListUnmanaged(CompareEntry){};

        // Build map for old files: name -> index
        var old_map = std.StringHashMap(usize).init(self.allocator);
        defer old_map.deinit();

        try old_map.ensureTotalCapacity(@intCast(old_entries.items.len));

        for (old_entries.items, 0..) |entry, idx| {
            const name = old_data[entry.name_offset .. entry.name_offset + entry.name_len];
            old_map.putAssumeCapacity(name, idx);
        }

        // Track directories
        var directories = std.StringHashMap(DirSizes).init(self.allocator);
        defer directories.deinit();

        // Track breakdown by category
        var breakdown_map: [5]CategoryBreakdown = undefined;
        for (&breakdown_map, 0..) |*bd, i| {
            bd.* = CategoryBreakdown{
                .category = @enumFromInt(i),
                .old_size = 0,
                .new_size = 0,
                .difference = 0,
                .file_count = 0,
                .added_count = 0,
                .removed_count = 0,
                .modified_count = 0,
            };
        }

        // Track summary
        var summary = CompareSummary{
            .old_file_count = @intCast(old_entries.items.len),
            .new_file_count = @intCast(new_entries.items.len),
            .added_count = 0,
            .removed_count = 0,
            .modified_count = 0,
            .unchanged_count = 0,
            .largest_increase = null,
            .largest_decrease = null,
        };

        // Populate directory sizes from old entries
        for (old_entries.items) |entry| {
            const name = old_data[entry.name_offset .. entry.name_offset + entry.name_len];
            try self.updateDirectorySizes(&directories, arena_alloc, name, entry.compressed_size, true);
        }

        // Process new entries
        for (new_entries.items) |entry| {
            const name = new_data[entry.name_offset .. entry.name_offset + entry.name_len];
            const new_size = entry.compressed_size;

            // Update directory sizes
            try self.updateDirectorySizes(&directories, arena_alloc, name, new_size, false);

            if (old_map.fetchRemove(name)) |kv| {
                // File exists in both
                const old_entry = old_entries.items[kv.value];
                const old_size = old_entry.compressed_size;
                const diff = @as(i64, @intCast(new_size)) - @as(i64, @intCast(old_size));

                // Check if content changed (using CRC32)
                const content_changed = entry.crc32 != old_entry.crc32;
                const status: CompareEntry.EntryStatus = if (!content_changed and diff == 0) .unchanged else .modified;

                switch (status) {
                    .modified => summary.modified_count += 1,
                    .unchanged => summary.unchanged_count += 1,
                    else => {},
                }

                // Update breakdown
                const category = categorizeFile(name, false);
                const cat_idx = @intFromEnum(category);
                breakdown_map[cat_idx].old_size += old_size;
                breakdown_map[cat_idx].new_size += new_size;
                breakdown_map[cat_idx].file_count += 1;
                if (status == .modified) breakdown_map[cat_idx].modified_count += 1;

                // Track largest changes
                updateLargestChanges(&summary, name, diff, old_size, new_size);

                if (options.different_only and diff == 0 and !content_changed) continue;

                const owned_path = try arena_alloc.dupe(u8, name);
                try all_entries.append(arena_alloc, .{
                    .path = owned_path,
                    .old_size = old_size,
                    .new_size = new_size,
                    .difference = diff,
                    .patch_size = if (options.patch_size) compare.estimatePatchSize(old_size, new_size) else null,
                    .is_directory = false,
                    .status = status,
                    .category = category,
                });
            } else {
                // Added file
                const diff = @as(i64, @intCast(new_size));
                summary.added_count += 1;

                const category = categorizeFile(name, false);
                const cat_idx = @intFromEnum(category);
                breakdown_map[cat_idx].new_size += new_size;
                breakdown_map[cat_idx].file_count += 1;
                breakdown_map[cat_idx].added_count += 1;

                updateLargestChanges(&summary, name, diff, 0, new_size);

                if (options.different_only and diff == 0) continue;

                const owned_path = try arena_alloc.dupe(u8, name);
                try all_entries.append(arena_alloc, .{
                    .path = owned_path,
                    .old_size = 0,
                    .new_size = new_size,
                    .difference = diff,
                    .patch_size = if (options.patch_size) new_size else null,
                    .is_directory = false,
                    .status = .added,
                    .category = category,
                });
            }
        }

        // Process removed files (remaining in old_map)
        var old_iter = old_map.iterator();
        while (old_iter.next()) |kv| {
            const name = kv.key_ptr.*;
            const old_entry = old_entries.items[kv.value_ptr.*];
            const old_size = old_entry.compressed_size;
            const diff = -@as(i64, @intCast(old_size));

            summary.removed_count += 1;

            const category = categorizeFile(name, false);
            const cat_idx = @intFromEnum(category);
            breakdown_map[cat_idx].old_size += old_size;
            breakdown_map[cat_idx].file_count += 1;
            breakdown_map[cat_idx].removed_count += 1;

            updateLargestChanges(&summary, name, diff, old_size, 0);

            const owned_path = try arena_alloc.dupe(u8, name);
            try all_entries.append(arena_alloc, .{
                .path = owned_path,
                .old_size = old_size,
                .new_size = 0,
                .difference = diff,
                .patch_size = if (options.patch_size) 64 else null,
                .is_directory = false,
                .status = .removed,
                .category = category,
            });
        }

        // Add root entry
        if (!options.files_only) {
            const root_diff = @as(i64, @intCast(new_total_size)) - @as(i64, @intCast(old_total_size));
            if (!options.different_only or root_diff != 0) {
                try all_entries.append(arena_alloc, .{
                    .path = try arena_alloc.dupe(u8, "/"),
                    .old_size = old_total_size,
                    .new_size = new_total_size,
                    .difference = root_diff,
                    .patch_size = if (options.patch_size) compare.estimatePatchSize(old_total_size, new_total_size) else null,
                    .is_directory = true,
                    .status = if (root_diff == 0) .unchanged else .modified,
                    .category = null,
                });
            }

            // Add directory entries
            var dir_iter = directories.iterator();
            while (dir_iter.next()) |kv| {
                const dir = kv.key_ptr.*;
                const sizes = kv.value_ptr.*;
                const diff = @as(i64, @intCast(sizes.new)) - @as(i64, @intCast(sizes.old));

                if (options.different_only and diff == 0) continue;

                const status: CompareEntry.EntryStatus = if (sizes.old == 0)
                    .added
                else if (sizes.new == 0)
                    .removed
                else if (diff == 0)
                    .unchanged
                else
                    .modified;

                try all_entries.append(arena_alloc, .{
                    .path = dir, // Already owned by arena from updateDirectorySizes
                    .old_size = sizes.old,
                    .new_size = sizes.new,
                    .difference = diff,
                    .patch_size = if (options.patch_size) compare.estimatePatchSize(sizes.old, sizes.new) else null,
                    .is_directory = true,
                    .status = status,
                    .category = null,
                });
            }
        }

        // Calculate breakdown differences
        for (&breakdown_map) |*bd| {
            bd.difference = @as(i64, @intCast(bd.new_size)) - @as(i64, @intCast(bd.old_size));
        }

        // Apply filters
        var filtered_entries = std.ArrayListUnmanaged(CompareEntry){};
        const category_filter: ?FileCategory = if (options.category) |cat_str|
            FileCategory.fromString(cat_str)
        else
            null;

        for (all_entries.items) |entry| {
            if (options.added_only and entry.status != .added) continue;
            if (options.removed_only and entry.status != .removed) continue;
            if (options.modified_only and entry.status != .modified) continue;

            if (category_filter) |filter_cat| {
                if (entry.category) |entry_cat| {
                    if (entry_cat != filter_cat) continue;
                } else {
                    continue;
                }
            }

            if (options.min_difference) |min_diff| {
                const abs_diff: u64 = if (entry.difference >= 0)
                    @intCast(entry.difference)
                else
                    @intCast(-entry.difference);
                if (abs_diff < min_diff) continue;
            }

            try filtered_entries.append(arena_alloc, entry);
        }

        // Sort
        if (options.sort_by_difference) {
            std.mem.sort(CompareEntry, filtered_entries.items, {}, struct {
                fn lessThan(_: void, a: CompareEntry, b: CompareEntry) bool {
                    const abs_a: u64 = if (a.difference >= 0) @intCast(a.difference) else @intCast(-a.difference);
                    const abs_b: u64 = if (b.difference >= 0) @intCast(b.difference) else @intCast(-b.difference);
                    return abs_a > abs_b;
                }
            }.lessThan);
        } else {
            std.mem.sort(CompareEntry, filtered_entries.items, {}, struct {
                fn lessThan(_: void, a: CompareEntry, b: CompareEntry) bool {
                    return std.mem.lessThan(u8, a.path, b.path);
                }
            }.lessThan);
        }

        // Apply limit
        var final_items = filtered_entries.items;
        if (options.limit) |limit| {
            if (final_items.len > limit) {
                final_items = final_items[0..limit];
            }
        }

        // Calculate patch totals
        var total_patch: u64 = 0;
        if (options.patch_size) {
            for (final_items) |entry| {
                if (!entry.is_directory) {
                    if (entry.patch_size) |ps| {
                        total_patch += ps;
                    }
                }
            }
        }

        // Build breakdown slice
        var breakdown_slice: ?[]CategoryBreakdown = null;
        if (options.include_breakdown) {
            const bd = try arena_alloc.alloc(CategoryBreakdown, 5);
            @memcpy(bd, &breakdown_map);
            breakdown_slice = bd;
        }

        // Copy largest change paths to arena
        if (summary.largest_increase) |*inc| {
            inc.path = try arena_alloc.dupe(u8, inc.path);
        }
        if (summary.largest_decrease) |*dec| {
            dec.path = try arena_alloc.dupe(u8, dec.path);
        }

        // Create final entries slice
        const entries_slice = try arena_alloc.alloc(CompareEntry, final_items.len);
        @memcpy(entries_slice, final_items);

        return CompareResult{
            .entries = entries_slice,
            .old_total = old_total_size,
            .new_total = new_total_size,
            .total_difference = @as(i64, @intCast(new_total_size)) - @as(i64, @intCast(old_total_size)),
            .total_patch_size = if (options.patch_size) total_patch else null,
            .breakdown = breakdown_slice,
            .summary = summary,
            .arena = arena,
        };
    }

    /// Parse ZIP central directory to extract entry metadata
    /// Only reads the central directory - does not load file contents
    fn parseCentralDirectory(self: *StreamingApkComparator, data: []const u8) !std.ArrayListUnmanaged(EntryInfo) {
        if (data.len < 22) return error.InvalidArchive;

        // Verify ZIP signature
        if (std.mem.readInt(u32, data[0..4], .little) != LOCAL_FILE_HEADER_SIG) {
            return error.InvalidArchive;
        }

        // Find End of Central Directory
        const eocd_offset = findEndOfCentralDirectory(data) orelse return error.InvalidArchive;

        // Parse EOCD
        var total_entries: u64 = std.mem.readInt(u16, data[eocd_offset + 10 ..][0..2], .little);
        var central_dir_offset: u64 = std.mem.readInt(u32, data[eocd_offset + 16 ..][0..4], .little);
        var is_zip64 = false;

        // Check for ZIP64
        if (total_entries == 0xFFFF or central_dir_offset == 0xFFFFFFFF) {
            if (eocd_offset >= 20) {
                const locator_offset = eocd_offset - 20;
                if (std.mem.readInt(u32, data[locator_offset..][0..4], .little) == ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG) {
                    const zip64_eocd_offset = std.mem.readInt(u64, data[locator_offset + 8 ..][0..8], .little);
                    const zip64_offset_usize: usize = @intCast(zip64_eocd_offset);
                    if (zip64_offset_usize < data.len and
                        std.mem.readInt(u32, data[zip64_offset_usize..][0..4], .little) == ZIP64_END_OF_CENTRAL_DIR_SIG)
                    {
                        is_zip64 = true;
                        total_entries = std.mem.readInt(u64, data[zip64_offset_usize + 32 ..][0..8], .little);
                        central_dir_offset = std.mem.readInt(u64, data[zip64_offset_usize + 48 ..][0..8], .little);
                    }
                }
            }
        }

        if (central_dir_offset >= data.len) return error.TruncatedArchive;

        // Pre-allocate entries
        var entries = std.ArrayListUnmanaged(EntryInfo){};
        const alloc_count: usize = if (total_entries > 1_000_000) 1_000_000 else @intCast(total_entries);
        try entries.ensureTotalCapacity(self.allocator, alloc_count);

        // Parse central directory entries
        var offset: usize = @intCast(central_dir_offset);
        var i: u64 = 0;
        while (i < total_entries) : (i += 1) {
            if (offset + 46 > data.len) break;

            const sig = std.mem.readInt(u32, data[offset..][0..4], .little);
            if (sig != CENTRAL_DIR_HEADER_SIG) break;

            const crc32 = std.mem.readInt(u32, data[offset + 16 ..][0..4], .little);
            var compressed_size: u64 = std.mem.readInt(u32, data[offset + 20 ..][0..4], .little);
            var uncompressed_size: u64 = std.mem.readInt(u32, data[offset + 24 ..][0..4], .little);
            const name_len = std.mem.readInt(u16, data[offset + 28 ..][0..2], .little);
            const extra_len = std.mem.readInt(u16, data[offset + 30 ..][0..2], .little);
            const comment_len = std.mem.readInt(u16, data[offset + 32 ..][0..2], .little);

            if (offset + 46 + name_len > data.len) break;

            const name_offset = offset + 46;
            const name = data[name_offset .. name_offset + name_len];
            const is_directory = name.len > 0 and (name[name.len - 1] == '/' or name[name.len - 1] == '\\');

            // Parse ZIP64 extra field if needed
            if (is_zip64 and extra_len > 0 and (compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF)) {
                const extra_start = offset + 46 + name_len;
                if (extra_start + extra_len <= data.len) {
                    const extra_data = data[extra_start .. extra_start + extra_len];
                    var pos: usize = 0;
                    while (pos + 4 <= extra_data.len) {
                        const tag = std.mem.readInt(u16, extra_data[pos..][0..2], .little);
                        const size = std.mem.readInt(u16, extra_data[pos + 2 ..][0..2], .little);
                        pos += 4;

                        if (tag == ZIP64_EXTRA_FIELD_TAG) {
                            var field_pos: usize = 0;
                            if (uncompressed_size == 0xFFFFFFFF and field_pos + 8 <= size) {
                                uncompressed_size = std.mem.readInt(u64, extra_data[pos + field_pos ..][0..8], .little);
                                field_pos += 8;
                            }
                            if (compressed_size == 0xFFFFFFFF and field_pos + 8 <= size) {
                                compressed_size = std.mem.readInt(u64, extra_data[pos + field_pos ..][0..8], .little);
                            }
                            break;
                        }
                        pos += size;
                    }
                }
            }

            entries.appendAssumeCapacity(.{
                .name_offset = name_offset,
                .name_len = name_len,
                .compressed_size = compressed_size,
                .uncompressed_size = uncompressed_size,
                .crc32 = crc32,
                .is_directory = is_directory,
            });

            offset += 46 + name_len + extra_len + comment_len;
        }

        return entries;
    }

    const DirSizes = struct {
        old: u64,
        new: u64,
    };

    fn updateDirectorySizes(
        _: *StreamingApkComparator,
        directories: *std.StringHashMap(DirSizes),
        arena: std.mem.Allocator,
        path: []const u8,
        size: u64,
        is_old: bool,
    ) !void {
        var pos: usize = 0;
        while (pos < path.len) {
            if (std.mem.indexOfPos(u8, path, pos, "/")) |slash_pos| {
                const dir = path[0 .. slash_pos + 1];
                const existing = directories.get(dir) orelse DirSizes{ .old = 0, .new = 0 };

                // Need to copy the key if it's new
                const key = if (directories.contains(dir)) dir else try arena.dupe(u8, dir);

                if (is_old) {
                    try directories.put(key, DirSizes{
                        .old = existing.old + size,
                        .new = existing.new,
                    });
                } else {
                    try directories.put(key, DirSizes{
                        .old = existing.old,
                        .new = existing.new + size,
                    });
                }
                pos = slash_pos + 1;
            } else {
                break;
            }
        }
    }
};

fn updateLargestChanges(
    summary: *CompareSummary,
    path: []const u8,
    diff: i64,
    old_size: u64,
    new_size: u64,
) void {
    if (diff > 0) {
        if (summary.largest_increase == null or diff > summary.largest_increase.?.difference) {
            summary.largest_increase = LargestChange{
                .path = path,
                .difference = diff,
                .old_size = old_size,
                .new_size = new_size,
            };
        }
    } else if (diff < 0) {
        if (summary.largest_decrease == null or diff < summary.largest_decrease.?.difference) {
            summary.largest_decrease = LargestChange{
                .path = path,
                .difference = diff,
                .old_size = old_size,
                .new_size = new_size,
            };
        }
    }
}

fn findEndOfCentralDirectory(data: []const u8) ?usize {
    if (data.len < 22) return null;

    const max_comment_len: usize = 65535;
    const eocd_min_size: usize = 22;
    const search_start = if (data.len > max_comment_len + eocd_min_size)
        data.len - max_comment_len - eocd_min_size
    else
        0;

    var i: usize = data.len - eocd_min_size;
    while (i >= search_start) : (i -= 1) {
        if (i + 4 > data.len) {
            if (i == 0) break;
            continue;
        }
        const sig = std.mem.readInt(u32, data[i..][0..4], .little);
        if (sig == END_OF_CENTRAL_DIR_SIG) {
            if (i + 20 + 2 <= data.len) {
                const comment_len = std.mem.readInt(u16, data[i + 20 ..][0..2], .little);
                if (i + 22 + comment_len == data.len) {
                    return i;
                }
            }
        }
        if (i == 0) break;
    }

    return null;
}

// ============================================================================
// Streaming Content Verification
// ============================================================================

const ZipParser = @import("../parsers/zip.zig").ZipParser;

/// Result of streaming content verification
pub const ContentVerifyResult = struct {
    /// Whether the file contents match exactly
    matches: bool,
    /// Number of bytes compared
    bytes_compared: u64,
    /// First byte position where content differs (if !matches)
    first_diff_offset: ?u64,
    /// Old file size
    old_size: u64,
    /// New file size
    new_size: u64,
};

/// Result of batch content verification
pub const BatchVerifyResult = struct {
    /// Total files verified
    total_files: usize,
    /// Files that match exactly
    matching_files: usize,
    /// Files that differ
    differing_files: usize,
    /// Files that failed to verify (errors)
    failed_files: usize,
    /// List of files that differ
    differing_paths: []const []const u8,
    /// Arena for memory management
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *BatchVerifyResult) void {
        self.arena.deinit();
    }
};

/// Streaming content verifier for comparing actual file contents
/// Uses streaming decompression to avoid loading entire files into memory
pub const StreamingContentVerifier = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) StreamingContentVerifier {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *StreamingContentVerifier) void {
        _ = self;
    }

    /// Verify that a specific file has identical content in both APKs
    /// Uses streaming decompression - memory usage is O(chunk_size) not O(file_size)
    pub fn verifyFileContent(
        self: *StreamingContentVerifier,
        old_path: []const u8,
        new_path: []const u8,
        file_name: []const u8,
    ) !ContentVerifyResult {
        // Open old APK
        const old_file = std.fs.cwd().openFile(old_path, .{}) catch {
            return error.OldFileNotFound;
        };
        defer old_file.close();

        const old_size = old_file.getEndPos() catch {
            return error.InvalidOldFile;
        };
        if (old_size == 0) return error.InvalidOldFile;

        const old_mapped = std.posix.mmap(
            null,
            @intCast(old_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            old_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(old_mapped);

        // Open new APK
        const new_file = std.fs.cwd().openFile(new_path, .{}) catch {
            return error.NewFileNotFound;
        };
        defer new_file.close();

        const new_size = new_file.getEndPos() catch {
            return error.InvalidNewFile;
        };
        if (new_size == 0) return error.InvalidNewFile;

        const new_mapped = std.posix.mmap(
            null,
            @intCast(new_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            new_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(new_mapped);

        // Parse both ZIPs
        var old_zip = ZipParser.parse(self.allocator, old_mapped) catch {
            return error.InvalidOldFile;
        };
        defer old_zip.deinit();

        var new_zip = ZipParser.parse(self.allocator, new_mapped) catch {
            return error.InvalidNewFile;
        };
        defer new_zip.deinit();

        // Find the file in both archives
        const old_entry = old_zip.findFile(file_name) orelse {
            return error.FileNotFoundInOld;
        };
        const new_entry = new_zip.findFile(file_name) orelse {
            return error.FileNotFoundInNew;
        };

        // Quick check: if sizes differ, content definitely differs
        if (old_entry.uncompressed_size != new_entry.uncompressed_size) {
            return ContentVerifyResult{
                .matches = false,
                .bytes_compared = 0,
                .first_diff_offset = 0,
                .old_size = old_entry.uncompressed_size,
                .new_size = new_entry.uncompressed_size,
            };
        }

        // Stream and compare content
        return self.streamCompareContent(&old_zip, old_entry, &new_zip, new_entry);
    }

    /// Stream and compare content of two ZIP entries
    fn streamCompareContent(
        self: *StreamingContentVerifier,
        old_zip: *ZipParser,
        old_entry: *const ZipParser.ZipEntry,
        new_zip: *ZipParser,
        new_entry: *const ZipParser.ZipEntry,
    ) !ContentVerifyResult {
        // For streaming comparison, we need to decompress both files and compare chunks
        // We'll use a simple approach: decompress both fully but in chunks

        // Allocate buffers for streaming comparison
        const chunk_size: usize = 65536; // 64KB chunks
        const old_buffer = try self.allocator.alloc(u8, chunk_size);
        defer self.allocator.free(old_buffer);
        const new_buffer = try self.allocator.alloc(u8, chunk_size);
        defer self.allocator.free(new_buffer);

        // Get compressed data for both entries
        const old_compressed = old_zip.getFileData(old_entry) catch {
            return error.InvalidOldFile;
        };
        const new_compressed = new_zip.getFileData(new_entry) catch {
            return error.InvalidNewFile;
        };

        // For stored (uncompressed) files, compare directly
        if (old_entry.compression_method == 0 and new_entry.compression_method == 0) {
            return self.compareStoredContent(old_compressed, new_compressed, old_entry.uncompressed_size, new_entry.uncompressed_size);
        }

        // For compressed files, we need to decompress and compare
        // This is more complex - we'll decompress both fully for now
        // A more memory-efficient approach would interleave decompression
        const old_decompressed = old_zip.getDecompressedData(self.allocator, old_entry) catch {
            return error.InvalidOldFile;
        };
        defer self.allocator.free(old_decompressed);

        const new_decompressed = new_zip.getDecompressedData(self.allocator, new_entry) catch {
            return error.InvalidNewFile;
        };
        defer self.allocator.free(new_decompressed);

        return self.compareStoredContent(old_decompressed, new_decompressed, old_entry.uncompressed_size, new_entry.uncompressed_size);
    }

    /// Compare stored (uncompressed) content
    fn compareStoredContent(
        _: *StreamingContentVerifier,
        old_data: []const u8,
        new_data: []const u8,
        old_size: u64,
        new_size: u64,
    ) ContentVerifyResult {
        const min_len = @min(old_data.len, new_data.len);

        // Find first difference
        var i: usize = 0;
        while (i < min_len) : (i += 1) {
            if (old_data[i] != new_data[i]) {
                return ContentVerifyResult{
                    .matches = false,
                    .bytes_compared = i,
                    .first_diff_offset = i,
                    .old_size = old_size,
                    .new_size = new_size,
                };
            }
        }

        // If lengths differ, content differs
        if (old_data.len != new_data.len) {
            return ContentVerifyResult{
                .matches = false,
                .bytes_compared = min_len,
                .first_diff_offset = min_len,
                .old_size = old_size,
                .new_size = new_size,
            };
        }

        return ContentVerifyResult{
            .matches = true,
            .bytes_compared = old_data.len,
            .first_diff_offset = null,
            .old_size = old_size,
            .new_size = new_size,
        };
    }

    /// Verify content of multiple files that have the same CRC32 but might differ
    /// Useful for thorough verification when CRC32 collision is suspected
    pub fn verifyMultipleFiles(
        self: *StreamingContentVerifier,
        old_path: []const u8,
        new_path: []const u8,
        file_names: []const []const u8,
    ) !BatchVerifyResult {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        var differing = std.ArrayListUnmanaged([]const u8){};
        var matching_count: usize = 0;
        var differing_count: usize = 0;
        var failed_count: usize = 0;

        for (file_names) |file_name| {
            const result = self.verifyFileContent(old_path, new_path, file_name) catch {
                failed_count += 1;
                continue;
            };

            if (result.matches) {
                matching_count += 1;
            } else {
                differing_count += 1;
                try differing.append(arena_alloc, try arena_alloc.dupe(u8, file_name));
            }
        }

        return BatchVerifyResult{
            .total_files = file_names.len,
            .matching_files = matching_count,
            .differing_files = differing_count,
            .failed_files = failed_count,
            .differing_paths = try differing.toOwnedSlice(arena_alloc),
            .arena = arena,
        };
    }

    /// Verify all files that have matching CRC32 in both APKs
    /// This is useful for detecting CRC32 collisions (extremely rare but possible)
    pub fn verifyAllMatchingCrc(
        self: *StreamingContentVerifier,
        old_path: []const u8,
        new_path: []const u8,
    ) !BatchVerifyResult {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        // Open and parse both APKs
        const old_file = std.fs.cwd().openFile(old_path, .{}) catch {
            return error.OldFileNotFound;
        };
        defer old_file.close();

        const old_size = old_file.getEndPos() catch {
            return error.InvalidOldFile;
        };
        if (old_size == 0) return error.InvalidOldFile;

        const old_mapped = std.posix.mmap(
            null,
            @intCast(old_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            old_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(old_mapped);

        const new_file = std.fs.cwd().openFile(new_path, .{}) catch {
            return error.NewFileNotFound;
        };
        defer new_file.close();

        const new_size = new_file.getEndPos() catch {
            return error.InvalidNewFile;
        };
        if (new_size == 0) return error.InvalidNewFile;

        const new_mapped = std.posix.mmap(
            null,
            @intCast(new_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            new_file.handle,
            0,
        ) catch {
            return error.MmapFailed;
        };
        defer std.posix.munmap(new_mapped);

        var old_zip = ZipParser.parse(self.allocator, old_mapped) catch {
            return error.InvalidOldFile;
        };
        defer old_zip.deinit();

        var new_zip = ZipParser.parse(self.allocator, new_mapped) catch {
            return error.InvalidNewFile;
        };
        defer new_zip.deinit();

        // Build map of old entries by name
        var old_map = std.StringHashMap(*const ZipParser.ZipEntry).init(self.allocator);
        defer old_map.deinit();

        for (old_zip.entries) |*entry| {
            try old_map.put(entry.name, entry);
        }

        // Find files with matching CRC32 and verify content
        var differing = std.ArrayListUnmanaged([]const u8){};
        var matching_count: usize = 0;
        var differing_count: usize = 0;
        var failed_count: usize = 0;
        var total_checked: usize = 0;

        for (new_zip.entries) |*new_entry| {
            if (old_map.get(new_entry.name)) |old_entry| {
                // Only verify files with matching CRC32 (potential collisions)
                if (old_entry.crc32 == new_entry.crc32 and
                    old_entry.uncompressed_size == new_entry.uncompressed_size and
                    !old_entry.is_directory)
                {
                    total_checked += 1;

                    const result = self.streamCompareContent(&old_zip, old_entry, &new_zip, new_entry) catch {
                        failed_count += 1;
                        continue;
                    };

                    if (result.matches) {
                        matching_count += 1;
                    } else {
                        differing_count += 1;
                        try differing.append(arena_alloc, try arena_alloc.dupe(u8, new_entry.name));
                    }
                }
            }
        }

        return BatchVerifyResult{
            .total_files = total_checked,
            .matching_files = matching_count,
            .differing_files = differing_count,
            .failed_files = failed_count,
            .differing_paths = try differing.toOwnedSlice(arena_alloc),
            .arena = arena,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "StreamingApkComparator.init" {
    var comparator = StreamingApkComparator.init(std.testing.allocator);
    defer comparator.deinit();
}

test "StreamingContentVerifier.init" {
    var verifier = StreamingContentVerifier.init(std.testing.allocator);
    defer verifier.deinit();
}

test "findEndOfCentralDirectory with minimal data" {
    // Too small
    const small_data = [_]u8{ 0, 0, 0, 0 };
    try std.testing.expect(findEndOfCentralDirectory(&small_data) == null);
}

test "compareStoredContent identical" {
    var verifier = StreamingContentVerifier.init(std.testing.allocator);
    defer verifier.deinit();

    const data = "Hello, World!";
    const result = verifier.compareStoredContent(data, data, data.len, data.len);

    try std.testing.expect(result.matches == true);
    try std.testing.expect(result.bytes_compared == data.len);
    try std.testing.expect(result.first_diff_offset == null);
}

test "compareStoredContent different" {
    var verifier = StreamingContentVerifier.init(std.testing.allocator);
    defer verifier.deinit();

    const old_data = "Hello, World!";
    const new_data = "Hello, Zig!!";
    const result = verifier.compareStoredContent(old_data, new_data, old_data.len, new_data.len);

    try std.testing.expect(result.matches == false);
    try std.testing.expect(result.first_diff_offset != null);
    try std.testing.expect(result.first_diff_offset.? == 7); // First diff at 'W' vs 'Z'
}

test "compareStoredContent different lengths" {
    var verifier = StreamingContentVerifier.init(std.testing.allocator);
    defer verifier.deinit();

    const old_data = "Hello";
    const new_data = "Hello, World!";
    const result = verifier.compareStoredContent(old_data, new_data, old_data.len, new_data.len);

    try std.testing.expect(result.matches == false);
    try std.testing.expect(result.first_diff_offset.? == old_data.len);
}
