//! APK Comparison Tool
//!
//! Compares the sizes of two APK files, showing differences in file sizes
//! and optionally estimating patch sizes for delta updates.
//!
//! ## Output Format
//!
//! The output shows: old size / new size / size difference / path
//!
//! Example:
//! ```
//! 39086736 48855615 9768879 /
//! 10678448 11039232 360784 /classes.dex
//! 18968956 18968956 0 /lib/
//! 110576 110100 -476 /AndroidManifest.xml
//! ```
//!
//! ## Usage
//!
//! ```zig
//! const compare = @import("compare.zig");
//!
//! var comparator = compare.ApkComparator.init(allocator);
//! defer comparator.deinit();
//!
//! const result = try comparator.compare(old_apk_data, new_apk_data, .{
//!     .different_only = true,
//!     .files_only = false,
//!     .patch_size = false,
//!     .include_breakdown = true,
//! });
//! defer result.deinit();
//!
//! for (result.entries) |entry| {
//!     std.debug.print("{d} {d} {d} {s}\n", .{
//!         entry.old_size, entry.new_size, entry.difference, entry.path,
//!     });
//! }
//! ```

const std = @import("std");
const zip = @import("../parsers/zip.zig");

/// File category for breakdown analysis
pub const FileCategory = enum {
    dex,
    native,
    resources,
    assets,
    other,

    pub fn toString(self: FileCategory) []const u8 {
        return switch (self) {
            .dex => "dex",
            .native => "native",
            .resources => "resources",
            .assets => "assets",
            .other => "other",
        };
    }

    pub fn fromString(str: []const u8) ?FileCategory {
        const map = std.StaticStringMap(FileCategory).initComptime(.{
            .{ "dex", .dex },
            .{ "native", .native },
            .{ "resources", .resources },
            .{ "assets", .assets },
            .{ "other", .other },
        });
        return map.get(str);
    }
};

/// Categorize a file based on its path
pub fn categorizeFile(path: []const u8, is_directory: bool) FileCategory {
    if (is_directory) return .other;

    // DEX files
    if (std.mem.endsWith(u8, path, ".dex")) return .dex;

    // Native libraries
    if (std.mem.indexOf(u8, path, "lib/") != null and std.mem.endsWith(u8, path, ".so")) return .native;
    if (std.mem.endsWith(u8, path, ".so")) return .native;

    // Resources
    if (std.mem.startsWith(u8, path, "res/")) return .resources;
    if (std.mem.eql(u8, path, "resources.arsc")) return .resources;
    if (std.mem.endsWith(u8, path, ".xml") and !std.mem.startsWith(u8, path, "assets/")) return .resources;

    // Assets
    if (std.mem.startsWith(u8, path, "assets/")) return .assets;

    return .other;
}

/// Category breakdown entry
pub const CategoryBreakdown = struct {
    category: FileCategory,
    old_size: u64,
    new_size: u64,
    difference: i64,
    file_count: u32,
    added_count: u32,
    removed_count: u32,
    modified_count: u32,
};

/// Largest change entry for summary
pub const LargestChange = struct {
    path: []const u8,
    difference: i64,
    old_size: u64,
    new_size: u64,
};

/// Summary statistics for comparison
pub const CompareSummary = struct {
    /// Total number of files in old archive
    old_file_count: u32,
    /// Total number of files in new archive
    new_file_count: u32,
    /// Number of added files
    added_count: u32,
    /// Number of removed files
    removed_count: u32,
    /// Number of modified files
    modified_count: u32,
    /// Number of unchanged files
    unchanged_count: u32,
    /// Largest size increase (file path and difference)
    largest_increase: ?LargestChange,
    /// Largest size decrease (file path and difference)
    largest_decrease: ?LargestChange,
};

/// Comparison entry for a single file or directory
pub const CompareEntry = struct {
    /// File or directory path (owned by CompareResult arena)
    path: []const u8,
    /// Size in old APK (0 if not present)
    old_size: u64,
    /// Size in new APK (0 if not present)
    new_size: u64,
    /// Size difference (new - old, can be negative)
    difference: i64,
    /// Estimated patch size (if patch_size option enabled)
    patch_size: ?u64,
    /// Whether this is a directory
    is_directory: bool,
    /// Entry status
    status: EntryStatus,
    /// File category (null for directories)
    category: ?FileCategory,

    pub const EntryStatus = enum {
        /// File exists in both APKs
        modified,
        /// File only in new APK
        added,
        /// File only in old APK
        removed,
        /// File unchanged
        unchanged,
    };
};

/// Comparison result
/// All string data is owned by the internal arena allocator and freed on deinit()
pub const CompareResult = struct {
    /// All comparison entries
    entries: []CompareEntry,
    /// Total size of old APK
    old_total: u64,
    /// Total size of new APK
    new_total: u64,
    /// Total size difference
    total_difference: i64,
    /// Estimated total patch size (if enabled)
    total_patch_size: ?u64,
    /// Summary breakdown by category (if include_breakdown=true)
    breakdown: ?[]CategoryBreakdown,
    /// Summary statistics
    summary: CompareSummary,
    /// Arena allocator that owns all string data
    arena: std.heap.ArenaAllocator,

    /// Free all memory associated with this result
    pub fn deinit(self: *CompareResult) void {
        // Arena allocator frees everything at once - entries, breakdown, and all strings
        self.arena.deinit();
    }
};

/// Comparison options
pub const CompareOptions = struct {
    /// Only show files/directories with differences
    different_only: bool = false,
    /// Don't print directory entries
    files_only: bool = false,
    /// Show estimated file-by-file patch size instead of raw difference
    patch_size: bool = false,
    /// Include summary breakdown by file category
    include_breakdown: bool = false,
    /// Filter by minimum absolute size difference (bytes)
    min_difference: ?u64 = null,
    /// Filter by file category (dex, native, resources, assets, other)
    category: ?[]const u8 = null,
    /// Only show added files
    added_only: bool = false,
    /// Only show removed files
    removed_only: bool = false,
    /// Only show modified files
    modified_only: bool = false,
    /// Sort entries by difference (descending by absolute value)
    sort_by_difference: bool = false,
    /// Limit number of entries returned
    limit: ?u32 = null,
};

/// Compares two APK files
pub const ApkComparator = struct {
    allocator: std.mem.Allocator,

    /// Directory size tracking struct
    const DirSizes = struct {
        old: u64,
        new: u64,
    };

    pub fn init(allocator: std.mem.Allocator) ApkComparator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ApkComparator) void {
        _ = self;
    }

    /// Compare two APKs from memory
    pub fn compare(
        self: *ApkComparator,
        old_data: []const u8,
        new_data: []const u8,
        options: CompareOptions,
    ) !CompareResult {
        // Parse both archives
        var old_archive = zip.ZipParser.parse(self.allocator, old_data) catch {
            return error.InvalidOldArchive;
        };
        defer old_archive.deinit();

        var new_archive = zip.ZipParser.parse(self.allocator, new_data) catch {
            return error.InvalidNewArchive;
        };
        defer new_archive.deinit();

        return self.compareArchives(&old_archive, &new_archive, old_data.len, new_data.len, options);
    }

    /// Compare two APKs from file paths
    pub fn compareFiles(
        self: *ApkComparator,
        old_path: []const u8,
        new_path: []const u8,
        options: CompareOptions,
    ) !CompareResult {
        // Read old file
        const old_file = std.fs.cwd().openFile(old_path, .{}) catch {
            return error.OldFileNotFound;
        };
        defer old_file.close();

        const old_size = old_file.getEndPos() catch {
            return error.InvalidOldFile;
        };

        const old_data = old_file.readToEndAlloc(self.allocator, 200 * 1024 * 1024) catch {
            return error.OutOfMemory;
        };
        defer self.allocator.free(old_data);

        // Read new file
        const new_file = std.fs.cwd().openFile(new_path, .{}) catch {
            return error.NewFileNotFound;
        };
        defer new_file.close();

        const new_size = new_file.getEndPos() catch {
            return error.InvalidNewFile;
        };

        const new_data = new_file.readToEndAlloc(self.allocator, 200 * 1024 * 1024) catch {
            return error.OutOfMemory;
        };
        defer self.allocator.free(new_data);

        // Parse archives
        var old_archive = zip.ZipParser.parse(self.allocator, old_data) catch {
            return error.InvalidOldArchive;
        };
        defer old_archive.deinit();

        var new_archive = zip.ZipParser.parse(self.allocator, new_data) catch {
            return error.InvalidNewArchive;
        };
        defer new_archive.deinit();

        return self.compareArchives(&old_archive, &new_archive, old_size, new_size, options);
    }

    /// Internal comparison of parsed archives
    /// Uses arena allocator to own all string data, preventing use-after-free
    fn compareArchives(
        self: *ApkComparator,
        old_archive: *zip.ZipParser,
        new_archive: *zip.ZipParser,
        old_total_size: u64,
        new_total_size: u64,
        options: CompareOptions,
    ) !CompareResult {
        // Create arena allocator for result data - all strings will be owned here
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        var all_entries = std.ArrayListUnmanaged(CompareEntry){};

        // Build map for old files only (optimization: single map approach)
        // Key: path, Value: compressed_size
        var old_files = std.StringHashMap(u64).init(self.allocator);
        defer old_files.deinit();

        // Track directories with full hierarchy
        var directories = std.StringHashMap(DirSizes).init(self.allocator);
        defer directories.deinit();

        // Track breakdown by category (5 categories)
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

        // Track summary statistics
        var summary = CompareSummary{
            .old_file_count = 0,
            .new_file_count = 0,
            .added_count = 0,
            .removed_count = 0,
            .modified_count = 0,
            .unchanged_count = 0,
            .largest_increase = null,
            .largest_decrease = null,
        };

        // Populate old files map and track directory sizes
        for (old_archive.listFiles()) |entry| {
            try old_files.put(entry.name, entry.compressed_size);
            summary.old_file_count += 1;

            // Track ALL ancestor directory sizes (fix for incorrect aggregation)
            try self.updateDirectorySizes(&directories, entry.name, entry.compressed_size, true);
        }

        // Process new archive - single pass algorithm
        // Files found in old_files -> Modified/Unchanged, remove from old_files
        // Files not found -> Added
        // Remaining in old_files after loop -> Removed
        for (new_archive.listFiles()) |entry| {
            summary.new_file_count += 1;

            // Track directory sizes for new archive
            try self.updateDirectorySizes(&directories, entry.name, entry.compressed_size, false);

            const new_size = entry.compressed_size;

            if (old_files.fetchRemove(entry.name)) |kv| {
                // File exists in both archives
                const old_size = kv.value;
                const diff = @as(i64, @intCast(new_size)) - @as(i64, @intCast(old_size));

                const status: CompareEntry.EntryStatus = if (diff == 0) .unchanged else .modified;

                // Update summary counts
                switch (status) {
                    .modified => summary.modified_count += 1,
                    .unchanged => summary.unchanged_count += 1,
                    else => {},
                }

                // Update breakdown
                const category = categorizeFile(entry.name, false);
                const cat_idx = @intFromEnum(category);
                breakdown_map[cat_idx].old_size += old_size;
                breakdown_map[cat_idx].new_size += new_size;
                breakdown_map[cat_idx].file_count += 1;
                if (status == .modified) breakdown_map[cat_idx].modified_count += 1;

                // Track largest changes
                self.updateLargestChanges(&summary, entry.name, diff, old_size, new_size);

                if (options.different_only and diff == 0) continue;

                // Copy path to arena (fix for use-after-free)
                const owned_path = try arena_alloc.dupe(u8, entry.name);

                try all_entries.append(arena_alloc, .{
                    .path = owned_path,
                    .old_size = old_size,
                    .new_size = new_size,
                    .difference = diff,
                    .patch_size = if (options.patch_size) estimatePatchSize(old_size, new_size) else null,
                    .is_directory = false,
                    .status = status,
                    .category = category,
                });
            } else {
                // File only in new archive (added)
                const diff = @as(i64, @intCast(new_size));
                summary.added_count += 1;

                // Update breakdown
                const category = categorizeFile(entry.name, false);
                const cat_idx = @intFromEnum(category);
                breakdown_map[cat_idx].new_size += new_size;
                breakdown_map[cat_idx].file_count += 1;
                breakdown_map[cat_idx].added_count += 1;

                // Track largest increase
                self.updateLargestChanges(&summary, entry.name, diff, 0, new_size);

                if (options.different_only and diff == 0) continue;

                // Copy path to arena
                const owned_path = try arena_alloc.dupe(u8, entry.name);

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

        // Process remaining files in old_files (removed files)
        var old_iter = old_files.iterator();
        while (old_iter.next()) |kv| {
            const path = kv.key_ptr.*;
            const old_size = kv.value_ptr.*;
            const diff = -@as(i64, @intCast(old_size));

            summary.removed_count += 1;

            // Update breakdown
            const category = categorizeFile(path, false);
            const cat_idx = @intFromEnum(category);
            breakdown_map[cat_idx].old_size += old_size;
            breakdown_map[cat_idx].file_count += 1;
            breakdown_map[cat_idx].removed_count += 1;

            // Track largest decrease
            self.updateLargestChanges(&summary, path, diff, old_size, 0);

            // Copy path to arena
            const owned_path = try arena_alloc.dupe(u8, path);

            try all_entries.append(arena_alloc, .{
                .path = owned_path,
                .old_size = old_size,
                .new_size = 0,
                .difference = diff,
                .patch_size = if (options.patch_size) 64 else null, // Deletion marker
                .is_directory = false,
                .status = .removed,
                .category = category,
            });
        }

        // Add root entry
        const root_diff = @as(i64, @intCast(new_total_size)) - @as(i64, @intCast(old_total_size));
        if (!options.different_only or root_diff != 0) {
            if (!options.files_only) {
                try all_entries.append(arena_alloc, .{
                    .path = try arena_alloc.dupe(u8, "/"),
                    .old_size = old_total_size,
                    .new_size = new_total_size,
                    .difference = root_diff,
                    .patch_size = if (options.patch_size) estimatePatchSize(old_total_size, new_total_size) else null,
                    .is_directory = true,
                    .status = if (root_diff == 0) .unchanged else .modified,
                    .category = null,
                });
            }
        }

        // Add directory entries
        if (!options.files_only) {
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

                // Copy path to arena
                const owned_path = try arena_alloc.dupe(u8, dir);

                try all_entries.append(arena_alloc, .{
                    .path = owned_path,
                    .old_size = sizes.old,
                    .new_size = sizes.new,
                    .difference = diff,
                    .patch_size = if (options.patch_size) estimatePatchSize(sizes.old, sizes.new) else null,
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

        // Apply filters and build final entries
        var filtered_entries = std.ArrayListUnmanaged(CompareEntry){};

        // Parse category filter if provided
        const category_filter: ?FileCategory = if (options.category) |cat_str|
            FileCategory.fromString(cat_str)
        else
            null;

        for (all_entries.items) |entry| {
            // Apply status filters
            if (options.added_only and entry.status != .added) continue;
            if (options.removed_only and entry.status != .removed) continue;
            if (options.modified_only and entry.status != .modified) continue;

            // Apply category filter
            if (category_filter) |filter_cat| {
                if (entry.category) |entry_cat| {
                    if (entry_cat != filter_cat) continue;
                } else {
                    continue; // Skip directories when filtering by category
                }
            }

            // Apply min_difference filter
            if (options.min_difference) |min_diff| {
                const abs_diff: u64 = if (entry.difference >= 0)
                    @intCast(entry.difference)
                else
                    @intCast(-entry.difference);
                if (abs_diff < min_diff) continue;
            }

            try filtered_entries.append(arena_alloc, entry);
        }

        // Sort entries
        if (options.sort_by_difference) {
            std.mem.sort(CompareEntry, filtered_entries.items, {}, struct {
                fn lessThan(_: void, a: CompareEntry, b: CompareEntry) bool {
                    const abs_a: u64 = if (a.difference >= 0) @intCast(a.difference) else @intCast(-a.difference);
                    const abs_b: u64 = if (b.difference >= 0) @intCast(b.difference) else @intCast(-b.difference);
                    return abs_a > abs_b; // Descending order
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

        // Calculate totals
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

        // Build breakdown array if requested (use toOwnedSlice optimization)
        var breakdown_slice: ?[]CategoryBreakdown = null;
        if (options.include_breakdown) {
            const bd = try arena_alloc.alloc(CategoryBreakdown, 5);
            @memcpy(bd, &breakdown_map);
            breakdown_slice = bd;
        }

        // Copy largest change paths to arena to ensure they're owned
        if (summary.largest_increase) |*inc| {
            inc.path = try arena_alloc.dupe(u8, inc.path);
        }
        if (summary.largest_decrease) |*dec| {
            dec.path = try arena_alloc.dupe(u8, dec.path);
        }

        // Create final entries slice (use arena for ownership)
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

    /// Update directory sizes for ALL ancestor directories (fixes incorrect aggregation)
    /// For path "lib/arm64/libtest.so", adds size to both "lib/" and "lib/arm64/"
    fn updateDirectorySizes(
        _: *ApkComparator,
        directories: *std.StringHashMap(DirSizes),
        path: []const u8,
        size: u64,
        is_old: bool,
    ) !void {
        // Iterate through path and add size to each directory level
        var pos: usize = 0;
        while (pos < path.len) {
            if (std.mem.indexOfPos(u8, path, pos, "/")) |slash_pos| {
                const dir = path[0 .. slash_pos + 1];
                const existing = directories.get(dir) orelse DirSizes{ .old = 0, .new = 0 };

                if (is_old) {
                    try directories.put(dir, DirSizes{
                        .old = existing.old + size,
                        .new = existing.new,
                    });
                } else {
                    try directories.put(dir, DirSizes{
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

    /// Update largest increase/decrease tracking
    fn updateLargestChanges(
        self: *ApkComparator,
        summary: *CompareSummary,
        path: []const u8,
        diff: i64,
        old_size: u64,
        new_size: u64,
    ) void {
        _ = self;

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

    /// Write comparison result to writer in apkanalyzer-compatible format
    pub fn writeComparison(
        result: *const CompareResult,
        writer: anytype,
        options: CompareOptions,
    ) !void {
        for (result.entries) |entry| {
            if (options.files_only and entry.is_directory) continue;
            if (options.different_only and entry.difference == 0) continue;

            try writer.print("{d} {d} {d} ", .{
                entry.old_size,
                entry.new_size,
                entry.difference,
            });

            if (options.patch_size) {
                if (entry.patch_size) |ps| {
                    try writer.print("(patch: {d}) ", .{ps});
                }
            }

            try writer.print("/{s}\n", .{entry.path});
        }
    }
};

/// Estimate patch size for delta update using integer math (no floating point)
/// Delta compression typically achieves 30-50% of raw difference
pub fn estimatePatchSize(old_size: u64, new_size: u64) u64 {
    if (old_size == 0) {
        // New file - full size needed
        return new_size;
    }

    if (new_size == 0) {
        // Deleted file - minimal patch (just deletion marker)
        return 64;
    }

    if (old_size == new_size) {
        // Same size - might be unchanged or small diff
        // Estimate small patch for potential metadata changes
        return @min(new_size / 10, 1024);
    }

    // Calculate raw difference
    const raw_diff = if (new_size > old_size)
        new_size - old_size
    else
        old_size - new_size;

    // Apply patch size factor using integer math: (diff * 4) / 10 = 40%
    // This avoids floating point arithmetic entirely
    const estimated = (raw_diff * 4) / 10;

    // Minimum patch size of 64 bytes
    return @max(estimated, 64);
}

// ============================================================================
// Unit Tests
// ============================================================================

test "estimatePatchSize handles new file" {
    const patch_size = estimatePatchSize(0, 1000);
    try std.testing.expectEqual(@as(u64, 1000), patch_size);
}

test "estimatePatchSize handles deleted file" {
    const patch_size = estimatePatchSize(1000, 0);
    try std.testing.expectEqual(@as(u64, 64), patch_size);
}

test "estimatePatchSize handles same size" {
    const patch_size = estimatePatchSize(1000, 1000);
    try std.testing.expect(patch_size < 1000);
    try std.testing.expectEqual(@as(u64, 100), patch_size); // 1000 / 10
}

test "estimatePatchSize handles size increase" {
    const patch_size = estimatePatchSize(1000, 2000);
    // Raw diff = 1000, estimated = (1000 * 4) / 10 = 400
    try std.testing.expectEqual(@as(u64, 400), patch_size);
}

test "estimatePatchSize handles size decrease" {
    const patch_size = estimatePatchSize(2000, 1000);
    // Raw diff = 1000, estimated = (1000 * 4) / 10 = 400
    try std.testing.expectEqual(@as(u64, 400), patch_size);
}

test "estimatePatchSize minimum patch size" {
    // Very small difference should still return minimum 64
    const patch_size = estimatePatchSize(100, 110);
    // Raw diff = 10, estimated = (10 * 4) / 10 = 4, but min is 64
    try std.testing.expectEqual(@as(u64, 64), patch_size);
}

test "CompareEntry.EntryStatus values" {
    try std.testing.expectEqual(CompareEntry.EntryStatus.modified, CompareEntry.EntryStatus.modified);
    try std.testing.expectEqual(CompareEntry.EntryStatus.added, CompareEntry.EntryStatus.added);
    try std.testing.expectEqual(CompareEntry.EntryStatus.removed, CompareEntry.EntryStatus.removed);
    try std.testing.expectEqual(CompareEntry.EntryStatus.unchanged, CompareEntry.EntryStatus.unchanged);
}

test "categorizeFile identifies DEX files" {
    try std.testing.expectEqual(FileCategory.dex, categorizeFile("classes.dex", false));
    try std.testing.expectEqual(FileCategory.dex, categorizeFile("classes2.dex", false));
}

test "categorizeFile identifies native libraries" {
    try std.testing.expectEqual(FileCategory.native, categorizeFile("lib/arm64-v8a/libnative.so", false));
    try std.testing.expectEqual(FileCategory.native, categorizeFile("lib/armeabi-v7a/libapp.so", false));
}

test "categorizeFile identifies resources" {
    try std.testing.expectEqual(FileCategory.resources, categorizeFile("res/drawable/icon.png", false));
    try std.testing.expectEqual(FileCategory.resources, categorizeFile("resources.arsc", false));
    try std.testing.expectEqual(FileCategory.resources, categorizeFile("AndroidManifest.xml", false));
}

test "categorizeFile identifies assets" {
    try std.testing.expectEqual(FileCategory.assets, categorizeFile("assets/data.json", false));
    try std.testing.expectEqual(FileCategory.assets, categorizeFile("assets/fonts/custom.ttf", false));
}

test "categorizeFile returns other for unknown files" {
    try std.testing.expectEqual(FileCategory.other, categorizeFile("META-INF/MANIFEST.MF", false));
    try std.testing.expectEqual(FileCategory.other, categorizeFile("kotlin/kotlin.kotlin_builtins", false));
}

test "categorizeFile returns other for directories" {
    try std.testing.expectEqual(FileCategory.other, categorizeFile("lib/", true));
    try std.testing.expectEqual(FileCategory.other, categorizeFile("res/", true));
}

test "FileCategory.toString" {
    try std.testing.expectEqualStrings("dex", FileCategory.dex.toString());
    try std.testing.expectEqualStrings("native", FileCategory.native.toString());
    try std.testing.expectEqualStrings("resources", FileCategory.resources.toString());
    try std.testing.expectEqualStrings("assets", FileCategory.assets.toString());
    try std.testing.expectEqualStrings("other", FileCategory.other.toString());
}

test "FileCategory.fromString" {
    try std.testing.expectEqual(FileCategory.dex, FileCategory.fromString("dex").?);
    try std.testing.expectEqual(FileCategory.native, FileCategory.fromString("native").?);
    try std.testing.expectEqual(FileCategory.resources, FileCategory.fromString("resources").?);
    try std.testing.expectEqual(FileCategory.assets, FileCategory.fromString("assets").?);
    try std.testing.expectEqual(FileCategory.other, FileCategory.fromString("other").?);
    try std.testing.expectEqual(@as(?FileCategory, null), FileCategory.fromString("invalid"));
}
