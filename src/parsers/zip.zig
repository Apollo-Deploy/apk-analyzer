const std = @import("std");

/// ZIP parser with security validation - Optimized for high-performance extraction
/// Supports ZIP64 extensions for archives larger than 4GB
pub const ZipParser = struct {
    allocator: std.mem.Allocator,
    data: []const u8,
    entries: []ZipEntry,
    /// Map of filename -> index in entries slice.
    /// Uses StringContext with NO key allocation, pointing directly into self.data.
    entry_map: std.HashMapUnmanaged([]const u8, usize, std.hash_map.StringContext, 80),
    /// Whether this archive uses ZIP64 extensions
    is_zip64: bool,

    pub const ZipEntry = struct {
        name: []const u8,
        compressed_size: u64,
        uncompressed_size: u64,
        offset: u64,
        compression_method: u16,
        crc32: u32,
        is_directory: bool,
    };

    pub const ZipError = error{
        InvalidArchive,
        PathTraversal,
        OutOfMemory,
        TruncatedArchive,
        UnsupportedCompression,
    };

    /// Callback function type for streaming file data
    pub const StreamCallback = *const fn (chunk: []const u8) anyerror!void;

    const LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
    const CENTRAL_DIR_HEADER_SIG: u32 = 0x02014b50;
    const END_OF_CENTRAL_DIR_SIG: u32 = 0x06054b50;
    const ZIP64_END_OF_CENTRAL_DIR_SIG: u32 = 0x06064b50;
    const ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG: u32 = 0x07064b50;
    const ZIP64_EXTRA_FIELD_TAG: u16 = 0x0001;

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) ZipError!ZipParser {
        if (data.len < 22) return ZipError.InvalidArchive;
        if (!isZipArchive(data)) return ZipError.InvalidArchive;

        const eocd_offset = findEndOfCentralDirectory(data) orelse return ZipError.InvalidArchive;
        const eocd = parseEndOfCentralDirectory(data, eocd_offset) orelse return ZipError.InvalidArchive;

        // Check for ZIP64 format
        var is_zip64_archive = false;
        var total_entries: u64 = eocd.total_entries;
        var central_dir_offset: u64 = eocd.central_dir_offset;

        // Check if we need ZIP64 (values are 0xFFFF or 0xFFFFFFFF)
        if (eocd.total_entries == 0xFFFF or eocd.central_dir_offset == 0xFFFFFFFF) {
            // Try to find ZIP64 End of Central Directory Locator
            if (findZip64EndOfCentralDirLocator(data, eocd_offset)) |locator| {
                if (parseZip64EndOfCentralDirectory(data, locator.zip64_eocd_offset)) |zip64_eocd| {
                    is_zip64_archive = true;
                    total_entries = zip64_eocd.total_entries;
                    central_dir_offset = zip64_eocd.central_dir_offset;
                }
            }
        }

        if (central_dir_offset >= data.len) return ZipError.TruncatedArchive;

        // Pre-allocate entries
        var entries = std.ArrayListUnmanaged(ZipEntry){};
        errdefer entries.deinit(allocator);
        
        // Cap allocation to prevent OOM on malformed archives
        const alloc_count: usize = if (total_entries > 1_000_000) 1_000_000 else @intCast(total_entries);
        try entries.ensureTotalCapacity(allocator, alloc_count);

        // Initialize map with capacity to prevent rehashing.
        // We store indices (usize) instead of pointers to avoid validity issues
        // and to allow the map to look up into the dense entries array.
        var entry_map = std.HashMapUnmanaged([]const u8, usize, std.hash_map.StringContext, 80){};
        errdefer entry_map.deinit(allocator);
        try entry_map.ensureTotalCapacity(allocator, @intCast(alloc_count));

        var offset = central_dir_offset;
        var i: u64 = 0;
        while (i < total_entries) : (i += 1) {
            const cd_entry = parseCentralDirectoryEntry(data, offset, is_zip64_archive) orelse {
                entries.deinit(allocator);
                entry_map.deinit(allocator);
                return ZipError.TruncatedArchive;
            };

            if (containsPathTraversal(cd_entry.name)) {
                entries.deinit(allocator);
                entry_map.deinit(allocator);
                return ZipError.PathTraversal;
            }

            const zip_entry = ZipEntry{
                .name = cd_entry.name,
                .compressed_size = cd_entry.compressed_size,
                .uncompressed_size = cd_entry.uncompressed_size,
                .offset = cd_entry.offset,
                .compression_method = cd_entry.compression_method,
                .crc32 = cd_entry.crc32,
                .is_directory = cd_entry.is_directory,
            };

            // Store entry and put index into map.
            // putAssumeCapacityNoClobber is safe as we ensured capacity and ZIPs shouldn't have duplicate names.
            entry_map.putAssumeCapacityNoClobber(zip_entry.name, entries.items.len);
            entries.appendAssumeCapacity(zip_entry);

            offset += 46 + @as(u64, @intCast(cd_entry.name.len)) + cd_entry.extra_len + cd_entry.comment_len;
        }

        const owned_entries = entries.toOwnedSlice(allocator) catch {
            entries.deinit(allocator);
            entry_map.deinit(allocator);
            return ZipError.OutOfMemory;
        };

        return ZipParser{
            .allocator = allocator,
            .data = data,
            .entries = owned_entries,
            .entry_map = entry_map,
            .is_zip64 = is_zip64_archive,
        };
    }

    pub fn deinit(self: *ZipParser) void {
        self.entry_map.deinit(self.allocator);
        self.allocator.free(self.entries);
    }

    pub fn findFile(self: *const ZipParser, path: []const u8) ?*const ZipEntry {
        if (self.entry_map.get(path)) |idx| {
            return &self.entries[idx];
        }
        return null;
    }

    pub fn findFileGlob(self: *const ZipParser, pattern: []const u8) ?*const ZipEntry {
        for (self.entries) |*entry| {
            if (matchGlob(pattern, entry.name)) {
                return entry;
            }
        }
        return null;
    }

    pub fn listFiles(self: *const ZipParser) []const ZipEntry {
        return self.entries;
    }

    pub fn count(self: *const ZipParser) usize {
        return self.entries.len;
    }

    pub fn validatePaths(self: *const ZipParser) ZipError!void {
        for (self.entries) |entry| {
            if (containsPathTraversal(entry.name)) {
                return ZipError.PathTraversal;
            }
        }
    }

    pub fn getFileData(self: *const ZipParser, entry: *const ZipEntry) ZipError![]const u8 {
        if (entry.offset + 30 > self.data.len) return ZipError.TruncatedArchive;

        const local_header_offset = entry.offset;
        const name_len = std.mem.readInt(u16, self.data[local_header_offset + 26 ..][0..2], .little);
        const extra_len = std.mem.readInt(u16, self.data[local_header_offset + 28 ..][0..2], .little);

        const data_offset = local_header_offset + 30 + name_len + extra_len;
        const data_end = data_offset + entry.compressed_size;

        if (data_end > self.data.len) return ZipError.TruncatedArchive;

        return self.data[data_offset..data_end];
    }

    pub fn getDecompressedData(self: *const ZipParser, allocator: std.mem.Allocator, entry: *const ZipEntry) ZipError![]u8 {
        const compressed_data = try self.getFileData(entry);

        if (entry.compression_method == 0) {
            // Stored (no compression)
            return allocator.dupe(u8, compressed_data) catch return ZipError.OutOfMemory;
        }

        if (entry.compression_method == 8) {
            // DEFLATE
            return decompressDeflate(allocator, compressed_data, entry.uncompressed_size);
        }

        return ZipError.UnsupportedCompression;
    }

    pub fn totalUncompressedSize(self: *const ZipParser) u64 {
        var total: u64 = 0;
        for (self.entries) |entry| {
            total += entry.uncompressed_size;
        }
        return total;
    }

    /// Check if this archive uses ZIP64 extensions
    pub fn isZip64(self: *const ZipParser) bool {
        return self.is_zip64;
    }

    /// Get entry by index (for streaming)
    pub fn getEntryByIndex(self: *const ZipParser, index: usize) ?*const ZipEntry {
        if (index >= self.entries.len) return null;
        return &self.entries[index];
    }

    /// Stream file data without full decompression into memory
    /// Calls the callback with chunks of decompressed data
    pub fn streamFileData(
        self: *const ZipParser,
        entry: *const ZipEntry,
        callback: StreamCallback,
    ) ZipError!void {
        const compressed_data = try self.getFileData(entry);

        if (entry.compression_method == 0) {
            // Stored (no compression) - stream in chunks
            const chunk_size: usize = 65536; // 64KB chunks
            var offset: usize = 0;
            while (offset < compressed_data.len) {
                const end = @min(offset + chunk_size, compressed_data.len);
                callback(compressed_data[offset..end]) catch return ZipError.InvalidArchive;
                offset = end;
            }
            return;
        }

        if (entry.compression_method == 8) {
            // DEFLATE - stream decompressed data
            try streamDecompressDeflate(compressed_data, entry.uncompressed_size, callback);
            return;
        }

        return ZipError.UnsupportedCompression;
    }
};

fn decompressDeflate(allocator: std.mem.Allocator, compressed_data: []const u8, expected_size: u64) ZipParser.ZipError![]u8 {
    const flate = std.compress.flate;
    const Io = std.Io;

    // Create a fixed reader from the compressed data
    var input_reader = Io.Reader.fixed(compressed_data);

    // Pre-allocate output buffer
    const output = allocator.alloc(u8, if (expected_size > 0) @intCast(expected_size) else 65536) catch {
        return ZipParser.ZipError.OutOfMemory;
    };
    errdefer allocator.free(output);

    // Use window buffer for decompression
    var window_buffer: [flate.max_window_len]u8 = undefined;

    // Initialize decompressor with new API
    var decompress: flate.Decompress = .init(&input_reader, .raw, &window_buffer);

    // Create a writer to collect the output
    var output_writer = Io.Writer.fixed(output);

    // Stream decompressed data to the output buffer
    if (expected_size > 0) {
        decompress.reader.streamExact64(&output_writer, expected_size) catch {
            return ZipParser.ZipError.InvalidArchive;
        };
        return output;
    } else {
        // Unknown size - read until end
        const bytes_written = decompress.reader.streamRemaining(&output_writer) catch {
            return ZipParser.ZipError.InvalidArchive;
        };

        // Resize to actual size
        if (bytes_written < output.len) {
            const resized = allocator.realloc(output, bytes_written) catch output;
            return resized;
        }
        return output;
    }
}

/// Stream decompressed DEFLATE data through a callback
fn streamDecompressDeflate(compressed_data: []const u8, expected_size: u64, callback: ZipParser.StreamCallback) ZipParser.ZipError!void {
    const flate = std.compress.flate;
    const Io = std.Io;

    // Create a fixed reader from the compressed data
    var input_reader = Io.Reader.fixed(compressed_data);

    // Use window buffer for decompression
    var window_buffer: [flate.max_window_len]u8 = undefined;

    // Initialize decompressor
    var decompress: flate.Decompress = .init(&input_reader, .raw, &window_buffer);

    // Stream in chunks
    const chunk_size: usize = 65536; // 64KB chunks
    var chunk_buffer: [65536]u8 = undefined;
    var total_read: u64 = 0;

    while (total_read < expected_size or expected_size == 0) {
        const to_read = if (expected_size > 0)
            @min(chunk_size, @as(usize, @intCast(expected_size - total_read)))
        else
            chunk_size;

        if (to_read == 0) break;

        var chunk_writer = Io.Writer.fixed(chunk_buffer[0..to_read]);
        const bytes_read = decompress.reader.streamRemaining(&chunk_writer) catch {
            return ZipParser.ZipError.InvalidArchive;
        };

        if (bytes_read == 0) break;

        callback(chunk_buffer[0..bytes_read]) catch return ZipParser.ZipError.InvalidArchive;
        total_read += bytes_read;

        if (bytes_read < to_read) break; // End of stream
    }
}

pub fn isZipArchive(data: []const u8) bool {
    if (data.len < 4) return false;
    return std.mem.readInt(u32, data[0..4], .little) == ZipParser.LOCAL_FILE_HEADER_SIG;
}

pub fn containsPathTraversal(path: []const u8) bool {
    if (path.len > 0 and (path[0] == '/' or path[0] == '\\')) return true;
    if (path.len >= 3 and path[1] == ':' and (path[2] == '/' or path[2] == '\\')) return true;

    // Optimized traversal check
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (i + 2 < path.len and path[i] == '.' and path[i + 1] == '.') {
            const c = path[i + 2];
            if (c == '/' or c == '\\') return true;
        }
    }
    // Check for standalone ".."
    if (path.len == 2 and path[0] == '.' and path[1] == '.') return true;

    return false;
}

fn matchGlob(pattern: []const u8, text: []const u8) bool {
    var p_idx: usize = 0;
    var t_idx: usize = 0;
    var star_idx: ?usize = null;
    var match_idx: usize = 0;

    while (t_idx < text.len) {
        if (p_idx < pattern.len and (pattern[p_idx] == text[t_idx] or pattern[p_idx] == '?')) {
            p_idx += 1;
            t_idx += 1;
        } else if (p_idx < pattern.len and pattern[p_idx] == '*') {
            star_idx = p_idx;
            match_idx = t_idx;
            p_idx += 1;
        } else if (star_idx != null) {
            p_idx = star_idx.? + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.len and pattern[p_idx] == '*') {
        p_idx += 1;
    }

    return p_idx == pattern.len;
}

/// Search backwards for End of Central Directory signature
/// EOCD can appear at any byte offset, so we must check every position
fn findEndOfCentralDirectory(data: []const u8) ?usize {
    if (data.len < 22) return null;

    // Zip comment max length is 65535, so EOCD is within last 65535 + 22 bytes
    const max_comment_len: usize = 65535;
    const eocd_min_size: usize = 22;
    const search_start = if (data.len > max_comment_len + eocd_min_size)
        data.len - max_comment_len - eocd_min_size
    else
        0;

    // Search backwards from the minimum possible EOCD position
    var i: usize = data.len - eocd_min_size;
    while (i >= search_start) : (i -= 1) {
        if (i + 4 > data.len) {
            if (i == 0) break;
            continue;
        }
        const sig = std.mem.readInt(u32, data[i..][0..4], .little);
        if (sig == ZipParser.END_OF_CENTRAL_DIR_SIG) {
            // Verify comment length matches file size
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

const EndOfCentralDirectory = struct {
    disk_number: u16,
    central_dir_disk: u16,
    entries_on_disk: u16,
    total_entries: u16,
    central_dir_size: u32,
    central_dir_offset: u32,
    comment_len: u16,
};

/// ZIP64 End of Central Directory Locator
const Zip64EndOfCentralDirLocator = struct {
    disk_with_zip64_eocd: u32,
    zip64_eocd_offset: u64,
    total_disks: u32,
};

/// ZIP64 End of Central Directory
const Zip64EndOfCentralDirectory = struct {
    size_of_zip64_eocd: u64,
    version_made_by: u16,
    version_needed: u16,
    disk_number: u32,
    central_dir_disk: u32,
    entries_on_disk: u64,
    total_entries: u64,
    central_dir_size: u64,
    central_dir_offset: u64,
};

const CentralDirEntry = struct {
    name: []const u8,
    compressed_size: u64,
    uncompressed_size: u64,
    offset: u64,
    compression_method: u16,
    crc32: u32,
    is_directory: bool,
    extra_len: u16,
    comment_len: u16,
};

fn parseEndOfCentralDirectory(data: []const u8, offset: usize) ?EndOfCentralDirectory {
    if (offset + 22 > data.len) return null;
    const slice = data[offset..];
    return EndOfCentralDirectory{
        .disk_number = std.mem.readInt(u16, slice[4..6], .little),
        .central_dir_disk = std.mem.readInt(u16, slice[6..8], .little),
        .entries_on_disk = std.mem.readInt(u16, slice[8..10], .little),
        .total_entries = std.mem.readInt(u16, slice[10..12], .little),
        .central_dir_size = std.mem.readInt(u32, slice[12..16], .little),
        .central_dir_offset = std.mem.readInt(u32, slice[16..20], .little),
        .comment_len = std.mem.readInt(u16, slice[20..22], .little),
    };
}

/// Find ZIP64 End of Central Directory Locator
/// It should be located just before the regular EOCD
fn findZip64EndOfCentralDirLocator(data: []const u8, eocd_offset: usize) ?Zip64EndOfCentralDirLocator {
    // ZIP64 EOCD Locator is 20 bytes and appears before the regular EOCD
    if (eocd_offset < 20) return null;

    const locator_offset = eocd_offset - 20;
    if (locator_offset + 20 > data.len) return null;

    const slice = data[locator_offset..];
    const sig = std.mem.readInt(u32, slice[0..4], .little);
    if (sig != ZipParser.ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG) return null;

    return Zip64EndOfCentralDirLocator{
        .disk_with_zip64_eocd = std.mem.readInt(u32, slice[4..8], .little),
        .zip64_eocd_offset = std.mem.readInt(u64, slice[8..16], .little),
        .total_disks = std.mem.readInt(u32, slice[16..20], .little),
    };
}

/// Parse ZIP64 End of Central Directory
fn parseZip64EndOfCentralDirectory(data: []const u8, offset: u64) ?Zip64EndOfCentralDirectory {
    if (offset >= data.len) return null;
    const offset_usize: usize = @intCast(offset);
    if (offset_usize + 56 > data.len) return null;

    const slice = data[offset_usize..];
    const sig = std.mem.readInt(u32, slice[0..4], .little);
    if (sig != ZipParser.ZIP64_END_OF_CENTRAL_DIR_SIG) return null;

    return Zip64EndOfCentralDirectory{
        .size_of_zip64_eocd = std.mem.readInt(u64, slice[4..12], .little),
        .version_made_by = std.mem.readInt(u16, slice[12..14], .little),
        .version_needed = std.mem.readInt(u16, slice[14..16], .little),
        .disk_number = std.mem.readInt(u32, slice[16..20], .little),
        .central_dir_disk = std.mem.readInt(u32, slice[20..24], .little),
        .entries_on_disk = std.mem.readInt(u64, slice[24..32], .little),
        .total_entries = std.mem.readInt(u64, slice[32..40], .little),
        .central_dir_size = std.mem.readInt(u64, slice[40..48], .little),
        .central_dir_offset = std.mem.readInt(u64, slice[48..56], .little),
    };
}

/// ZIP64 extra field result
const Zip64ExtraFieldResult = struct {
    compressed_size: u64,
    uncompressed_size: u64,
    offset: u64,
};

/// Parse ZIP64 Extended Information Extra Field
/// Returns updated sizes and offset if ZIP64 extra field is present
fn parseZip64ExtraField(extra_data: []const u8, compressed_size: u32, uncompressed_size: u32, local_header_offset: u32) Zip64ExtraFieldResult {
    var result = Zip64ExtraFieldResult{
        .compressed_size = @as(u64, compressed_size),
        .uncompressed_size = @as(u64, uncompressed_size),
        .offset = @as(u64, local_header_offset),
    };

    var pos: usize = 0;
    while (pos + 4 <= extra_data.len) {
        const tag = std.mem.readInt(u16, extra_data[pos..][0..2], .little);
        const size = std.mem.readInt(u16, extra_data[pos + 2 ..][0..2], .little);
        pos += 4;

        if (tag == ZipParser.ZIP64_EXTRA_FIELD_TAG) {
            // ZIP64 Extended Information Extra Field
            var field_pos: usize = 0;

            // Uncompressed size (if original was 0xFFFFFFFF)
            if (uncompressed_size == 0xFFFFFFFF and field_pos + 8 <= size) {
                result.uncompressed_size = std.mem.readInt(u64, extra_data[pos + field_pos ..][0..8], .little);
                field_pos += 8;
            }

            // Compressed size (if original was 0xFFFFFFFF)
            if (compressed_size == 0xFFFFFFFF and field_pos + 8 <= size) {
                result.compressed_size = std.mem.readInt(u64, extra_data[pos + field_pos ..][0..8], .little);
                field_pos += 8;
            }

            // Local header offset (if original was 0xFFFFFFFF)
            if (local_header_offset == 0xFFFFFFFF and field_pos + 8 <= size) {
                result.offset = std.mem.readInt(u64, extra_data[pos + field_pos ..][0..8], .little);
                field_pos += 8;
            }

            break;
        }

        pos += size;
    }

    return result;
}

fn parseCentralDirectoryEntry(data: []const u8, offset: u64, is_zip64: bool) ?CentralDirEntry {
    const offset_usize: usize = @intCast(offset);
    if (offset_usize + 46 > data.len) return null;
    const slice = data[offset_usize..];

    const sig = std.mem.readInt(u32, slice[0..4], .little);
    if (sig != ZipParser.CENTRAL_DIR_HEADER_SIG) return null;

    const compression_method = std.mem.readInt(u16, slice[10..12], .little);
    const crc32 = std.mem.readInt(u32, slice[16..20], .little);
    const compressed_size_32 = std.mem.readInt(u32, slice[20..24], .little);
    const uncompressed_size_32 = std.mem.readInt(u32, slice[24..28], .little);
    const name_len = std.mem.readInt(u16, slice[28..30], .little);
    const extra_len = std.mem.readInt(u16, slice[30..32], .little);
    const comment_len = std.mem.readInt(u16, slice[32..34], .little);
    const local_header_offset_32 = std.mem.readInt(u32, slice[42..46], .little);

    if (offset_usize + 46 + name_len > data.len) return null;

    const name = slice[46 .. 46 + name_len];
    const is_directory = name.len > 0 and (name[name.len - 1] == '/' or name[name.len - 1] == '\\');

    // Parse ZIP64 extra field if needed
    var compressed_size: u64 = compressed_size_32;
    var uncompressed_size: u64 = uncompressed_size_32;
    var local_header_offset: u64 = local_header_offset_32;

    if (is_zip64 and extra_len > 0) {
        const extra_start = 46 + name_len;
        if (offset_usize + extra_start + extra_len <= data.len) {
            const extra_data = slice[extra_start .. extra_start + extra_len];
            const zip64_info = parseZip64ExtraField(extra_data, compressed_size_32, uncompressed_size_32, local_header_offset_32);
            compressed_size = zip64_info.compressed_size;
            uncompressed_size = zip64_info.uncompressed_size;
            local_header_offset = zip64_info.offset;
        }
    }

    return CentralDirEntry{
        .name = name,
        .compressed_size = compressed_size,
        .uncompressed_size = uncompressed_size,
        .offset = local_header_offset,
        .compression_method = compression_method,
        .crc32 = crc32,
        .is_directory = is_directory,
        .extra_len = extra_len,
        .comment_len = comment_len,
    };
}
