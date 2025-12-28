const std = @import("std");

/// Android Resource Table (resources.arsc) Parser
/// Parses the binary resource table format to resolve string resources
pub const ArscParser = struct {
    /// String pool containing all string values
    string_pool: []const []const u8,
    /// Resource entries mapping resource ID to string pool index
    resource_entries: std.AutoHashMapUnmanaged(u32, u32),
    /// Allocator used for dynamic allocations
    allocator: std.mem.Allocator,
    /// Arena for batch deallocations
    arena: ?std.heap.ArenaAllocator,
    /// Package ID (usually 0x7f for app resources)
    package_id: u8,

    pub const ArscError = error{
        InvalidFormat,
        TruncatedData,
        OutOfMemory,
        InvalidStringPool,
    };

    // Chunk types
    const CHUNK_TABLE: u16 = 0x0002;
    const CHUNK_STRING_POOL: u16 = 0x0001;
    const CHUNK_TABLE_PACKAGE: u16 = 0x0200;
    const CHUNK_TABLE_TYPE: u16 = 0x0201;
    const CHUNK_TABLE_TYPE_SPEC: u16 = 0x0202;

    /// Parse resources.arsc data
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) ArscError!ArscParser {
        if (data.len < 12) {
            return ArscError.InvalidFormat;
        }

        // Check table header: type (2) + header_size (2) + size (4) + package_count (4)
        const chunk_type = std.mem.readInt(u16, data[0..2], .little);
        if (chunk_type != CHUNK_TABLE) {
            return ArscError.InvalidFormat;
        }

        const header_size = std.mem.readInt(u16, data[2..4], .little);
        const file_size = std.mem.readInt(u32, data[4..8], .little);
        const package_count = std.mem.readInt(u32, data[8..12], .little);
        _ = package_count;

        if (file_size > data.len) {
            return ArscError.TruncatedData;
        }

        // Use arena allocator for efficient memory management
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        var global_string_pool = std.ArrayListUnmanaged([]const u8){};
        var resource_entries = std.AutoHashMapUnmanaged(u32, u32){};
        var package_id: u8 = 0x7f; // Default

        var offset: usize = header_size;

        // Parse chunks
        while (offset + 8 <= data.len) {
            const c_type = std.mem.readInt(u16, data[offset..][0..2], .little);
            const c_size = std.mem.readInt(u32, data[offset + 4 ..][0..4], .little);

            if (c_size < 8 or offset + c_size > data.len) break;

            const chunk_data = data[offset .. offset + c_size];

            switch (c_type) {
                CHUNK_STRING_POOL => {
                    // Parse the global string pool (first one only)
                    if (global_string_pool.items.len == 0) {
                        try parseStringPool(arena_alloc, chunk_data, &global_string_pool);
                    }
                },
                CHUNK_TABLE_PACKAGE => {
                    // Parse package to get package ID and type chunks
                    try parsePackage(arena_alloc, chunk_data, &resource_entries, &package_id);
                },
                else => {},
            }

            offset += c_size;
        }

        return ArscParser{
            .string_pool = try global_string_pool.toOwnedSlice(arena_alloc),
            .resource_entries = resource_entries,
            .allocator = allocator,
            .arena = arena,
            .package_id = package_id,
        };
    }

    /// Deinitialize the parser
    pub fn deinit(self: *ArscParser) void {
        if (self.arena) |*arena| {
            arena.deinit();
        }
        self.string_pool = &.{};
        self.resource_entries = .{};
        self.arena = null;
    }

    /// Resolve a resource ID to its string value
    pub fn resolveString(self: *const ArscParser, resource_id: u32) ?[]const u8 {
        const string_idx = self.resource_entries.get(resource_id) orelse return null;

        if (string_idx < self.string_pool.len) {
            return self.string_pool[string_idx];
        }
        return null;
    }

    /// Get a string directly from the string pool by index
    pub fn getString(self: *const ArscParser, index: u32) ?[]const u8 {
        if (index < self.string_pool.len) {
            return self.string_pool[index];
        }
        return null;
    }
};

/// Parse package chunk
fn parsePackage(
    allocator: std.mem.Allocator,
    data: []const u8,
    entries: *std.AutoHashMapUnmanaged(u32, u32),
    package_id: *u8,
) ArscParser.ArscError!void {
    // ResTable_package structure:
    // ResChunk_header (8 bytes):
    //   - type (2 bytes): RES_TABLE_PACKAGE_TYPE (0x0200)
    //   - headerSize (2 bytes): size of this header
    //   - size (4 bytes): total size of chunk
    // id (4 bytes): Package ID (usually 0x7f for app resources)
    // name (256 bytes): Package name as UTF-16, null-terminated
    // typeStrings (4 bytes): Offset from header to type string pool
    // lastPublicType (4 bytes): Last index of public type strings
    // keyStrings (4 bytes): Offset from header to key string pool
    // lastPublicKey (4 bytes): Last index of public key strings
    // typeIdOffset (4 bytes): Offset for type IDs (split APKs)
    //
    // Minimum size: 8 + 4 + 256 + 4 + 4 + 4 + 4 + 4 = 288 bytes

    if (data.len < 288) {
        return;
    }

    const header_size = std.mem.readInt(u16, data[2..4], .little);

    // Package ID at offset 8 (immediately after ResChunk_header)
    const pkg_id = std.mem.readInt(u32, data[8..12], .little);
    package_id.* = @intCast(pkg_id & 0xFF);

    // Package name starts at offset 12, spans 256 bytes (128 UTF-16 chars)
    // After package name (offset 12 + 256 = 268):
    //   typeStrings at offset 268
    //   lastPublicType at offset 272
    //   keyStrings at offset 276
    //   lastPublicKey at offset 280
    //   typeIdOffset at offset 284

    // These offsets point to string pools within this package chunk
    // They are relative to the start of this package chunk
    const type_strings_offset = std.mem.readInt(u32, data[268..272], .little);
    const key_strings_offset = std.mem.readInt(u32, data[276..280], .little);

    _ = type_strings_offset;
    _ = key_strings_offset;

    // Child chunks (type specs and types) start after the package header
    // The header_size tells us where the first child chunk begins
    var offset: usize = header_size;

    while (offset + 8 <= data.len) {
        const c_type = std.mem.readInt(u16, data[offset..][0..2], .little);
        const c_size = std.mem.readInt(u32, data[offset + 4 ..][0..4], .little);

        // Validate chunk size
        if (c_size < 8 or offset + c_size > data.len) break;

        const chunk_data = data[offset .. offset + c_size];

        switch (c_type) {
            ArscParser.CHUNK_TABLE_TYPE => {
                // ResTable_type contains actual resource entries
                const c_header_size = std.mem.readInt(u16, data[offset + 2 ..][0..2], .little);
                try parseTypeChunk(allocator, chunk_data, c_header_size, entries, package_id.*);
            },
            ArscParser.CHUNK_TABLE_TYPE_SPEC => {
                // ResTable_typeSpec contains configuration flags for each entry
                // We skip this for now as we only need string values
            },
            ArscParser.CHUNK_STRING_POOL => {
                // Type or key string pool within package
                // These contain type names (drawable, string, etc.) and key names
                // We skip these as we use the global string pool for values
            },
            else => {},
        }

        offset += c_size;
    }
}

/// Parse string pool chunk
/// ResStringPool_header structure:
///   ResChunk_header (8 bytes):
///     - type (2): RES_STRING_POOL_TYPE (0x0001)
///     - headerSize (2): Size of this header (typically 28)
///     - size (4): Total size of chunk including strings
///   stringCount (4): Number of strings in the pool
///   styleCount (4): Number of style span arrays
///   flags (4): Flags (UTF8_FLAG = 0x100, SORTED_FLAG = 0x001)
///   stringsStart (4): Offset from chunk start to string data
///   stylesStart (4): Offset from chunk start to style data
///
/// After the header comes:
///   - String offsets array: stringCount * 4 bytes
///   - Style offsets array: styleCount * 4 bytes (if styleCount > 0)
///   - String data: starts at stringsStart offset
///   - Style data: starts at stylesStart offset (if styleCount > 0)
fn parseStringPool(
    allocator: std.mem.Allocator,
    data: []const u8,
    pool: *std.ArrayListUnmanaged([]const u8),
) ArscParser.ArscError!void {
    // Minimum header size: 8 (ResChunk_header) + 20 (pool-specific) = 28 bytes
    if (data.len < 28) {
        return ArscParser.ArscError.InvalidStringPool;
    }

    const header_size = std.mem.readInt(u16, data[2..4], .little);
    const string_count = std.mem.readInt(u32, data[8..12], .little);
    const style_count = std.mem.readInt(u32, data[12..16], .little);
    const flags = std.mem.readInt(u32, data[16..20], .little);
    const strings_start = std.mem.readInt(u32, data[20..24], .little);
    const styles_start = std.mem.readInt(u32, data[24..28], .little);

    _ = style_count;
    _ = styles_start;

    // UTF8_FLAG (0x100) indicates strings are UTF-8 encoded
    // Otherwise they are UTF-16LE encoded
    const is_utf8 = (flags & 0x100) != 0;

    // Validate strings_start is within bounds
    if (strings_start >= data.len) {
        return ArscParser.ArscError.InvalidStringPool;
    }

    // String offset array starts immediately after the header
    // Each offset is 4 bytes, relative to strings_start
    const offsets_start: usize = header_size;

    // Validate we have space for all string offsets
    if (offsets_start + string_count * 4 > strings_start) {
        // Offsets would overlap with string data - invalid
        return ArscParser.ArscError.InvalidStringPool;
    }

    if (string_count == 0) {
        return;
    }

    try pool.ensureTotalCapacity(allocator, string_count);

    var i: u32 = 0;
    while (i < string_count) : (i += 1) {
        const offset_pos = offsets_start + i * 4;
        if (offset_pos + 4 > data.len) break;

        // Each offset is relative to strings_start (not to the offset array)
        const string_offset = std.mem.readInt(u32, data[offset_pos..][0..4], .little);
        const abs_offset = strings_start + string_offset;

        if (abs_offset >= data.len) {
            pool.appendAssumeCapacity(try allocator.dupe(u8, ""));
            continue;
        }

        const remaining_data = data[abs_offset..];
        const str = if (is_utf8)
            parseUtf8String(remaining_data)
        else
            try parseUtf16String(allocator, remaining_data);

        const final_str = if (is_utf8)
            try allocator.dupe(u8, str)
        else
            str;

        pool.appendAssumeCapacity(final_str);
    }
}

/// Parse UTF-8 string from resource table
fn parseUtf8String(data: []const u8) []const u8 {
    if (data.len < 2) return "";

    var offset: usize = 0;

    // Read character count (variable-length encoding)
    if (data[0] & 0x80 != 0) {
        if (data.len < 2) return "";
        // High bit set: 2-byte encoding
        offset = 2;
    } else {
        // High bit clear: 1-byte encoding
        offset = 1;
    }

    if (offset >= data.len) return "";

    // Read byte length (variable-length encoding)
    var byte_len: usize = undefined;
    if (data[offset] & 0x80 != 0) {
        if (offset + 2 > data.len) return "";
        // High bit set: 2-byte encoding
        byte_len = (@as(usize, data[offset] & 0x7F) << 8) | @as(usize, data[offset + 1]);
        offset += 2;
    } else {
        // High bit clear: 1-byte encoding
        byte_len = data[offset];
        offset += 1;
    }

    if (byte_len == 0) return "";
    if (offset + byte_len > data.len) {
        byte_len = data.len - offset;
    }

    const string_data = data[offset..];
    const max_len = @min(byte_len, string_data.len);

    // Find null terminator
    const null_pos = std.mem.indexOfScalar(u8, string_data[0..max_len], 0);
    const actual_len = null_pos orelse max_len;

    return string_data[0..actual_len];
}

/// Parse UTF-16 string from resource table
fn parseUtf16String(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    if (data.len < 2) return "";

    // Read character count (variable-length encoding for UTF-16)
    var char_count: u32 = undefined;
    var offset: usize = 0;

    const first_byte = data[0];
    if (first_byte & 0x80 != 0) {
        // High bit set: 2-byte length encoding
        if (data.len < 4) return "";
        char_count = (@as(u32, first_byte & 0x7F) << 8) | @as(u32, data[1]);
        offset = 4; // Skip 2 bytes for length + 2 bytes alignment
    } else {
        // High bit clear: 1-byte length encoding
        char_count = first_byte;
        offset = 2; // Skip 1 byte for length + 1 byte padding
    }

    if (char_count == 0 or offset >= data.len) return "";

    // Allocate worst case: 4 bytes per UTF-16 code unit
    var buffer = try allocator.alloc(u8, char_count * 4);
    errdefer allocator.free(buffer);

    var out_idx: usize = 0;
    var chars_read: u32 = 0;

    while (chars_read < char_count and offset + 1 < data.len) {
        const code_unit = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;

        if (code_unit == 0) break;

        // Handle surrogate pairs (U+D800 to U+DFFF)
        if (code_unit >= 0xD800 and code_unit <= 0xDBFF) {
            // High surrogate
            if (offset + 1 < data.len) {
                const low_surrogate = std.mem.readInt(u16, data[offset..][0..2], .little);
                if (low_surrogate >= 0xDC00 and low_surrogate <= 0xDFFF) {
                    offset += 2;
                    chars_read += 1;
                    // Decode surrogate pair to code point
                    const code_point: u21 = 0x10000 + ((@as(u21, code_unit - 0xD800) << 10) | @as(u21, low_surrogate - 0xDC00));
                    // Encode as UTF-8 (4 bytes)
                    buffer[out_idx] = @intCast(0xF0 | (code_point >> 18));
                    buffer[out_idx + 1] = @intCast(0x80 | ((code_point >> 12) & 0x3F));
                    buffer[out_idx + 2] = @intCast(0x80 | ((code_point >> 6) & 0x3F));
                    buffer[out_idx + 3] = @intCast(0x80 | (code_point & 0x3F));
                    out_idx += 4;
                }
            }
        } else if (code_unit < 0x80) {
            // ASCII
            buffer[out_idx] = @intCast(code_unit);
            out_idx += 1;
        } else if (code_unit < 0x800) {
            // 2-byte UTF-8
            buffer[out_idx] = @intCast(0xC0 | (code_unit >> 6));
            buffer[out_idx + 1] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 2;
        } else {
            // 3-byte UTF-8
            buffer[out_idx] = @intCast(0xE0 | (code_unit >> 12));
            buffer[out_idx + 1] = @intCast(0x80 | ((code_unit >> 6) & 0x3F));
            buffer[out_idx + 2] = @intCast(0x80 | (code_unit & 0x3F));
            out_idx += 3;
        }

        chars_read += 1;
    }

    // Shrink to actual size
    if (out_idx < buffer.len) {
        return allocator.realloc(buffer, out_idx) catch buffer[0..out_idx];
    }
    return buffer[0..out_idx];
}

/// Parse type chunk to extract resource entries
/// ResTable_type structure:
///   ResChunk_header (8 bytes):
///     - type (2): RES_TABLE_TYPE_TYPE (0x0201)
///     - headerSize (2): Size of header (varies by Android version, typically 52-76)
///     - size (4): Total size of chunk
///   id (1): Type identifier (1-based, e.g., 1=attr, 2=drawable, 3=string)
///   flags (1): Flags (FLAG_SPARSE = 0x01)
///   reserved (2): Reserved, always 0
///   entryCount (4): Number of entries
///   entriesStart (4): Offset from chunk start to entry data
///   config (variable): ResTable_config structure (device configuration)
///
/// After header:
///   - Entry offsets array: entryCount * 4 bytes (or sparse entries if FLAG_SPARSE)
///   - Entry data: starts at entriesStart offset
///
/// Each entry (ResTable_entry):
///   size (2): Size of entry header
///   flags (2): Entry flags (FLAG_COMPLEX = 0x0001, FLAG_PUBLIC = 0x0002)
///   key (4): Index into key string pool for entry name
///
/// For simple entries (no FLAG_COMPLEX), followed by Res_value:
///   size (2): Size of Res_value (always 8)
///   res0 (1): Reserved, always 0
///   dataType (1): Type of data (TYPE_STRING = 0x03, TYPE_REFERENCE = 0x01, etc.)
///   data (4): The actual data or string pool index
fn parseTypeChunk(
    allocator: std.mem.Allocator,
    data: []const u8,
    header_size: u16,
    entries: *std.AutoHashMapUnmanaged(u32, u32),
    package_id: u8,
) ArscParser.ArscError!void {
    // Minimum header: 8 (ResChunk_header) + 4 (id/flags/reserved) + 4 (entryCount) + 4 (entriesStart) = 20
    // Plus ResTable_config which is at least 28 bytes in older versions
    if (data.len < header_size or header_size < 20) {
        return;
    }

    // Type ID at offset 8 (1-based identifier for this type)
    const type_id = data[8];

    // Flags at offset 9 (FLAG_SPARSE = 0x01 for sparse type chunks)
    const type_flags = data[9];
    const is_sparse = (type_flags & 0x01) != 0;

    // Entry count at offset 12
    const entry_count = std.mem.readInt(u32, data[12..16], .little);

    // Entries start offset at offset 16 (relative to chunk start)
    const entries_start = std.mem.readInt(u32, data[16..20], .little);

    if (entry_count == 0 or entries_start >= data.len) {
        return;
    }

    // Entry offsets array starts immediately after header
    const offsets_start: usize = header_size;

    if (is_sparse) {
        // Sparse type: entries are stored as (index, offset) pairs
        // Each pair is 8 bytes: entry_index (4) + offset (4)
        const pair_count = entry_count;
        var pair_idx: u32 = 0;

        while (pair_idx < pair_count) : (pair_idx += 1) {
            const pair_pos = offsets_start + pair_idx * 8;
            if (pair_pos + 8 > data.len) break;

            const entry_idx = std.mem.readInt(u32, data[pair_pos..][0..4], .little);
            const entry_offset = std.mem.readInt(u32, data[pair_pos + 4 ..][0..4], .little);

            if (entry_offset == 0xFFFFFFFF) continue;

            const abs_offset = entries_start + entry_offset;
            try parseEntry(allocator, data, abs_offset, entries, package_id, type_id, entry_idx);
        }
    } else {
        // Dense type: sequential offsets array, one per entry
        if (offsets_start + entry_count * 4 > data.len) {
            return;
        }

        var entry_idx: u32 = 0;
        while (entry_idx < entry_count) : (entry_idx += 1) {
            const offset_pos = offsets_start + entry_idx * 4;
            if (offset_pos + 4 > data.len) break;

            const entry_offset = std.mem.readInt(u32, data[offset_pos..][0..4], .little);

            // NO_ENTRY (0xFFFFFFFF) means no entry at this index
            if (entry_offset == 0xFFFFFFFF) continue;

            const abs_offset = entries_start + entry_offset;
            try parseEntry(allocator, data, abs_offset, entries, package_id, type_id, entry_idx);
        }
    }
}

/// Parse a single resource entry
fn parseEntry(
    allocator: std.mem.Allocator,
    data: []const u8,
    abs_offset: usize,
    entries: *std.AutoHashMapUnmanaged(u32, u32),
    package_id: u8,
    type_id: u8,
    entry_idx: u32,
) ArscParser.ArscError!void {
    // Need at least entry header (8 bytes) + Res_value (8 bytes) = 16 bytes
    if (abs_offset + 16 > data.len) return;

    // Entry header
    const entry_size = std.mem.readInt(u16, data[abs_offset..][0..2], .little);
    const entry_flags = std.mem.readInt(u16, data[abs_offset + 2 ..][0..2], .little);
    // key at abs_offset + 4 (4 bytes) - index into key string pool

    _ = entry_size;

    // FLAG_COMPLEX (0x0001) indicates a map entry (bag) with multiple values
    // We only handle simple entries with a single Res_value
    if (entry_flags & 0x0001 != 0) return;

    // Res_value starts at abs_offset + 8 (after entry header)
    const value_offset = abs_offset + 8;
    if (value_offset + 8 > data.len) return;

    // Res_value structure:
    // size (2): Always 8
    // res0 (1): Reserved, always 0
    // dataType (1): Type of the data
    // data (4): The actual value

    const value_type = data[value_offset + 3];
    const value_data = std.mem.readInt(u32, data[value_offset + 4 ..][0..4], .little);

    // TYPE_STRING (0x03): data is an index into the global string pool
    if (value_type == 0x03) {
        // Build resource ID: 0xPPTTEEEE
        // PP = package ID (8 bits, usually 0x7f for app resources)
        // TT = type ID (8 bits, 1-based)
        // EEEE = entry ID (16 bits, 0-based)
        const resource_id: u32 = (@as(u32, package_id) << 24) | (@as(u32, type_id) << 16) | entry_idx;
        try entries.put(allocator, resource_id, value_data);
    }
}

// Unit tests
test "ArscParser basic structure" {
    const parser = ArscParser{
        .string_pool = &.{},
        .resource_entries = .{},
        .allocator = std.testing.allocator,
        .arena = null,
        .package_id = 0x7f,
    };
    _ = parser;
}
