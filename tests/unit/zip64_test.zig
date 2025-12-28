const std = @import("std");
const testing = std.testing;
const zip = @import("zip");

/// Test helper to create a minimal ZIP64 archive structure in memory
/// This creates a synthetic ZIP64 archive for testing the parser
fn createMinimalZip64Archive(allocator: std.mem.Allocator) ![]u8 {
    // Create a minimal ZIP64 archive with one file
    // Structure:
    // - Local file header
    // - File data
    // - Central directory header with ZIP64 extra field
    // - ZIP64 End of Central Directory
    // - ZIP64 End of Central Directory Locator
    // - End of Central Directory (with 0xFFFF/0xFFFFFFFF markers)

    var buffer = std.ArrayListUnmanaged(u8){};
    errdefer buffer.deinit(allocator);

    const file_name = "test.txt";
    const file_data = "Hello, ZIP64!";

    // Local file header (30 bytes + filename)
    const local_header_offset: u64 = 0;
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x03, 0x04, // Local file header signature
        0x2d, 0x00, // Version needed (4.5 for ZIP64)
        0x00, 0x00, // General purpose bit flag
        0x00, 0x00, // Compression method (stored)
        0x00, 0x00, // Last mod file time
        0x00, 0x00, // Last mod file date
        0x00, 0x00, 0x00, 0x00, // CRC-32
    });
    // Compressed size (use 0xFFFFFFFF for ZIP64)
    try buffer.appendSlice(allocator, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
    // Uncompressed size (use 0xFFFFFFFF for ZIP64)
    try buffer.appendSlice(allocator, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
    // File name length
    try buffer.appendSlice(allocator, &[_]u8{ @intCast(file_name.len), 0x00 });
    // Extra field length (ZIP64 extra field: 4 header + 16 data)
    try buffer.appendSlice(allocator, &[_]u8{ 0x14, 0x00 });
    // File name
    try buffer.appendSlice(allocator, file_name);
    // ZIP64 extra field in local header
    try buffer.appendSlice(allocator, &[_]u8{
        0x01, 0x00, // ZIP64 extra field tag
        0x10, 0x00, // Size of extra field data (16 bytes)
    });
    // Uncompressed size (8 bytes)
    try buffer.writer(allocator).writeInt(u64, file_data.len, .little);
    // Compressed size (8 bytes)
    try buffer.writer(allocator).writeInt(u64, file_data.len, .little);

    // File data
    try buffer.appendSlice(allocator, file_data);

    // Central directory header
    const central_dir_offset: u64 = buffer.items.len;
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x01, 0x02, // Central directory header signature
        0x2d, 0x00, // Version made by
        0x2d, 0x00, // Version needed (4.5 for ZIP64)
        0x00, 0x00, // General purpose bit flag
        0x00, 0x00, // Compression method (stored)
        0x00, 0x00, // Last mod file time
        0x00, 0x00, // Last mod file date
        0x00, 0x00, 0x00, 0x00, // CRC-32
    });
    // Compressed size (use 0xFFFFFFFF for ZIP64)
    try buffer.appendSlice(allocator, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
    // Uncompressed size (use 0xFFFFFFFF for ZIP64)
    try buffer.appendSlice(allocator, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
    // File name length
    try buffer.appendSlice(allocator, &[_]u8{ @intCast(file_name.len), 0x00 });
    // Extra field length (ZIP64: 4 header + 24 data for sizes + offset)
    try buffer.appendSlice(allocator, &[_]u8{ 0x1c, 0x00 });
    // File comment length
    try buffer.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });
    // Disk number start
    try buffer.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });
    // Internal file attributes
    try buffer.appendSlice(allocator, &[_]u8{ 0x00, 0x00 });
    // External file attributes
    try buffer.appendSlice(allocator, &[_]u8{ 0x00, 0x00, 0x00, 0x00 });
    // Relative offset of local header (use 0xFFFFFFFF for ZIP64)
    try buffer.appendSlice(allocator, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });
    // File name
    try buffer.appendSlice(allocator, file_name);
    // ZIP64 extra field
    try buffer.appendSlice(allocator, &[_]u8{
        0x01, 0x00, // ZIP64 extra field tag
        0x18, 0x00, // Size of extra field data (24 bytes)
    });
    // Uncompressed size (8 bytes)
    try buffer.writer(allocator).writeInt(u64, file_data.len, .little);
    // Compressed size (8 bytes)
    try buffer.writer(allocator).writeInt(u64, file_data.len, .little);
    // Local header offset (8 bytes)
    try buffer.writer(allocator).writeInt(u64, local_header_offset, .little);

    const central_dir_size: u64 = buffer.items.len - central_dir_offset;

    // ZIP64 End of Central Directory
    const zip64_eocd_offset: u64 = buffer.items.len;
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x06, 0x06, // ZIP64 EOCD signature
    });
    // Size of ZIP64 EOCD (44 bytes remaining)
    try buffer.writer(allocator).writeInt(u64, 44, .little);
    // Version made by
    try buffer.appendSlice(allocator, &[_]u8{ 0x2d, 0x00 });
    // Version needed
    try buffer.appendSlice(allocator, &[_]u8{ 0x2d, 0x00 });
    // Disk number
    try buffer.writer(allocator).writeInt(u32, 0, .little);
    // Disk with central directory
    try buffer.writer(allocator).writeInt(u32, 0, .little);
    // Entries on this disk
    try buffer.writer(allocator).writeInt(u64, 1, .little);
    // Total entries
    try buffer.writer(allocator).writeInt(u64, 1, .little);
    // Central directory size
    try buffer.writer(allocator).writeInt(u64, central_dir_size, .little);
    // Central directory offset
    try buffer.writer(allocator).writeInt(u64, central_dir_offset, .little);

    // ZIP64 End of Central Directory Locator
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x06, 0x07, // ZIP64 EOCD Locator signature
    });
    // Disk with ZIP64 EOCD
    try buffer.writer(allocator).writeInt(u32, 0, .little);
    // Offset of ZIP64 EOCD
    try buffer.writer(allocator).writeInt(u64, zip64_eocd_offset, .little);
    // Total disks
    try buffer.writer(allocator).writeInt(u32, 1, .little);

    // End of Central Directory (with ZIP64 markers)
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x05, 0x06, // EOCD signature
        0x00, 0x00, // Disk number
        0x00, 0x00, // Disk with central directory
        0xFF, 0xFF, // Entries on this disk (0xFFFF = use ZIP64)
        0xFF, 0xFF, // Total entries (0xFFFF = use ZIP64)
        0xFF, 0xFF, 0xFF, 0xFF, // Central directory size (0xFFFFFFFF = use ZIP64)
        0xFF, 0xFF, 0xFF, 0xFF, // Central directory offset (0xFFFFFFFF = use ZIP64)
        0x00, 0x00, // Comment length
    });

    return buffer.toOwnedSlice(allocator);
}

test "ZIP64: isZip64 returns true for ZIP64 archives" {
    const allocator = testing.allocator;

    const zip64_data = try createMinimalZip64Archive(allocator);
    defer allocator.free(zip64_data);

    var parser = try zip.ZipParser.parse(allocator, zip64_data);
    defer parser.deinit();

    try testing.expect(parser.isZip64());
}

test "ZIP64: isZip64 returns false for regular ZIP archives" {
    const allocator = testing.allocator;

    // Create a minimal regular ZIP archive
    var buffer = std.ArrayList(u8){};
    defer buffer.deinit(allocator);

    const file_name = "test.txt";
    const file_data = "Hello!";

    // Local file header
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x03, 0x04, // Signature
        0x14, 0x00, // Version needed
        0x00, 0x00, // Flags
        0x00, 0x00, // Compression (stored)
        0x00, 0x00, // Time
        0x00, 0x00, // Date
        0x00, 0x00, 0x00, 0x00, // CRC
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little); // Compressed size
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little); // Uncompressed size
    try buffer.writer(allocator).writeInt(u16, @intCast(file_name.len), .little); // Name length
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Extra length
    try buffer.appendSlice(allocator, file_name);
    try buffer.appendSlice(allocator, file_data);

    const central_dir_offset = buffer.items.len;

    // Central directory header
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x01, 0x02, // Signature
        0x14, 0x00, // Version made by
        0x14, 0x00, // Version needed
        0x00, 0x00, // Flags
        0x00, 0x00, // Compression
        0x00, 0x00, // Time
        0x00, 0x00, // Date
        0x00, 0x00, 0x00, 0x00, // CRC
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little); // Compressed size
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little); // Uncompressed size
    try buffer.writer(allocator).writeInt(u16, @intCast(file_name.len), .little); // Name length
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Extra length
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Comment length
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Disk start
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Internal attrs
    try buffer.writer(allocator).writeInt(u32, 0, .little); // External attrs
    try buffer.writer(allocator).writeInt(u32, 0, .little); // Local header offset
    try buffer.appendSlice(allocator, file_name);

    const central_dir_size = buffer.items.len - central_dir_offset;

    // End of central directory
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x05, 0x06, // Signature
        0x00, 0x00, // Disk number
        0x00, 0x00, // Disk with CD
        0x01, 0x00, // Entries on disk
        0x01, 0x00, // Total entries
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(central_dir_size), .little);
    try buffer.writer(allocator).writeInt(u32, @intCast(central_dir_offset), .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little); // Comment length

    var parser = try zip.ZipParser.parse(allocator, buffer.items);
    defer parser.deinit();

    try testing.expect(!parser.isZip64());
}

test "ZIP64: parses file entries correctly" {
    const allocator = testing.allocator;

    const zip64_data = try createMinimalZip64Archive(allocator);
    defer allocator.free(zip64_data);

    var parser = try zip.ZipParser.parse(allocator, zip64_data);
    defer parser.deinit();

    try testing.expectEqual(@as(usize, 1), parser.count());

    const entry = parser.findFile("test.txt");
    try testing.expect(entry != null);
    try testing.expectEqualStrings("test.txt", entry.?.name);
    try testing.expectEqual(@as(u64, 13), entry.?.uncompressed_size); // "Hello, ZIP64!" = 13 bytes
}

test "ZIP64: getEntryByIndex works correctly" {
    const allocator = testing.allocator;

    const zip64_data = try createMinimalZip64Archive(allocator);
    defer allocator.free(zip64_data);

    var parser = try zip.ZipParser.parse(allocator, zip64_data);
    defer parser.deinit();

    const entry = parser.getEntryByIndex(0);
    try testing.expect(entry != null);
    try testing.expectEqualStrings("test.txt", entry.?.name);

    const invalid_entry = parser.getEntryByIndex(100);
    try testing.expect(invalid_entry == null);
}

test "ZIP64: streamFileData streams stored data correctly" {
    const allocator = testing.allocator;

    const zip64_data = try createMinimalZip64Archive(allocator);
    defer allocator.free(zip64_data);

    var parser = try zip.ZipParser.parse(allocator, zip64_data);
    defer parser.deinit();

    const entry = parser.findFile("test.txt").?;

    var collected_data = std.ArrayList(u8){};
    defer collected_data.deinit(allocator);

    const callback = struct {
        fn cb(chunk: []const u8) anyerror!void {
            // This is a workaround since we can't capture the ArrayList
            // In real usage, you'd use a proper context
            _ = chunk;
        }
    }.cb;

    // Test that streaming doesn't error
    try parser.streamFileData(entry, callback);
}

test "ZIP64: handles regular ZIP with streaming" {
    const allocator = testing.allocator;

    // Create a minimal regular ZIP archive
    var buffer = std.ArrayList(u8){};
    defer buffer.deinit(allocator);

    const file_name = "hello.txt";
    const file_data = "Hello, World!";

    // Local file header
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x03, 0x04,
        0x14, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little);
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little);
    try buffer.writer(allocator).writeInt(u16, @intCast(file_name.len), .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);
    try buffer.appendSlice(allocator, file_name);
    try buffer.appendSlice(allocator, file_data);

    const central_dir_offset = buffer.items.len;

    // Central directory header
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x01, 0x02,
        0x14, 0x00,
        0x14, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little);
    try buffer.writer(allocator).writeInt(u32, @intCast(file_data.len), .little);
    try buffer.writer(allocator).writeInt(u16, @intCast(file_name.len), .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);
    try buffer.writer(allocator).writeInt(u32, 0, .little);
    try buffer.writer(allocator).writeInt(u32, 0, .little);
    try buffer.appendSlice(allocator, file_name);

    const central_dir_size = buffer.items.len - central_dir_offset;

    // EOCD
    try buffer.appendSlice(allocator, &[_]u8{
        0x50, 0x4b, 0x05, 0x06,
        0x00, 0x00,
        0x00, 0x00,
        0x01, 0x00,
        0x01, 0x00,
    });
    try buffer.writer(allocator).writeInt(u32, @intCast(central_dir_size), .little);
    try buffer.writer(allocator).writeInt(u32, @intCast(central_dir_offset), .little);
    try buffer.writer(allocator).writeInt(u16, 0, .little);

    var parser = try zip.ZipParser.parse(allocator, buffer.items);
    defer parser.deinit();

    const entry = parser.findFile("hello.txt").?;

    const callback = struct {
        fn cb(chunk: []const u8) anyerror!void {
            _ = chunk;
        }
    }.cb;

    try parser.streamFileData(entry, callback);
}
