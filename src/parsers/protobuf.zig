const std = @import("std");

/// Protobuf Parser for Android App Bundle (AAB) BundleConfig.pb
/// Parses the BundleConfig.pb file to extract split dimension configurations
pub const ProtobufParser = struct {
    /// Split configurations extracted from BundleConfig
    split_configs: []const SplitConfig,
    /// Bundle tool version (if present)
    bundletool_version: ?[]const u8,
    /// Allocator used for dynamic allocations
    allocator: std.mem.Allocator,

    /// Split configuration
    pub const SplitConfig = struct {
        /// Dimension type (ABI, LANGUAGE, SCREEN_DENSITY, etc.)
        dimension: []const u8,
        /// Values for this dimension
        values: []const []const u8,
    };

    /// Errors that can occur during protobuf parsing
    pub const ProtobufError = error{
        /// Invalid protobuf format
        InvalidFormat,
        /// Truncated or corrupted data
        TruncatedData,
        /// Out of memory
        OutOfMemory,
        /// Unsupported wire type
        UnsupportedWireType,
    };

    /// Wire types
    const WIRE_VARINT: u3 = 0;
    const WIRE_FIXED64: u3 = 1;
    const WIRE_LENGTH_DELIMITED: u3 = 2;
    const WIRE_START_GROUP: u3 = 3;
    const WIRE_END_GROUP: u3 = 4;
    const WIRE_FIXED32: u3 = 5;

    /// Known field numbers in BundleConfig.pb
    const FIELD_BUNDLETOOL: u32 = 1;
    const FIELD_OPTIMIZATIONS: u32 = 2;
    const FIELD_COMPRESSION: u32 = 3;
    const FIELD_SPLITS_CONFIG: u32 = 4;

    /// Parse BundleConfig.pb from raw data
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) ProtobufError!ProtobufParser {
        var split_configs = std.ArrayListUnmanaged(SplitConfig){};
        errdefer {
            for (split_configs.items) |*config| {
                allocator.free(config.values);
            }
            split_configs.deinit(allocator);
        }

        var bundletool_version: ?[]const u8 = null;

        var offset: usize = 0;
        while (offset < data.len) {
            const tag_result = readVarint(data[offset..]) catch break;
            offset += tag_result.bytes_read;

            // Bounds check: ensure field number doesn't overflow u32
            const shifted_value = tag_result.value >> 3;
            if (shifted_value > std.math.maxInt(u32)) break;
            const field_number = @as(u32, @intCast(shifted_value));

            const wire_type_value = tag_result.value & 0x7;
            if (wire_type_value > 5) break; // Invalid wire type
            const wire_type: u3 = @intCast(wire_type_value);

            switch (wire_type) {
                WIRE_VARINT => {
                    const varint = readVarint(data[offset..]) catch break;
                    offset += varint.bytes_read;
                },
                WIRE_FIXED64 => {
                    if (offset + 8 > data.len) break;
                    offset += 8;
                },
                WIRE_LENGTH_DELIMITED => {
                    const len_result = readVarint(data[offset..]) catch break;
                    offset += len_result.bytes_read;

                    // Bounds check: ensure length doesn't overflow and is reasonable
                    if (len_result.value > std.math.maxInt(usize)) break;
                    const length = @as(usize, @intCast(len_result.value));

                    // Additional sanity check: length shouldn't exceed remaining data
                    if (length > data.len or offset > data.len - length) break;

                    const field_data = data[offset .. offset + length];

                    if (field_number == FIELD_BUNDLETOOL) {
                        // Parse bundletool message for version
                        bundletool_version = parseBundletoolVersion(allocator, field_data) catch null;
                    } else if (field_number == FIELD_SPLITS_CONFIG) {
                        // Parse splits config
                        const configs = parseSplitsConfig(allocator, field_data) catch &[_]SplitConfig{};
                        for (configs) |config| {
                            split_configs.append(allocator, config) catch {};
                        }
                        if (configs.len > 0) {
                            allocator.free(configs);
                        }
                    }

                    offset += length;
                },
                WIRE_FIXED32 => {
                    if (offset + 4 > data.len) break;
                    offset += 4;
                },
                else => break,
            }
        }

        return ProtobufParser{
            .split_configs = split_configs.toOwnedSlice(allocator) catch return ProtobufError.OutOfMemory,
            .bundletool_version = bundletool_version,
            .allocator = allocator,
        };
    }

    /// Deinitialize the parser and free resources
    pub fn deinit(self: *ProtobufParser) void {
        for (self.split_configs) |*config| {
            self.allocator.free(config.values);
        }
        self.allocator.free(self.split_configs);
        if (self.bundletool_version) |v| {
            self.allocator.free(v);
        }
    }

    /// Get split configurations
    pub fn getSplitConfigs(self: *const ProtobufParser) []const SplitConfig {
        return self.split_configs;
    }

    /// Check if a specific dimension is configured
    pub fn hasDimension(self: *const ProtobufParser, dimension: []const u8) bool {
        for (self.split_configs) |config| {
            if (std.mem.eql(u8, config.dimension, dimension)) {
                return true;
            }
        }
        return false;
    }

    /// Get values for a specific dimension
    pub fn getDimensionValues(self: *const ProtobufParser, dimension: []const u8) ?[]const []const u8 {
        for (self.split_configs) |config| {
            if (std.mem.eql(u8, config.dimension, dimension)) {
                return config.values;
            }
        }
        return null;
    }
};

/// Varint read result
const VarintResult = struct {
    value: u64,
    bytes_read: usize,
};

/// Read a varint from data
fn readVarint(data: []const u8) ProtobufParser.ProtobufError!VarintResult {
    var result: u64 = 0;
    var shift: u6 = 0;
    var bytes_read: usize = 0;

    for (data) |byte| {
        bytes_read += 1;

        // Check shift before performing the operation to avoid overflow
        if (shift >= 64) {
            return ProtobufParser.ProtobufError.InvalidFormat;
        }

        result |= @as(u64, byte & 0x7F) << @intCast(shift);

        if (byte & 0x80 == 0) {
            return .{ .value = result, .bytes_read = bytes_read };
        }

        // Check if incrementing shift would overflow u6 (max value 63)
        // shift + 7 must be <= 63, so shift must be <= 56
        if (shift > 56) {
            return ProtobufParser.ProtobufError.InvalidFormat;
        }
        shift += 7;
    }

    return ProtobufParser.ProtobufError.TruncatedData;
}

/// Parse bundletool version from message
fn parseBundletoolVersion(allocator: std.mem.Allocator, data: []const u8) ProtobufParser.ProtobufError![]const u8 {
    var offset: usize = 0;

    while (offset < data.len) {
        const tag_result = readVarint(data[offset..]) catch break;
        offset += tag_result.bytes_read;

        // Bounds check for field number
        const shifted_value = tag_result.value >> 3;
        if (shifted_value > std.math.maxInt(u32)) break;
        const field_number = @as(u32, @intCast(shifted_value));

        const wire_type_value = tag_result.value & 0x7;
        if (wire_type_value > 5) break;
        const wire_type: u3 = @intCast(wire_type_value);

        if (wire_type == ProtobufParser.WIRE_LENGTH_DELIMITED) {
            const len_result = readVarint(data[offset..]) catch break;
            offset += len_result.bytes_read;

            // Bounds check for length
            if (len_result.value > std.math.maxInt(usize)) break;
            const length = @as(usize, @intCast(len_result.value));

            if (length > data.len or offset > data.len - length) break;

            // Field 1 in Bundletool message is version string
            if (field_number == 1) {
                return allocator.dupe(u8, data[offset .. offset + length]) catch
                    return ProtobufParser.ProtobufError.OutOfMemory;
            }

            offset += length;
        } else if (wire_type == ProtobufParser.WIRE_VARINT) {
            const varint = readVarint(data[offset..]) catch break;
            offset += varint.bytes_read;
        } else {
            break;
        }
    }

    return ProtobufParser.ProtobufError.InvalidFormat;
}

/// Parse splits config from message
fn parseSplitsConfig(allocator: std.mem.Allocator, data: []const u8) ProtobufParser.ProtobufError![]ProtobufParser.SplitConfig {
    var configs = std.ArrayListUnmanaged(ProtobufParser.SplitConfig){};
    errdefer configs.deinit(allocator);

    var offset: usize = 0;

    while (offset < data.len) {
        const tag_result = readVarint(data[offset..]) catch break;
        offset += tag_result.bytes_read;

        const wire_type_value = tag_result.value & 0x7;
        if (wire_type_value > 5) break;
        const wire_type: u3 = @intCast(wire_type_value);

        if (wire_type == ProtobufParser.WIRE_LENGTH_DELIMITED) {
            const len_result = readVarint(data[offset..]) catch break;
            offset += len_result.bytes_read;
            const length = @as(usize, @intCast(len_result.value));

            if (offset + length > data.len) break;

            // Try to parse as split dimension config
            const config = parseSplitDimension(allocator, data[offset .. offset + length]) catch null;
            if (config) |c| {
                configs.append(allocator, c) catch {};
            }

            offset += length;
        } else if (wire_type == ProtobufParser.WIRE_VARINT) {
            const varint = readVarint(data[offset..]) catch break;
            offset += varint.bytes_read;
        } else {
            break;
        }
    }

    return configs.toOwnedSlice(allocator) catch return ProtobufParser.ProtobufError.OutOfMemory;
}

/// Parse a single split dimension
fn parseSplitDimension(allocator: std.mem.Allocator, data: []const u8) ProtobufParser.ProtobufError!ProtobufParser.SplitConfig {
    var dimension: []const u8 = "";
    var values = std.ArrayListUnmanaged([]const u8){};
    errdefer values.deinit(allocator);

    var offset: usize = 0;

    while (offset < data.len) {
        const tag_result = readVarint(data[offset..]) catch break;
        offset += tag_result.bytes_read;

        // Bounds check for field number to prevent overflow
        const shifted_value = tag_result.value >> 3;
        if (shifted_value > std.math.maxInt(u32)) break;
        const field_number = @as(u32, @intCast(shifted_value));

        const wire_type_value = tag_result.value & 0x7;
        if (wire_type_value > 5) break;
        const wire_type: u3 = @intCast(wire_type_value);

        if (wire_type == ProtobufParser.WIRE_VARINT) {
            const varint = readVarint(data[offset..]) catch break;
            offset += varint.bytes_read;

            // Field 1 is typically the dimension type enum
            if (field_number == 1) {
                dimension = switch (varint.value) {
                    0 => "UNSPECIFIED",
                    1 => "ABI",
                    2 => "SCREEN_DENSITY",
                    3 => "LANGUAGE",
                    4 => "TEXTURE_COMPRESSION_FORMAT",
                    5 => "DEVICE_TIER",
                    else => "UNKNOWN",
                };
            }
        } else if (wire_type == ProtobufParser.WIRE_LENGTH_DELIMITED) {
            const len_result = readVarint(data[offset..]) catch break;
            offset += len_result.bytes_read;
            const length = @as(usize, @intCast(len_result.value));

            if (offset + length > data.len) break;

            // Field 2+ are typically values
            if (field_number >= 2) {
                const value = allocator.dupe(u8, data[offset .. offset + length]) catch
                    return ProtobufParser.ProtobufError.OutOfMemory;
                values.append(allocator, value) catch {};
            }

            offset += length;
        } else {
            break;
        }
    }

    return ProtobufParser.SplitConfig{
        .dimension = dimension,
        .values = values.toOwnedSlice(allocator) catch return ProtobufParser.ProtobufError.OutOfMemory,
    };
}

/// Parse BundleConfig.pb (convenience function)
pub fn parseBundleConfig(allocator: std.mem.Allocator, data: []const u8) ProtobufParser.ProtobufError!ProtobufParser {
    return ProtobufParser.parse(allocator, data);
}

// Unit tests
test "readVarint single byte" {
    const data = [_]u8{0x01};
    const result = try readVarint(&data);
    try std.testing.expectEqual(@as(u64, 1), result.value);
    try std.testing.expectEqual(@as(usize, 1), result.bytes_read);
}

test "readVarint multi byte" {
    // 300 = 0xAC 0x02
    const data = [_]u8{ 0xAC, 0x02 };
    const result = try readVarint(&data);
    try std.testing.expectEqual(@as(u64, 300), result.value);
    try std.testing.expectEqual(@as(usize, 2), result.bytes_read);
}

test "readVarint max single byte" {
    const data = [_]u8{0x7F};
    const result = try readVarint(&data);
    try std.testing.expectEqual(@as(u64, 127), result.value);
    try std.testing.expectEqual(@as(usize, 1), result.bytes_read);
}

test "ProtobufParser parse empty data" {
    const empty: []const u8 = &[_]u8{};
    var parser = try ProtobufParser.parse(std.testing.allocator, empty);
    defer parser.deinit();

    try std.testing.expectEqual(@as(usize, 0), parser.split_configs.len);
    try std.testing.expectEqual(@as(?[]const u8, null), parser.bundletool_version);
}

test "ProtobufParser hasDimension" {
    // Create a simple test with manually constructed data
    var parser = ProtobufParser{
        .split_configs = &[_]ProtobufParser.SplitConfig{
            .{ .dimension = "ABI", .values = &[_][]const u8{ "arm64-v8a", "armeabi-v7a" } },
            .{ .dimension = "LANGUAGE", .values = &[_][]const u8{ "en", "es", "fr" } },
        },
        .bundletool_version = null,
        .allocator = std.testing.allocator,
    };

    try std.testing.expect(parser.hasDimension("ABI"));
    try std.testing.expect(parser.hasDimension("LANGUAGE"));
    try std.testing.expect(!parser.hasDimension("SCREEN_DENSITY"));
}

test "ProtobufParser getDimensionValues" {
    var parser = ProtobufParser{
        .split_configs = &[_]ProtobufParser.SplitConfig{
            .{ .dimension = "ABI", .values = &[_][]const u8{ "arm64-v8a", "armeabi-v7a" } },
        },
        .bundletool_version = null,
        .allocator = std.testing.allocator,
    };

    const values = parser.getDimensionValues("ABI");
    try std.testing.expect(values != null);
    try std.testing.expectEqual(@as(usize, 2), values.?.len);

    const no_values = parser.getDimensionValues("UNKNOWN");
    try std.testing.expectEqual(@as(?[]const []const u8, null), no_values);
}
