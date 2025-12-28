//! JSON Serialization
//!
//! High-performance, reflection-based JSON serializer.
//! Features buffered string writing, configurable casing, and robust type handling.

const std = @import("std");

/// Serialization configuration options
pub const Options = struct {
    /// Pretty-print with indentation
    pretty: bool = true,
    /// Indentation string
    indent: []const u8 = "  ",
    /// Convert snake_case struct fields to camelCase keys
    convert_to_camel_case: bool = false,
    /// Omit fields with null values entirely (if false, writes "null")
    ignore_null_fields: bool = false,
};

/// Serialize any value to JSON
pub fn serialize(writer: anytype, value: anytype, options: Options) !void {
    try writeValue(writer, value, options, 0);
}

/// Serialize to compact JSON (no whitespace)
pub fn serializeCompact(writer: anytype, value: anytype) !void {
    try serialize(writer, value, .{ .pretty = false });
}

/// Internal recursive serializer
fn writeValue(writer: anytype, value: anytype, options: Options, depth: usize) !void {
    const T = @TypeOf(value);
    const info = @typeInfo(T);

    switch (info) {
        .float, .comptime_float => {
            if (std.math.isNan(value) or std.math.isInf(value)) {
                try writer.writeAll("null");
            } else {
                try writer.print("{d}", .{value});
            }
        },
        .int, .comptime_int => {
            try writer.print("{d}", .{value});
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .null => {
            try writer.writeAll("null");
        },
        .optional => {
            if (value) |v| {
                try writeValue(writer, v, options, depth);
            } else {
                try writer.writeAll("null");
            }
        },
        .@"enum" => {
            try writeString(writer, @tagName(value));
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    try writeString(writer, value);
                } else {
                    try writeArray(writer, value, options, depth);
                }
            } else if (ptr.size == .one) {
                try writeValue(writer, value.*, options, depth);
            } else {
                @compileError("Cannot serialize multi-item pointer of type " ++ @typeName(T));
            }
        },
        .array => |arr| {
            if (arr.child == u8) {
                try writeString(writer, &value);
            } else {
                try writeArray(writer, &value, options, depth);
            }
        },
        .@"struct" => |s| {
            if (s.is_tuple) {
                try writeTuple(writer, value, options, depth);
            } else {
                try writeStruct(writer, value, options, depth);
            }
        },
        .void => {
            try writer.writeAll("null");
        },
        else => {
            @compileError("Unsupported JSON type: " ++ @typeName(T));
        },
    }
}

fn writeStruct(writer: anytype, value: anytype, options: Options, depth: usize) !void {
    try writer.writeByte('{');

    const T = @TypeOf(value);
    const fields = std.meta.fields(T);
    var has_output = false;

    inline for (fields) |field| {
        const FieldType = field.type;

        // Filter out internal types (allocators, arenas, void) by TYPE, not name
        // This avoids false positives (e.g., a game with an "allocator" resource field)
        // and false negatives (e.g., an allocator named "mem_pool")
        if (FieldType == std.mem.Allocator or
            FieldType == std.heap.ArenaAllocator or
            FieldType == void) continue;

        const field_val = @field(value, field.name);

        // Handle optional null omission
        const is_optional = comptime @typeInfo(FieldType) == .optional;
        const should_skip = if (is_optional)
            options.ignore_null_fields and field_val == null
        else
            false;

        if (!should_skip) {
            if (has_output) {
                try writer.writeByte(',');
            }
            if (options.pretty) {
                try writer.writeByte('\n');
                try writeIndent(writer, options.indent, depth + 1);
            }

            has_output = true;

            // Write key
            try writer.writeByte('"');
            if (options.convert_to_camel_case) {
                try writeCamelCase(writer, field.name);
            } else {
                try writer.writeAll(field.name);
            }
            try writer.writeAll("\":");
            if (options.pretty) try writer.writeByte(' ');

            // Write value
            try writeValue(writer, field_val, options, depth + 1);
        }
    }

    if (options.pretty and has_output) {
        try writer.writeByte('\n');
        try writeIndent(writer, options.indent, depth);
    }
    try writer.writeByte('}');
}

fn writeArray(writer: anytype, items: anytype, options: Options, depth: usize) !void {
    try writer.writeByte('[');

    var first = true;
    for (items) |item| {
        if (!first) try writer.writeByte(',');
        first = false;

        if (options.pretty) {
            try writer.writeByte('\n');
            try writeIndent(writer, options.indent, depth + 1);
        }

        try writeValue(writer, item, options, depth + 1);
    }

    if (options.pretty and items.len > 0) {
        try writer.writeByte('\n');
        try writeIndent(writer, options.indent, depth);
    }
    try writer.writeByte(']');
}

fn writeTuple(writer: anytype, tuple: anytype, options: Options, depth: usize) !void {
    try writer.writeByte('[');
    const fields = std.meta.fields(@TypeOf(tuple));

    inline for (fields, 0..) |field, i| {
        if (i > 0) try writer.writeByte(',');

        if (options.pretty) {
            try writer.writeByte('\n');
            try writeIndent(writer, options.indent, depth + 1);
        }

        try writeValue(writer, @field(tuple, field.name), options, depth + 1);
    }

    if (options.pretty and fields.len > 0) {
        try writer.writeByte('\n');
        try writeIndent(writer, options.indent, depth);
    }
    try writer.writeByte(']');
}

/// Optimized string writer.
/// Scans for characters needing escape and writes benign chunks in bulk.
pub fn writeString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');

    var start_idx: usize = 0;
    var i: usize = 0;

    while (i < value.len) : (i += 1) {
        const c = value[i];

        // Check for special characters per JSON spec (RFC 8259)
        const escape_seq: ?[]const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            0x08 => "\\b",
            0x0C => "\\f",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            else => null,
        };

        if (escape_seq) |seq| {
            if (i > start_idx) try writer.writeAll(value[start_idx..i]);
            try writer.writeAll(seq);
            start_idx = i + 1;
        } else if (c <= 0x1F) {
            // Control characters must be escaped as unicode hex
            if (i > start_idx) try writer.writeAll(value[start_idx..i]);
            try writer.print("\\u{x:0>4}", .{c});
            start_idx = i + 1;
        }
    }

    // Write remaining chunk
    if (start_idx < value.len) {
        try writer.writeAll(value[start_idx..]);
    }

    try writer.writeByte('"');
}

fn writeIndent(writer: anytype, indent: []const u8, depth: usize) !void {
    for (0..depth) |_| {
        try writer.writeAll(indent);
    }
}

fn writeCamelCase(writer: anytype, name: []const u8) !void {
    var capitalize_next = false;
    for (name) |c| {
        if (c == '_') {
            capitalize_next = true;
        } else if (capitalize_next) {
            try writer.writeByte(std.ascii.toUpper(c));
            capitalize_next = false;
        } else {
            try writer.writeByte(c);
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

test "serialize basic types" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    // Int
    try serializeCompact(buf.writer(std.testing.allocator), @as(u32, 123));
    try std.testing.expectEqualStrings("123", buf.items);

    // Bool
    buf.clearRetainingCapacity();
    try serializeCompact(buf.writer(std.testing.allocator), true);
    try std.testing.expectEqualStrings("true", buf.items);

    // Float (precision)
    buf.clearRetainingCapacity();
    try serializeCompact(buf.writer(std.testing.allocator), @as(f64, 12.345678));
    try std.testing.expectEqualStrings("12.345678", buf.items);
}

test "serialize string escaping" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    try writeString(buf.writer(std.testing.allocator), "Hello\n\"World\"");
    try std.testing.expectEqualStrings("\"Hello\\n\\\"World\\\"\"", buf.items);

    buf.clearRetainingCapacity();
    try writeString(buf.writer(std.testing.allocator), "\x1F"); // Unit separator (control char)
    try std.testing.expectEqualStrings("\"\\u001f\"", buf.items);
}

test "serialize struct with options" {
    const User = struct {
        first_name: []const u8,
        is_active: bool,
        meta_data: ?u32,
        allocator: std.mem.Allocator, // Should be ignored
    };

    const u = User{
        .first_name = "John",
        .is_active = true,
        .meta_data = null,
        .allocator = std.testing.allocator,
    };

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    // Test 1: Snake case, keep nulls (default)
    try serializeCompact(buf.writer(std.testing.allocator), u);
    const s1 = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, s1, "\"first_name\":\"John\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "\"meta_data\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, s1, "allocator") == null);

    // Test 2: Camel case, ignore nulls
    buf.clearRetainingCapacity();
    try serialize(buf.writer(std.testing.allocator), u, .{ .pretty = false, .convert_to_camel_case = true, .ignore_null_fields = true });
    const s2 = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, s2, "\"firstName\":\"John\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s2, "metaData") == null); // Ignored
}

test "serialize tuple" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    const t = .{ 1, "two", true };
    try serializeCompact(buf.writer(std.testing.allocator), t);
    try std.testing.expectEqualStrings("[1,\"two\",true]", buf.items);
}

test "serialize array" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    const arr = [_]u32{ 1, 2, 3 };
    try serializeCompact(buf.writer(std.testing.allocator), arr);
    try std.testing.expectEqualStrings("[1,2,3]", buf.items);
}

test "serialize optional" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    const some: ?u32 = 42;
    try serializeCompact(buf.writer(std.testing.allocator), some);
    try std.testing.expectEqualStrings("42", buf.items);

    buf.clearRetainingCapacity();
    const none: ?u32 = null;
    try serializeCompact(buf.writer(std.testing.allocator), none);
    try std.testing.expectEqualStrings("null", buf.items);
}

test "serialize enum" {
    const Status = enum { active, inactive, pending };

    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    try serializeCompact(buf.writer(std.testing.allocator), Status.active);
    try std.testing.expectEqualStrings("\"active\"", buf.items);
}

test "serialize special floats" {
    var buf = std.ArrayListUnmanaged(u8){};
    defer buf.deinit(std.testing.allocator);

    // NaN should serialize as null
    try serializeCompact(buf.writer(std.testing.allocator), std.math.nan(f64));
    try std.testing.expectEqualStrings("null", buf.items);

    // Infinity should serialize as null
    buf.clearRetainingCapacity();
    try serializeCompact(buf.writer(std.testing.allocator), std.math.inf(f64));
    try std.testing.expectEqualStrings("null", buf.items);
}
