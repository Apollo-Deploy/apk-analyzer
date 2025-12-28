//! Output Module
//!
//! Provides serialization and formatting for analysis results.

pub const json = @import("json.zig");

// Re-export commonly used functions
pub const toJson = json.serialize;
pub const toJsonCompact = json.serializeCompact;
pub const JsonOptions = json.Options;

test {
    @import("std").testing.refAllDecls(@This());
}
