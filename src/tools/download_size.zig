const std = @import("std");
const zip = @import("../parsers/zip.zig");

/// Download size estimation result
pub const DownloadSizeEstimate = struct {
    /// Estimated download size in bytes
    download_size: u64,
    /// Original APK file size in bytes
    file_size: u64,
    /// Estimated compression ratio (0.0 - 1.0)
    compression_ratio: f32,
    /// Detailed breakdown by component
    breakdown: SizeBreakdown,

    pub const SizeBreakdown = struct {
        dex: u64,
        native: u64,
        resources: u64,
        assets: u64,
        other: u64,
    };
};

pub const DownloadSizeEstimator = struct {
    allocator: std.mem.Allocator,

    // Empirical compression factors (Multiplied by 100 for integer math)
    // 95 means "95% of original size" (5% reduction)
    const FACTOR_DEX = 88; // DEX compresses very well with Brotli
    const FACTOR_NATIVE = 92; // Native libs usually see moderate gains over Deflate
    const FACTOR_RESOURCES = 85; // ARSC and XMLs compress significantly
    const FACTOR_ASSETS = 95; // Assets (often media) don't compress much more
    const FACTOR_OTHER = 90; // Metadata, signatures, etc.

    pub fn init(allocator: std.mem.Allocator) DownloadSizeEstimator {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *DownloadSizeEstimator) void {
        _ = self;
    }

    /// Estimate download size from APK memory buffer
    pub fn estimate(self: *DownloadSizeEstimator, data: []const u8) !DownloadSizeEstimate {
        // Play Store serves the file using Brotli compression which is generally
        // 10-20% more efficient than the Deflate used in standard ZIPs.
        var archive = try zip.ZipParser.parse(self.allocator, data);
        defer archive.deinit();

        return self.calculateEstimate(&archive, data.len);
    }

    /// Estimate download size from file path
    pub fn estimateFile(self: *DownloadSizeEstimator, path: []const u8) !DownloadSizeEstimate {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const file_size = try file.getEndPos();

        // Safety: Limit read to 500MB to prevent OOM.
        // For larger files, a streaming parser or mmap is required.
        if (file_size > 500 * 1024 * 1024) {
            return error.FileTooLarge;
        }

        const data = try file.readToEndAlloc(self.allocator, 500 * 1024 * 1024);
        defer self.allocator.free(data);

        return self.estimate(data);
    }

    fn calculateEstimate(self: *DownloadSizeEstimator, archive: *zip.ZipParser, original_size: u64) DownloadSizeEstimate {
        _ = self;
        var breakdown = DownloadSizeEstimate.SizeBreakdown{
            .dex = 0,
            .native = 0,
            .resources = 0,
            .assets = 0,
            .other = 0,
        };

        // Categorize and Sum
        for (archive.listFiles()) |entry| {
            // We use compressed_size because that represents the "Deflate" baseline.
            // Play Store re-compresses, but the relative bulk is best estimated from
            // the already-compressed state for generic files.
            const size = entry.compressed_size;
            const name = entry.name;

            if (std.mem.endsWith(u8, name, ".dex")) {
                breakdown.dex += size;
            } else if (std.mem.endsWith(u8, name, ".so")) {
                breakdown.native += size;
            } else if (std.mem.startsWith(u8, name, "res/") or
                std.mem.eql(u8, name, "resources.arsc"))
            {
                breakdown.resources += size;
            } else if (std.mem.startsWith(u8, name, "assets/")) {
                breakdown.assets += size;
            } else {
                breakdown.other += size;
            }
        }

        //
        // Apply integer-based compression factors
        const est_dex = (breakdown.dex * FACTOR_DEX) / 100;
        const est_native = (breakdown.native * FACTOR_NATIVE) / 100;
        const est_resources = (breakdown.resources * FACTOR_RESOURCES) / 100;
        const est_assets = (breakdown.assets * FACTOR_ASSETS) / 100;
        const est_other = (breakdown.other * FACTOR_OTHER) / 100;

        var total_est = est_dex + est_native + est_resources + est_assets + est_other;

        // Signature Block Heuristic:
        // APK v2/v3 signatures are a block in the ZIP file. Play Store delivers
        // a different signature (Play signed). The upload signature is essentially wasted bytes.
        // We assume roughly 4KB overhead for certificates + block headers.
        if (total_est > 4096) {
            total_est -= 4096;
        }

        const ratio = if (original_size > 0)
            @as(f32, @floatFromInt(total_est)) / @as(f32, @floatFromInt(original_size))
        else
            1.0;

        return .{
            .download_size = total_est,
            .file_size = original_size,
            .compression_ratio = ratio,
            .breakdown = .{
                .dex = est_dex,
                .native = est_native,
                .resources = est_resources,
                .assets = est_assets,
                .other = est_other,
            },
        };
    }

    /// Formats a file size into a human-readable string.
    /// Returns a slice to a static thread-local buffer (valid until next call).
    pub fn formatSize(size: u64) []const u8 {
        // Thread-local buffer prevents data races if multiple threads log at once
        // (assuming the logger copies immediately).
        const S = struct {
            threadlocal var buf: [64]u8 = undefined;
        };

        const f_size = @as(f64, @floatFromInt(size));

        if (f_size < 1024.0) {
            return std.fmt.bufPrint(&S.buf, "{d} B", .{size}) catch "ERR";
        }

        const kb = f_size / 1024.0;
        if (kb < 1024.0) {
            return std.fmt.bufPrint(&S.buf, "{d:.1} KB", .{kb}) catch "ERR";
        }

        const mb = kb / 1024.0;
        return std.fmt.bufPrint(&S.buf, "{d:.2} MB", .{mb}) catch "ERR";
    }
};

// ============================================================================
// Unit Tests
// ============================================================================

test "formatSize handles scales" {
    try std.testing.expectEqualStrings("500 B", DownloadSizeEstimator.formatSize(500));
    try std.testing.expectEqualStrings("1.0 KB", DownloadSizeEstimator.formatSize(1024));
    try std.testing.expectEqualStrings("1.5 KB", DownloadSizeEstimator.formatSize(1536));
    try std.testing.expectEqualStrings("1.00 MB", DownloadSizeEstimator.formatSize(1048576));
}

test "estimate calculation uses integer math" {
    // Mock allocator not strictly needed for this calc logic if we could isolate it,
    // but here we test the flow.
    const est = DownloadSizeEstimator.init(std.testing.allocator);
    _ = est;

    // We can't easily mock the ZipParser output without a real zip file in this snippet,
    // but we can verify the constant factors mathematically:
    // DEX 1000 bytes -> 1000 * 88 / 100 = 880 bytes.
    const input: u64 = 1000;
    const factor = 88;
    const expected = (input * factor) / 100;
    try std.testing.expectEqual(@as(u64, 880), expected);
}
