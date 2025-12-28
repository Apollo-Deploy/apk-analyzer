//! Main Analyzer
//!
//! Thin orchestration layer that coordinates parsers and aggregates results.
//! Follows single responsibility - only orchestrates, doesn't parse.

const std = @import("std");
const core = @import("../core/mod.zig");
const Options = @import("options.zig").Options;

// Import parsers (using existing implementations for now)
const zip = @import("../parsers/zip.zig");
const axml = @import("../parsers/axml.zig");
const dex = @import("../parsers/dex.zig");
const certificate = @import("../parsers/certificate.zig");
const pb_manifest = @import("../parsers/pb_manifest.zig");
const arsc = @import("../parsers/arsc.zig");

/// Main analyzer for APK and AAB files
pub const Analyzer = struct {
    allocator: std.mem.Allocator,
    options: Options,

    /// Initialize analyzer with allocator and options
    pub fn init(allocator: std.mem.Allocator, options: Options) Analyzer {
        return .{
            .allocator = allocator,
            .options = options,
        };
    }

    /// Analyze APK or AAB from memory
    pub fn analyze(self: *Analyzer, data: []const u8) core.AnalysisError!core.AnalysisResult {
        // Check memory budget
        if (self.options.max_memory > 0 and data.len > self.options.max_memory) {
            return core.AnalysisError.MemoryBudgetExceeded;
        }

        // Create arena for this analysis session
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        // Initialize result
        var result = core.AnalysisResult{};
        var diagnostics = core.errors.DiagnosticCollector.init(alloc);

        // Parse ZIP archive
        var archive = zip.ZipParser.parse(alloc, data) catch |err| {
            return switch (err) {
                error.InvalidArchive => core.AnalysisError.InvalidArchive,
                error.OutOfMemory => core.AnalysisError.OutOfMemory,
                error.TruncatedArchive => core.AnalysisError.TruncatedArchive,
                error.PathTraversal => core.AnalysisError.InvalidArchive,
                else => core.AnalysisError.InvalidArchive,
            };
        };
        defer archive.deinit();

        // Detect artifact type and set sizes
        result.artifact_type = detectArtifactType(&archive);
        result.compressed_size = data.len;
        result.uncompressed_size = archive.totalUncompressedSize();

        // Parse manifest
        if (result.artifact_type == .aab) {
            self.parseAabManifest(alloc, &archive, &result, &diagnostics) catch |err| {
                return mapError(err);
            };
        } else {
            self.parseApkManifest(alloc, &archive, &result, &diagnostics) catch |err| {
                return mapError(err);
            };
        }

        // Analyze DEX files (unless skipped)
        if (!self.options.skip_dex_analysis) {
            self.analyzeDex(alloc, &archive, &result, &diagnostics) catch {
                diagnostics.addWarning(.dex_analysis_failed, "Failed to analyze DEX files") catch {};
            };
        }

        // Extract certificate (unless skipped)
        if (!self.options.skip_certificate) {
            self.extractCertificate(alloc, &archive, &result, &diagnostics) catch {
                diagnostics.addWarning(.certificate_extraction_failed, "Failed to extract certificate") catch {};
            };
        }

        // Analyze native libraries
        self.analyzeNativeLibs(alloc, &archive, &result) catch {
            diagnostics.addWarning(.native_analysis_failed, "Failed to analyze native libraries") catch {};
        };

        // Calculate size breakdown
        self.calculateSizeBreakdown(&archive, &result);

        // Finalize - convert diagnostics to core types
        const diag_slice = diagnostics.toOwnedSlice() catch &[_]core.errors.Diagnostic{};
        if (diag_slice.len > 0) {
            const core_diags = try alloc.alloc(core.Diagnostic, diag_slice.len);
            for (diag_slice, 0..) |d, i| {
                core_diags[i] = .{
                    .code = @enumFromInt(@intFromEnum(d.code)),
                    .message = d.message,
                    .severity = @enumFromInt(@intFromEnum(d.severity)),
                };
            }
            result.diagnostics = core_diags;
        }
        result._arena = arena;

        return result;
    }

    /// Analyze from file path
    pub fn analyzeFile(self: *Analyzer, path: []const u8) core.AnalysisError!core.AnalysisResult {
        const file = std.fs.cwd().openFile(path, .{}) catch {
            return core.AnalysisError.IoError;
        };
        defer file.close();

        const file_size = file.getEndPos() catch {
            return core.AnalysisError.IoError;
        };

        if (self.options.max_memory > 0 and file_size > self.options.max_memory) {
            return core.AnalysisError.FileTooLarge;
        }

        const data = file.readToEndAlloc(self.allocator, 200 * 1024 * 1024) catch {
            return core.AnalysisError.OutOfMemory;
        };
        defer self.allocator.free(data);

        return self.analyze(data);
    }

    /// Analyze from file path using memory-mapped I/O.
    /// This is more memory-efficient for large files as the OS manages
    /// page loading on-demand rather than loading the entire file upfront.
    /// Only pages that are actually accessed are loaded into physical memory.
    pub fn analyzeFileMapped(self: *Analyzer, path: []const u8) core.AnalysisError!core.AnalysisResult {
        const file = std.fs.cwd().openFile(path, .{}) catch {
            return core.AnalysisError.IoError;
        };
        defer file.close();

        const file_size = file.getEndPos() catch {
            return core.AnalysisError.IoError;
        };

        if (file_size == 0) {
            return core.AnalysisError.InvalidArchive;
        }

        if (self.options.max_memory > 0 and file_size > self.options.max_memory) {
            return core.AnalysisError.FileTooLarge;
        }

        // Memory-map the file for read-only access
        // This lets the OS manage which pages are loaded into physical memory
        const mapped_data = std.posix.mmap(
            null,
            @intCast(file_size),
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        ) catch {
            // Fall back to regular file read if mmap fails
            return self.analyzeFile(path);
        };
        defer std.posix.munmap(mapped_data);

        // Advise the kernel that we'll read sequentially (improves prefetching)
        // MADV_SEQUENTIAL = 2 on most Unix systems
        std.posix.madvise(@alignCast(mapped_data.ptr), mapped_data.len, 2) catch {};

        return self.analyze(mapped_data);
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    fn parseApkManifest(
        self: *Analyzer,
        alloc: std.mem.Allocator,
        archive: *zip.ZipParser,
        result: *core.AnalysisResult,
        diagnostics: *core.errors.DiagnosticCollector,
    ) !void {
        _ = self;

        const entry = archive.findFile("AndroidManifest.xml") orelse {
            return core.AnalysisError.MissingManifest;
        };

        const data = archive.getDecompressedData(alloc, entry) catch {
            return core.AnalysisError.InvalidManifest;
        };

        var parser = axml.AxmlParser.parse(alloc, data) catch {
            try diagnostics.addError(.manifest_parse_failed, "Failed to parse AndroidManifest.xml");
            return core.AnalysisError.InvalidManifest;
        };
        defer parser.deinit();

        const meta = parser.extractManifestMetadata(alloc) catch {
            return core.AnalysisError.OutOfMemory;
        };

        // Convert to core types
        var metadata = convertMetadata(alloc, meta) catch {
            return core.AnalysisError.OutOfMemory;
        };

        // Check if app_name looks like a resource ID (numeric string > 1000000)
        // Resource IDs in Android are typically in the 0x7f000000 range (2130706432+)
        if (metadata.app_name.len > 0) {
            const resource_id = std.fmt.parseInt(u32, metadata.app_name, 10) catch null;
            if (resource_id) |res_id| {
                if (res_id > 1000000) {
                    // Try to resolve from resources.arsc
                    if (archive.findFile("resources.arsc")) |arsc_entry| {
                        if (archive.getDecompressedData(alloc, arsc_entry)) |arsc_data| {
                            var arsc_parser = arsc.ArscParser.parse(alloc, arsc_data) catch null;
                            if (arsc_parser) |*ap| {
                                defer ap.deinit();
                                if (ap.resolveString(res_id)) |resolved_name| {
                                    // Use the resolved string as app_name
                                    metadata.app_name = alloc.dupe(u8, resolved_name) catch metadata.app_name;
                                }
                            }
                        } else |_| {}
                    }
                }
            }
        }

        result.metadata = metadata;
    }

    fn parseAabManifest(
        self: *Analyzer,
        alloc: std.mem.Allocator,
        archive: *zip.ZipParser,
        result: *core.AnalysisResult,
        diagnostics: *core.errors.DiagnosticCollector,
    ) !void {
        _ = self;

        const entry = archive.findFile("base/manifest/AndroidManifest.xml") orelse {
            return core.AnalysisError.MissingManifest;
        };

        const data = archive.getDecompressedData(alloc, entry) catch {
            return core.AnalysisError.InvalidManifest;
        };

        var parser = pb_manifest.PbManifestParser.parse(alloc, data) catch {
            try diagnostics.addError(.manifest_parse_failed, "Failed to parse protobuf manifest");
            return core.AnalysisError.InvalidManifest;
        };
        defer parser.deinit();

        const meta = parser.extractMetadata();
        result.metadata = convertPbMetadata(alloc, meta) catch {
            return core.AnalysisError.OutOfMemory;
        };
    }

    /// Analyze DEX files sequentially to minimize memory usage.
    /// Each DEX file is decompressed, analyzed, and immediately freed
    /// before processing the next one. This reduces peak memory from
    /// O(sum of all DEX sizes) to O(largest single DEX size).
    fn analyzeDex(
        self: *Analyzer,
        alloc: std.mem.Allocator,
        archive: *zip.ZipParser,
        result: *core.AnalysisResult,
        diagnostics: *core.errors.DiagnosticCollector,
    ) !void {
        _ = self;
        _ = diagnostics;

        // First pass: count DEX files to pre-allocate
        var dex_count: usize = 0;
        for (archive.listFiles()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".dex")) {
                dex_count += 1;
            }
        }

        if (dex_count == 0) return;

        // Pre-allocate file info array
        var files = try alloc.alloc(core.DexFileInfo, dex_count);
        errdefer alloc.free(files);

        // Aggregate statistics
        var total_methods: u64 = 0;
        var total_classes: u64 = 0;
        var total_fields: u64 = 0;
        var file_idx: usize = 0;

        // Second pass: process each DEX file sequentially
        // This is the key optimization - we only keep ONE decompressed DEX in memory at a time
        for (archive.listFiles()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".dex")) {
                // Decompress this DEX file
                const dex_data = archive.getDecompressedData(alloc, &entry) catch continue;
                // IMPORTANT: Free immediately after analysis to minimize peak memory
                defer alloc.free(dex_data);

                // Analyze this single DEX file (only parses 112-byte header)
                const info = dex.DexAnalyzer.analyze(alloc, dex_data) catch continue;

                // Store results
                files[file_idx] = .{
                    .method_count = info.method_count,
                    .class_count = info.class_count,
                    .field_count = info.field_count,
                    .string_count = info.string_count,
                    .version = info.version,
                    .exceeds_limit = info.exceeds_limit,
                };

                // Aggregate totals
                total_methods += info.method_count;
                total_classes += info.class_count;
                total_fields += info.field_count;

                file_idx += 1;
            }
        }

        // Shrink array if some DEX files failed to parse
        if (file_idx < dex_count) {
            files = alloc.realloc(files, file_idx) catch files[0..file_idx];
        }

        result.dex_info = .{
            .files = files[0..file_idx],
            .total_methods = total_methods,
            .total_classes = total_classes,
            .total_fields = total_fields,
            .is_multidex = file_idx > 1,
        };
    }

    fn extractCertificate(
        self: *Analyzer,
        alloc: std.mem.Allocator,
        archive: *zip.ZipParser,
        result: *core.AnalysisResult,
        diagnostics: *core.errors.DiagnosticCollector,
    ) !void {
        _ = self;
        _ = diagnostics;

        var parser = certificate.CertificateParser.init(alloc);
        defer parser.deinit();

        const info = parser.extractFromApk(archive) catch return;

        result.certificate = .{
            .subject = info.subject,
            .issuer = info.issuer,
            .serial_number = info.serial_number,
            .not_before = info.not_before,
            .not_after = info.not_after,
            .fingerprint_md5 = info.fingerprint_md5,
            .fingerprint_sha256 = info.fingerprint_sha256,
            .signature_algorithm = info.signature_algorithm,
            .public_key_algorithm = info.public_key_algorithm,
            .public_key_size = info.public_key_size,
        };
    }

    fn analyzeNativeLibs(
        self: *Analyzer,
        alloc: std.mem.Allocator,
        archive: *zip.ZipParser,
        result: *core.AnalysisResult,
    ) !void {
        _ = self;

        var architectures = std.ArrayListUnmanaged([]const u8){};
        var seen = std.StringHashMap(void).init(alloc);
        defer seen.deinit();

        var total_size: u64 = 0;

        for (archive.listFiles()) |entry| {
            if (std.mem.startsWith(u8, entry.name, "lib/") and
                std.mem.endsWith(u8, entry.name, ".so"))
            {
                const after_lib = entry.name[4..];
                if (std.mem.indexOf(u8, after_lib, "/")) |slash_pos| {
                    const abi = after_lib[0..slash_pos];
                    if (!seen.contains(abi)) {
                        const abi_copy = try alloc.dupe(u8, abi);
                        try architectures.append(alloc, abi_copy);
                        try seen.put(abi_copy, {});
                    }
                    total_size += entry.uncompressed_size;
                }
            }
        }

        result.native_libs = .{
            .architectures = try architectures.toOwnedSlice(alloc),
            .total_size = total_size,
        };
    }

    fn calculateSizeBreakdown(self: *Analyzer, archive: *zip.ZipParser, result: *core.AnalysisResult) void {
        _ = self;

        var breakdown = core.SizeBreakdown{};

        for (archive.listFiles()) |entry| {
            const size = entry.uncompressed_size;

            if (std.mem.endsWith(u8, entry.name, ".dex")) {
                breakdown.dex.size += size;
            } else if (std.mem.startsWith(u8, entry.name, "res/") or
                std.mem.eql(u8, entry.name, "resources.arsc"))
            {
                breakdown.resources.size += size;
            } else if (std.mem.startsWith(u8, entry.name, "lib/")) {
                breakdown.native.size += size;
            } else if (std.mem.startsWith(u8, entry.name, "assets/")) {
                breakdown.assets.size += size;
            } else {
                breakdown.other.size += size;
            }
        }

        breakdown.calculatePercentages(result.uncompressed_size);
        result.size_breakdown = breakdown;
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

fn detectArtifactType(archive: *const zip.ZipParser) core.ArtifactType {
    if (archive.findFile("base/manifest/AndroidManifest.xml") != null) return .aab;
    if (archive.findFile("BundleConfig.pb.json") != null) return .aab;
    return .apk;
}

fn mapError(err: anyerror) core.AnalysisError {
    return switch (err) {
        error.OutOfMemory => core.AnalysisError.OutOfMemory,
        error.MissingManifest => core.AnalysisError.MissingManifest,
        error.InvalidManifest => core.AnalysisError.InvalidManifest,
        else => core.AnalysisError.InvalidArchive,
    };
}

fn convertMetadata(alloc: std.mem.Allocator, meta: anytype) !core.Metadata {
    // Convert permissions
    var permissions = try alloc.alloc(core.Permission, meta.permissions.len);
    for (meta.permissions, 0..) |p, i| {
        permissions[i] = .{
            .name = p.name,
            .max_sdk_version = p.max_sdk_version,
        };
    }

    // Convert features
    var features = try alloc.alloc(core.Feature, meta.features.len);
    for (meta.features, 0..) |f, i| {
        features[i] = .{
            .name = f.name,
            .required = f.required,
        };
    }

    return .{
        .package_id = meta.package_id,
        .app_name = meta.app_name,
        .version_code_str = meta.version_code,
        .version_name = meta.version_name,
        .min_sdk_version = meta.min_sdk_version,
        .target_sdk_version = meta.target_sdk_version,
        .install_location = core.InstallLocation.fromValue(@intFromEnum(meta.install_location)),
        .permissions = permissions,
        .features = features,
        .is_debuggable = meta.is_debuggable,
    };
}

fn convertPbMetadata(alloc: std.mem.Allocator, meta: anytype) !core.Metadata {
    var permissions = try alloc.alloc(core.Permission, meta.permissions.len);
    for (meta.permissions, 0..) |p, i| {
        permissions[i] = .{
            .name = p.name,
            .max_sdk_version = p.max_sdk_version,
        };
    }

    var features = try alloc.alloc(core.Feature, meta.features.len);
    for (meta.features, 0..) |f, i| {
        features[i] = .{
            .name = f.name,
            .required = f.required,
        };
    }

    return .{
        .package_id = meta.package_id,
        .app_name = meta.app_name,
        .version_code_str = meta.version_code,
        .version_name = meta.version_name,
        .min_sdk_version = meta.min_sdk_version,
        .target_sdk_version = meta.target_sdk_version,
        .permissions = permissions,
        .features = features,
        .is_debuggable = meta.is_debuggable,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Analyzer.init creates analyzer" {
    const analyzer = Analyzer.init(std.testing.allocator, .{});
    _ = analyzer;
}

test "Analyzer with fast preset" {
    const analyzer = Analyzer.init(std.testing.allocator, Options.fast);
    try std.testing.expect(analyzer.options.skip_dex_analysis);
    try std.testing.expect(analyzer.options.skip_certificate);
}
