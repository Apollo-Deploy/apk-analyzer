//! APK Analyzer CLI
//!
//! A standalone command-line tool for analyzing Android APK and AAB files.
//! Outputs analysis results as JSON to stdout.
//!
//! Usage:
//!   apk-analyzer <file.apk|file.aab> [options]
//!   apk-analyzer compare <old.apk> <new.apk> [options]
//!
//! Options:
//!   --help, -h          Show this help message
//!   --version, -v       Show version information
//!   --compact, -c       Output compact JSON (no formatting)
//!   --pretty, -p        Output pretty-printed JSON (default)
//!   --skip-dex          Skip DEX analysis (faster)
//!   --skip-cert         Skip certificate extraction
//!   --fast              Enable fast mode (skip DEX and certificate)
//!   --quiet, -q         Suppress stderr messages
//!
//! Compare Options:
//!   --different-only    Only show files with differences
//!   --files-only        Don't show directory entries
//!   --sort-by-diff      Sort by size difference (largest first)
//!   --breakdown         Include category breakdown
//!   --patch-size        Include estimated patch sizes for delta updates
//!   --category <cat>    Filter by category (dex, native, resources, assets, other)
//!   --added-only        Only show added files
//!   --removed-only      Only show removed files
//!   --modified-only     Only show modified files
//!   --min-diff <bytes>  Filter by minimum absolute size difference
//!   --limit <n>         Limit number of entries returned
//!
//! Exit Codes:
//!   0 - Success
//!   1 - Invalid arguments
//!   2 - File not found or read error
//!   3 - Analysis error (invalid APK/AAB)

const std = @import("std");
const builtin = @import("builtin");
const lib = @import("apk-analyzer");

const version = "0.2.0";

const Command = enum {
    analyze,
    compare,
    verify,
    help,
    version_cmd,
};

const CliOptions = struct {
    command: Command = .analyze,
    file_path: ?[]const u8 = null,
    old_file: ?[]const u8 = null,
    new_file: ?[]const u8 = null,
    compact: bool = false,
    skip_dex: bool = false,
    skip_cert: bool = false,
    quiet: bool = false,
    show_help: bool = false,
    show_version: bool = false,
    use_mmap: bool = true, // Use memory-mapped I/O by default for better memory efficiency
    use_streaming: bool = false, // Use streaming analyzer for minimal memory footprint
    // Compare options
    different_only: bool = false,
    files_only: bool = false,
    sort_by_diff: bool = false,
    breakdown: bool = false,
    patch_size: bool = false,
    category: ?[]const u8 = null,
    added_only: bool = false,
    removed_only: bool = false,
    modified_only: bool = false,
    min_difference: ?u64 = null,
    limit: ?u32 = null,
    // Verify options
    verify_file: ?[]const u8 = null, // Specific file to verify
    verify_all: bool = false, // Verify all files with matching CRC32
};

// Cross-platform stdout/stderr
fn getStdoutFile() std.fs.File {
    if (builtin.os.tag == .windows) {
        return std.fs.File{ .handle = std.os.windows.GetStdHandle(std.os.windows.STD_OUTPUT_HANDLE) catch unreachable };
    } else {
        return std.fs.File{ .handle = std.posix.STDOUT_FILENO };
    }
}

fn getStderrFile() std.fs.File {
    if (builtin.os.tag == .windows) {
        return std.fs.File{ .handle = std.os.windows.GetStdHandle(std.os.windows.STD_ERROR_HANDLE) catch unreachable };
    } else {
        return std.fs.File{ .handle = std.posix.STDERR_FILENO };
    }
}

fn writeStdout(data: []const u8) void {
    const stdout = getStdoutFile();
    _ = stdout.write(data) catch {};
}

fn writeStderr(data: []const u8) void {
    const stderr = getStderrFile();
    _ = stderr.write(data) catch {};
}

fn printStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeStderr(msg);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const cli_opts = parseArgs(allocator) catch {
        printStderr("Error: Invalid arguments\n\n", .{});
        printUsage(false);
        std.process.exit(1);
    };

    // Handle help
    if (cli_opts.show_help or cli_opts.command == .help) {
        printUsage(true);
        return;
    }

    // Handle version
    if (cli_opts.show_version or cli_opts.command == .version_cmd) {
        writeStdout("apk-analyzer ");
        writeStdout(version);
        writeStdout("\n");
        return;
    }

    // Execute command
    switch (cli_opts.command) {
        .analyze => runAnalyze(allocator, cli_opts),
        .compare => runCompare(allocator, cli_opts),
        .verify => runVerify(allocator, cli_opts),
        .help => printUsage(true),
        .version_cmd => {
            writeStdout("apk-analyzer ");
            writeStdout(version);
            writeStdout("\n");
        },
    }
}

fn runAnalyze(allocator: std.mem.Allocator, cli_opts: CliOptions) void {
    // Validate file path
    const file_path = cli_opts.file_path orelse {
        writeStderr("Error: No input file specified\n\n");
        printUsage(false);
        std.process.exit(1);
    };

    // Log start (unless quiet)
    if (!cli_opts.quiet) {
        printStderr("Analyzing: {s}\n", .{file_path});
        if (cli_opts.use_streaming) {
            writeStderr("Using streaming analyzer for minimal memory footprint\n");
        } else if (cli_opts.use_mmap) {
            writeStderr("Using memory-mapped I/O for reduced memory usage\n");
        }
    }

    // Configure analyzer options
    const options = lib.Options{
        .skip_dex_analysis = cli_opts.skip_dex,
        .skip_certificate = cli_opts.skip_cert,
    };

    // Use streaming analyzer for minimal memory footprint
    if (cli_opts.use_streaming) {
        var streaming_analyzer = lib.StreamingAnalyzer.init(allocator, options);
        var result = streaming_analyzer.analyzeFile(file_path) catch |err| {
            printStderr("Error: Analysis failed: {}\n", .{err});
            std.process.exit(3);
        };
        defer result.deinit();

        outputAnalysisResult(allocator, &result, cli_opts);
        return;
    }

    // Standard analyzer with optional mmap
    var analyzer = lib.Analyzer.init(allocator, options);

    // Analyze using memory-mapped I/O or traditional file read
    var result = if (cli_opts.use_mmap)
        analyzer.analyzeFileMapped(file_path) catch |err| {
            printStderr("Error: Analysis failed: {}\n", .{err});
            std.process.exit(3);
        }
    else blk: {
        // Traditional file read path
        const file = std.fs.cwd().openFile(file_path, .{}) catch {
            printStderr("Error: Cannot open file '{s}'\n", .{file_path});
            std.process.exit(2);
        };
        defer file.close();

        const data = file.readToEndAlloc(allocator, 500 * 1024 * 1024) catch {
            printStderr("Error: Cannot read file '{s}'\n", .{file_path});
            std.process.exit(2);
        };
        defer allocator.free(data);

        break :blk analyzer.analyze(data) catch |err| {
            printStderr("Error: Analysis failed: {}\n", .{err});
            std.process.exit(3);
        };
    };
    defer result.deinit();

    outputAnalysisResult(allocator, &result, cli_opts);
}

fn outputAnalysisResult(allocator: std.mem.Allocator, result: *lib.AnalysisResult, cli_opts: CliOptions) void {
    // Create JSON view
    const json_view = lib.AnalysisResultJson.fromResult(result, allocator) catch {
        writeStderr("Error: Failed to create JSON output\n");
        std.process.exit(3);
    };

    // Serialize to a buffer first, then write to stdout
    var json_buf = std.ArrayListUnmanaged(u8){};
    defer json_buf.deinit(allocator);

    const json_opts = lib.output.json.Options{
        .pretty = !cli_opts.compact,
        .convert_to_camel_case = true,
    };

    lib.output.json.serialize(json_buf.writer(allocator), json_view, json_opts) catch {
        writeStderr("Error: Failed to serialize JSON\n");
        std.process.exit(3);
    };

    // Write JSON to stdout
    const stdout = getStdoutFile();
    _ = stdout.writeAll(json_buf.items) catch {
        writeStderr("Error: Failed to write output\n");
        std.process.exit(3);
    };
    writeStdout("\n");

    // Log completion (unless quiet)
    if (!cli_opts.quiet) {
        writeStderr("Analysis complete.\n");
    }
}

fn runCompare(allocator: std.mem.Allocator, cli_opts: CliOptions) void {
    const old_file = cli_opts.old_file orelse {
        writeStderr("Error: No old file specified for comparison\n\n");
        printUsage(false);
        std.process.exit(1);
    };

    const new_file = cli_opts.new_file orelse {
        writeStderr("Error: No new file specified for comparison\n\n");
        printUsage(false);
        std.process.exit(1);
    };

    // Log start (unless quiet)
    if (!cli_opts.quiet) {
        printStderr("Comparing:\n  Old: {s}\n  New: {s}\n", .{ old_file, new_file });
        if (cli_opts.use_mmap) {
            writeStderr("Using streaming comparison (memory-mapped I/O) for reduced memory usage\n");
        }
    }

    // Compare options
    const compare_opts = lib.CompareOptions{
        .different_only = cli_opts.different_only,
        .files_only = cli_opts.files_only,
        .sort_by_difference = cli_opts.sort_by_diff,
        .include_breakdown = cli_opts.breakdown,
        .patch_size = cli_opts.patch_size,
        .category = cli_opts.category,
        .added_only = cli_opts.added_only,
        .removed_only = cli_opts.removed_only,
        .modified_only = cli_opts.modified_only,
        .min_difference = cli_opts.min_difference,
        .limit = cli_opts.limit,
    };

    // Run comparison using streaming comparator (memory-efficient) or standard comparator
    var result = if (cli_opts.use_mmap) blk: {
        var comparator = lib.StreamingApkComparator.init(allocator);
        defer comparator.deinit();
        break :blk comparator.compareFiles(old_file, new_file, compare_opts) catch |err| {
            printStderr("Error: Comparison failed: {}\n", .{err});
            std.process.exit(3);
        };
    } else blk: {
        var comparator = lib.ApkComparator.init(allocator);
        defer comparator.deinit();
        break :blk comparator.compareFiles(old_file, new_file, compare_opts) catch |err| {
            printStderr("Error: Comparison failed: {}\n", .{err});
            std.process.exit(3);
        };
    };
    defer result.deinit();

    // Output as JSON
    var json_buf = std.ArrayListUnmanaged(u8){};
    defer json_buf.deinit(allocator);

    const json_opts = lib.output.json.Options{
        .pretty = !cli_opts.compact,
        .convert_to_camel_case = true,
    };

    // Build JSON output structure
    const writer = json_buf.writer(allocator);

    // Start object
    writer.writeAll("{\n") catch {};

    // Summary
    writer.writeAll("  \"summary\": {\n") catch {};
    writeJsonField(writer, "    ", "oldTotal", result.old_total, false);
    writeJsonField(writer, "    ", "newTotal", result.new_total, false);
    writeJsonField(writer, "    ", "totalDifference", result.total_difference, false);
    writeJsonField(writer, "    ", "oldFileCount", result.summary.old_file_count, false);
    writeJsonField(writer, "    ", "newFileCount", result.summary.new_file_count, false);
    writeJsonField(writer, "    ", "addedCount", result.summary.added_count, false);
    writeJsonField(writer, "    ", "removedCount", result.summary.removed_count, false);
    writeJsonField(writer, "    ", "modifiedCount", result.summary.modified_count, false);
    writeJsonField(writer, "    ", "unchangedCount", result.summary.unchanged_count, true);
    writer.writeAll("  },\n") catch {};

    // Breakdown (if enabled)
    if (result.breakdown) |breakdown| {
        writer.writeAll("  \"breakdown\": [\n") catch {};
        for (breakdown, 0..) |bd, i| {
            writer.writeAll("    {\n") catch {};
            writeJsonStringField(writer, "      ", "category", bd.category.toString(), false);
            writeJsonField(writer, "      ", "oldSize", bd.old_size, false);
            writeJsonField(writer, "      ", "newSize", bd.new_size, false);
            writeJsonField(writer, "      ", "difference", bd.difference, false);
            writeJsonField(writer, "      ", "fileCount", bd.file_count, false);
            writeJsonField(writer, "      ", "addedCount", bd.added_count, false);
            writeJsonField(writer, "      ", "removedCount", bd.removed_count, false);
            writeJsonField(writer, "      ", "modifiedCount", bd.modified_count, true);
            if (i < breakdown.len - 1) {
                writer.writeAll("    },\n") catch {};
            } else {
                writer.writeAll("    }\n") catch {};
            }
        }
        writer.writeAll("  ],\n") catch {};
    }

    // Entries
    writer.writeAll("  \"entries\": [\n") catch {};
    for (result.entries, 0..) |entry, i| {
        writer.writeAll("    {\n") catch {};
        writeJsonStringField(writer, "      ", "path", entry.path, false);
        writeJsonField(writer, "      ", "oldSize", entry.old_size, false);
        writeJsonField(writer, "      ", "newSize", entry.new_size, false);
        writeJsonField(writer, "      ", "difference", entry.difference, false);
        writeJsonStringField(writer, "      ", "status", @tagName(entry.status), false);
        writeJsonBoolField(writer, "      ", "isDirectory", entry.is_directory, true);
        if (i < result.entries.len - 1) {
            writer.writeAll("    },\n") catch {};
        } else {
            writer.writeAll("    }\n") catch {};
        }
    }
    writer.writeAll("  ]\n") catch {};

    writer.writeAll("}\n") catch {};

    _ = json_opts;

    // Write to stdout
    const stdout = getStdoutFile();
    _ = stdout.writeAll(json_buf.items) catch {
        writeStderr("Error: Failed to write output\n");
        std.process.exit(3);
    };

    // Log completion (unless quiet)
    if (!cli_opts.quiet) {
        writeStderr("Comparison complete.\n");
    }
}

fn runVerify(allocator: std.mem.Allocator, cli_opts: CliOptions) void {
    const old_file = cli_opts.old_file orelse {
        writeStderr("Error: No old file specified for verification\n\n");
        printUsage(false);
        std.process.exit(1);
    };

    const new_file = cli_opts.new_file orelse {
        writeStderr("Error: No new file specified for verification\n\n");
        printUsage(false);
        std.process.exit(1);
    };

    // Log start (unless quiet)
    if (!cli_opts.quiet) {
        printStderr("Verifying content:\n  Old: {s}\n  New: {s}\n", .{ old_file, new_file });
    }

    var verifier = lib.StreamingContentVerifier.init(allocator);
    defer verifier.deinit();

    // Output buffer
    var json_buf = std.ArrayListUnmanaged(u8){};
    defer json_buf.deinit(allocator);
    const writer = json_buf.writer(allocator);

    if (cli_opts.verify_file) |file_name| {
        // Verify specific file
        if (!cli_opts.quiet) {
            printStderr("Verifying file: {s}\n", .{file_name});
        }

        const result = verifier.verifyFileContent(old_file, new_file, file_name) catch |err| {
            printStderr("Error: Verification failed: {}\n", .{err});
            std.process.exit(3);
        };

        // Output JSON
        writer.writeAll("{\n") catch {};
        writeJsonStringField(writer, "  ", "file", file_name, false);
        writeJsonBoolField(writer, "  ", "matches", result.matches, false);
        writeJsonField(writer, "  ", "bytesCompared", result.bytes_compared, false);
        if (result.first_diff_offset) |offset| {
            writeJsonField(writer, "  ", "firstDiffOffset", offset, false);
        } else {
            writer.writeAll("  \"firstDiffOffset\": null,\n") catch {};
        }
        writeJsonField(writer, "  ", "oldSize", result.old_size, false);
        writeJsonField(writer, "  ", "newSize", result.new_size, true);
        writer.writeAll("}\n") catch {};
    } else if (cli_opts.verify_all) {
        // Verify all files with matching CRC32
        if (!cli_opts.quiet) {
            writeStderr("Verifying all files with matching CRC32...\n");
        }

        var result = verifier.verifyAllMatchingCrc(old_file, new_file) catch |err| {
            printStderr("Error: Verification failed: {}\n", .{err});
            std.process.exit(3);
        };
        defer result.deinit();

        // Output JSON
        writer.writeAll("{\n") catch {};
        writeJsonField(writer, "  ", "totalFiles", result.total_files, false);
        writeJsonField(writer, "  ", "matchingFiles", result.matching_files, false);
        writeJsonField(writer, "  ", "differingFiles", result.differing_files, false);
        writeJsonField(writer, "  ", "failedFiles", result.failed_files, false);

        writer.writeAll("  \"differingPaths\": [\n") catch {};
        for (result.differing_paths, 0..) |path, i| {
            writer.writeAll("    \"") catch {};
            writer.writeAll(path) catch {};
            writer.writeAll("\"") catch {};
            if (i < result.differing_paths.len - 1) {
                writer.writeAll(",\n") catch {};
            } else {
                writer.writeAll("\n") catch {};
            }
        }
        writer.writeAll("  ]\n") catch {};
        writer.writeAll("}\n") catch {};
    } else {
        writeStderr("Error: Specify --file <name> or --all for verification\n\n");
        printUsage(false);
        std.process.exit(1);
    }

    // Write to stdout
    const stdout = getStdoutFile();
    _ = stdout.writeAll(json_buf.items) catch {
        writeStderr("Error: Failed to write output\n");
        std.process.exit(3);
    };

    // Log completion (unless quiet)
    if (!cli_opts.quiet) {
        writeStderr("Verification complete.\n");
    }
}

fn writeJsonField(writer: anytype, indent: []const u8, name: []const u8, value: anytype, is_last: bool) void {
    const T = @TypeOf(value);
    if (T == i64) {
        writer.print("{s}\"{s}\": {d}", .{ indent, name, value }) catch {};
    } else {
        writer.print("{s}\"{s}\": {d}", .{ indent, name, value }) catch {};
    }
    if (is_last) {
        writer.writeAll("\n") catch {};
    } else {
        writer.writeAll(",\n") catch {};
    }
}

fn writeJsonStringField(writer: anytype, indent: []const u8, name: []const u8, value: []const u8, is_last: bool) void {
    writer.print("{s}\"{s}\": \"{s}\"", .{ indent, name, value }) catch {};
    if (is_last) {
        writer.writeAll("\n") catch {};
    } else {
        writer.writeAll(",\n") catch {};
    }
}

fn writeJsonBoolField(writer: anytype, indent: []const u8, name: []const u8, value: bool, is_last: bool) void {
    writer.print("{s}\"{s}\": {s}", .{ indent, name, if (value) "true" else "false" }) catch {};
    if (is_last) {
        writer.writeAll("\n") catch {};
    } else {
        writer.writeAll(",\n") catch {};
    }
}

fn parseArgs(allocator: std.mem.Allocator) !CliOptions {
    var opts = CliOptions{};

    // Use cross-platform argument iterator
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip program name
    _ = args.skip();

    var positional_count: u32 = 0;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "compare")) {
            opts.command = .compare;
        } else if (std.mem.eql(u8, arg, "verify")) {
            opts.command = .verify;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            opts.show_help = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            opts.show_version = true;
        } else if (std.mem.eql(u8, arg, "--compact") or std.mem.eql(u8, arg, "-c")) {
            opts.compact = true;
        } else if (std.mem.eql(u8, arg, "--pretty") or std.mem.eql(u8, arg, "-p")) {
            opts.compact = false;
        } else if (std.mem.eql(u8, arg, "--skip-dex")) {
            opts.skip_dex = true;
        } else if (std.mem.eql(u8, arg, "--skip-cert")) {
            opts.skip_cert = true;
        } else if (std.mem.eql(u8, arg, "--fast")) {
            opts.skip_dex = true;
            opts.skip_cert = true;
        } else if (std.mem.eql(u8, arg, "--no-mmap")) {
            opts.use_mmap = false;
        } else if (std.mem.eql(u8, arg, "--streaming")) {
            opts.use_streaming = true;
        } else if (std.mem.eql(u8, arg, "--quiet") or std.mem.eql(u8, arg, "-q")) {
            opts.quiet = true;
        } else if (std.mem.eql(u8, arg, "--different-only") or std.mem.eql(u8, arg, "-d")) {
            opts.different_only = true;
        } else if (std.mem.eql(u8, arg, "--files-only") or std.mem.eql(u8, arg, "-f")) {
            opts.files_only = true;
        } else if (std.mem.eql(u8, arg, "--sort-by-diff") or std.mem.eql(u8, arg, "-s")) {
            opts.sort_by_diff = true;
        } else if (std.mem.eql(u8, arg, "--breakdown") or std.mem.eql(u8, arg, "-b")) {
            opts.breakdown = true;
        } else if (std.mem.eql(u8, arg, "--patch-size")) {
            opts.patch_size = true;
        } else if (std.mem.eql(u8, arg, "--added-only")) {
            opts.added_only = true;
        } else if (std.mem.eql(u8, arg, "--removed-only")) {
            opts.removed_only = true;
        } else if (std.mem.eql(u8, arg, "--modified-only")) {
            opts.modified_only = true;
        } else if (std.mem.eql(u8, arg, "--all")) {
            opts.verify_all = true;
        } else if (std.mem.eql(u8, arg, "--file")) {
            // Next arg is the file name to verify
            if (args.next()) |file| {
                opts.verify_file = file;
            } else {
                return error.MissingValue;
            }
        } else if (std.mem.eql(u8, arg, "--category")) {
            // Next arg is the category value
            if (args.next()) |cat| {
                opts.category = cat;
            } else {
                return error.MissingValue;
            }
        } else if (std.mem.eql(u8, arg, "--min-diff")) {
            // Next arg is the min difference value
            if (args.next()) |val| {
                opts.min_difference = std.fmt.parseInt(u64, val, 10) catch return error.InvalidValue;
            } else {
                return error.MissingValue;
            }
        } else if (std.mem.eql(u8, arg, "--limit")) {
            // Next arg is the limit value
            if (args.next()) |val| {
                opts.limit = std.fmt.parseInt(u32, val, 10) catch return error.InvalidValue;
            } else {
                return error.MissingValue;
            }
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.UnknownOption;
        } else {
            // Positional argument
            if (opts.command == .compare or opts.command == .verify) {
                if (positional_count == 0) {
                    opts.old_file = arg;
                } else if (positional_count == 1) {
                    opts.new_file = arg;
                } else {
                    return error.TooManyArguments;
                }
            } else {
                if (opts.file_path != null) {
                    return error.TooManyArguments;
                }
                opts.file_path = arg;
            }
            positional_count += 1;
        }
    }

    return opts;
}

fn printUsage(to_stdout: bool) void {
    const usage =
        \\APK Analyzer - Android Package Analysis Tool
        \\
        \\USAGE:
        \\  apk-analyzer <file.apk|file.aab> [OPTIONS]
        \\  apk-analyzer compare <old.apk> <new.apk> [OPTIONS]
        \\  apk-analyzer verify <old.apk> <new.apk> [OPTIONS]
        \\
        \\COMMANDS:
        \\  (default)           Analyze a single APK/AAB file
        \\  compare             Compare two APK files and show differences
        \\  verify              Verify actual file content between two APKs
        \\
        \\ARGUMENTS:
        \\  <file>              Path to APK or AAB file to analyze
        \\  <old.apk>           Path to old APK file (for compare/verify)
        \\  <new.apk>           Path to new APK file (for compare/verify)
        \\
        \\GENERAL OPTIONS:
        \\  -h, --help          Show this help message
        \\  -v, --version       Show version information
        \\  -c, --compact       Output compact JSON (no formatting)
        \\  -p, --pretty        Output pretty-printed JSON (default)
        \\  -q, --quiet         Suppress progress messages on stderr
        \\  --no-mmap           Disable memory-mapped I/O (use traditional file read)
        \\  --streaming         Use streaming analyzer for minimal memory footprint
        \\
        \\ANALYZE OPTIONS:
        \\  --skip-dex          Skip DEX file analysis (faster)
        \\  --skip-cert         Skip certificate extraction
        \\  --fast              Enable fast mode (skip DEX and certificate)
        \\
        \\COMPARE OPTIONS:
        \\  -d, --different-only  Only show files with differences
        \\  -f, --files-only      Don't show directory entries
        \\  -s, --sort-by-diff    Sort by size difference (largest first)
        \\  -b, --breakdown       Include category breakdown
        \\  --patch-size          Include estimated patch sizes for delta updates
        \\  --category <cat>      Filter by category (dex, native, resources, assets, other)
        \\  --added-only          Only show added files
        \\  --removed-only        Only show removed files
        \\  --modified-only       Only show modified files
        \\  --min-diff <bytes>    Filter by minimum absolute size difference
        \\  --limit <n>           Limit number of entries returned
        \\
        \\VERIFY OPTIONS:
        \\  --file <name>         Verify a specific file by path (e.g., classes.dex)
        \\  --all                 Verify all files with matching CRC32 (detect collisions)
        \\
        \\MEMORY OPTIMIZATION:
        \\  By default, both analyze and compare commands use memory-mapped I/O
        \\  for reduced memory usage. This is especially beneficial for large APKs:
        \\
        \\  --streaming   Uses streaming analyzer with sequential file processing.
        \\                Each file is decompressed, analyzed, then freed immediately.
        \\                Peak memory: O(largest single file) instead of O(total APK).
        \\                For 150MB APK: ~20-50MB vs ~150-300MB standard.
        \\
        \\  (default)     Uses mmap for on-demand page loading by the OS.
        \\                Good balance of performance and memory efficiency.
        \\
        \\  --no-mmap     Loads entire file into memory. Use only if mmap fails.
        \\
        \\OUTPUT:
        \\  JSON results are written to stdout.
        \\  Progress and error messages are written to stderr.
        \\
        \\EXIT CODES:
        \\  0  Success
        \\  1  Invalid arguments
        \\  2  File not found or read error
        \\  3  Analysis error (invalid APK/AAB)
        \\
        \\EXAMPLES:
        \\  apk-analyzer app.apk
        \\  apk-analyzer app.apk --streaming          # Minimal memory usage
        \\  apk-analyzer app.apk --compact > result.json
        \\  apk-analyzer app.aab --fast -q > result.json
        \\  apk-analyzer compare old.apk new.apk --breakdown
        \\  apk-analyzer compare v1.apk v2.apk -d -s > diff.json
        \\  apk-analyzer compare v1.apk v2.apk --category dex --added-only
        \\  apk-analyzer compare v1.apk v2.apk --min-diff 1000 --limit 50
        \\  apk-analyzer verify v1.apk v2.apk --file classes.dex
        \\  apk-analyzer verify v1.apk v2.apk --all
        \\
        \\For more information, visit: https://github.com/apollo-deploy/apk-analyzer
        \\
    ;

    if (to_stdout) {
        writeStdout(usage);
    } else {
        writeStderr(usage);
    }
}
