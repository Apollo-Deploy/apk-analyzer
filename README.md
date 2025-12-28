# APK Analyzer

A high-performance, zero-dependency Zig library and CLI tool for analyzing Android application packages (APK) and Android App Bundles (AAB).

## CLI Tool

The APK Analyzer is available as a standalone CLI tool with prebuilt binaries for all major platforms. **No Zig installation required.**

### Download Prebuilt Binaries

Download the appropriate binary for your platform from the [releases page](https://github.com/apollo-deploy/apk-analyzer/releases):

| Platform | Architecture | Download |
|----------|--------------|----------|
| Linux | x64 | `apk-analyzer-linux-x64.tar.gz` |
| Linux | ARM64 | `apk-analyzer-linux-arm64.tar.gz` |
| macOS | x64 (Intel) | `apk-analyzer-darwin-x64.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `apk-analyzer-darwin-arm64.tar.gz` |
| Windows | x64 | `apk-analyzer-win32-x64.zip` |

### CLI Usage

```bash
# Basic analysis (outputs JSON to stdout)
apk-analyzer app.apk

# Save output to file
apk-analyzer app.apk > result.json

# Compact JSON output (no formatting)
apk-analyzer app.apk --compact

# Fast mode (skip DEX and certificate analysis)
apk-analyzer app.apk --fast

# Quiet mode (suppress progress messages)
apk-analyzer app.apk --quiet > result.json

# Analyze Android App Bundle
apk-analyzer app.aab
```

### CLI Options

```
OPTIONS:
  -h, --help          Show help message
  -v, --version       Show version information
  -c, --compact       Output compact JSON (no formatting)
  -p, --pretty        Output pretty-printed JSON (default)
  -q, --quiet         Suppress progress messages on stderr
  --skip-dex          Skip DEX file analysis (faster)
  --skip-cert         Skip certificate extraction
  --fast              Enable fast mode (skip DEX and certificate)

EXIT CODES:
  0  Success
  1  Invalid arguments
  2  File not found or read error
  3  Analysis error (invalid APK/AAB)
```

### Node.js / TypeScript Integration

For Node.js applications, use the npm wrapper:

```bash
npm install @apollo-deploy/apk-analyzer
```

```typescript
import { analyzeApk } from '@apollo-deploy/apk-analyzer';

const result = await analyzeApk('/path/to/app.apk');
console.log(`Package: ${result.packageId}`);
console.log(`Version: ${result.versionName} (${result.versionCode})`);
console.log(`Size: ${result.compressedSize} bytes`);

// With options
const fastResult = await analyzeApk('/path/to/app.apk', {
  fast: true,      // Skip DEX and certificate analysis
  timeout: 30000,  // 30 second timeout
});
```

---

## Zig Library

For Zig applications, the library can be used directly without the CLI.

## Features

- **Zero Dependencies**: Pure Zig implementation with no external tools required
- **High Performance**: Sub-500ms analysis for typical 50MB APKs
- **Low Memory**: Uses arena allocators for efficient memory management
- **Modular Architecture**: Clean separation of concerns with pluggable components
- **Comprehensive Analysis**:
  - Package metadata (name, version, SDK versions)
  - Permissions and features extraction
  - DEX file analysis (method counts, multidex detection)
  - Certificate/signing information
  - Native library detection
  - File size breakdown by category
- **Multiple Formats**: Supports both APK and AAB files
- **JSON Output**: Reflection-based serialization with camelCase field names
- **Analysis Tools**: APK comparison, download size estimation, feature analysis

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .apk_analyzer = .{
        .url = "https://github.com/apollo-deploy/apk-analyzer/archive/v0.2.0.tar.gz",
        .hash = "...",
    },
    // Or for local development in monorepo:
    // .apk_analyzer = .{ .path = "../packages/apk-analyzer" },
},
```

Add to your `build.zig`:

```zig
const apk_analyzer = b.dependency("apk_analyzer", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("apk-analyzer", apk_analyzer.module("apk-analyzer"));
```

## Architecture

The library follows a clean modular architecture:

```
src/
├── lib.zig              # Main entry point with re-exports
├── core/                # Domain types, errors, utilities
│   ├── mod.zig          # Core module exports
│   ├── types.zig        # Domain types (single source of truth)
│   └── errors.zig       # Error types and diagnostics
├── analysis/            # Orchestration layer
│   ├── mod.zig          # Analysis module exports
│   ├── analyzer.zig     # Main Analyzer implementation
│   ├── lazy_analyzer.zig # On-demand parsing analyzer
│   └── options.zig      # Configuration options with presets
├── parsers/             # Format-specific parsers
│   ├── mod.zig          # Parser module exports
│   ├── zip.zig          # ZIP archive parser
│   ├── axml.zig         # Android Binary XML parser
│   ├── dex.zig          # DEX file analyzer
│   ├── certificate.zig  # Certificate parser
│   ├── arsc.zig         # Resource table parser
│   ├── protobuf.zig     # Protocol Buffers parser
│   └── pb_manifest.zig  # AAB manifest parser
├── tools/               # Analysis tools
│   ├── mod.zig          # Tools module exports
│   ├── compare.zig      # APK comparator
│   ├── download_size.zig # Download size estimator
│   └── features.zig     # Feature analyzer
├── output/              # Serialization
│   ├── mod.zig          # Output module exports
│   └── json.zig         # Reflection-based JSON serializer
└── perf/                # Performance utilities
    ├── mod.zig          # Perf module exports
    └── buffer_pool.zig  # Buffer pool and SIMD utilities
```

### Design Principles

- **Single Source of Truth**: Core types in `core/types.zig` are used everywhere
- **No Type Duplication**: Parsers return domain types directly
- **Reflection-Based Serialization**: JSON output uses comptime reflection
- **Clear Module Boundaries**: Explicit imports between modules
- **Unified Error Handling**: `AnalysisError` and `Diagnostic` types

## Quick Start

### Basic Analysis

```zig
const apk = @import("apk-analyzer");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create analyzer with default options
    var analyzer = apk.Analyzer.init(allocator, .{});

    // Read APK file
    const data = try std.fs.cwd().readFileAlloc(allocator, "app.apk", 100 * 1024 * 1024);
    defer allocator.free(data);

    // Analyze the APK
    var result = try analyzer.analyze(data);
    defer result.deinit();

    // Access metadata
    std.debug.print("Package: {s}\n", .{result.metadata.package_id});
    std.debug.print("Version: {s} ({d})\n", .{result.metadata.version_name, result.metadata.version_code});
    std.debug.print("Min SDK: {}\n", .{result.metadata.min_sdk_version});
    
    // Check DEX info
    if (result.dex_info) |dex| {
        std.debug.print("Total methods: {}\n", .{dex.total_methods});
        std.debug.print("Is multidex: {}\n", .{dex.is_multidex});
    }

    // Serialize to JSON
    const stdout = std.io.getStdOut().writer();
    try apk.output.json.serialize(&result, stdout, .{});
}
```

### Convenience Functions

```zig
const apk = @import("apk-analyzer");

// Quick analysis (skips DEX and certificate for speed)
var result = try apk.analyzeQuick(allocator, data);
defer result.deinit();

// Full analysis (all features enabled)
var result = try apk.analyzeFull(allocator, data);
defer result.deinit();

// Detect artifact type
const artifact_type = apk.detectArtifactType("app.aab", data);
std.debug.print("Type: {s}\n", .{artifact_type.toString()});
```

## API Reference

### Analyzer

The main analyzer interface for APK and AAB files.

```zig
const apk = @import("apk-analyzer");

// Create analyzer with options
var analyzer = apk.Analyzer.init(allocator, .{
    .skip_dex_analysis = false,
    .skip_certificate = false,
    .max_memory = 100 * 1024 * 1024, // 100MB limit
    .streaming_mode = true,
    .lazy_parsing = false,
    .use_simd = true,
    .use_buffer_pool = true,
});

// Analyze from memory
var result = try analyzer.analyze(data);
defer result.deinit();

// Analyze from file path
var result = try analyzer.analyzeFile("path/to/app.apk");
defer result.deinit();
```

### Options

Configuration options with preset configurations:

```zig
pub const Options = struct {
    /// Skip DEX analysis for faster parsing
    skip_dex_analysis: bool = false,
    
    /// Skip certificate extraction
    skip_certificate: bool = false,
    
    /// Maximum memory budget in bytes (0 = unlimited)
    max_memory: usize = 0,
    
    /// Enable streaming mode for large files
    streaming_mode: bool = true,
    
    /// Enable lazy parsing (parse components on-demand)
    lazy_parsing: bool = false,
    
    /// Enable SIMD optimizations
    use_simd: bool = true,
    
    /// Enable buffer pooling for decompression
    use_buffer_pool: bool = true,
};
```

**Preset Configurations:**

```zig
// Fast mode - skip expensive operations
var analyzer = apk.Analyzer.init(allocator, apk.Options.fast);

// Full analysis mode - all features enabled
var analyzer = apk.Analyzer.init(allocator, apk.Options.full);

// Memory-constrained mode - 50MB limit with streaming
var analyzer = apk.Analyzer.init(allocator, apk.Options.memory_constrained);
```

| Preset | Description |
|--------|-------------|
| `Options.fast` | Skips DEX and certificate analysis, enables lazy parsing |
| `Options.full` | Full analysis with all features enabled |
| `Options.memory_constrained` | 50MB limit, streaming mode, lazy parsing |

### AnalysisResult

Complete analysis result structure:

```zig
pub const AnalysisResult = struct {
    artifact_type: ArtifactType,      // .apk or .aab
    metadata: Metadata,                // Package info, permissions, features
    size_breakdown: SizeBreakdown,     // Size by category
    compressed_size: u64,              // Total compressed size
    uncompressed_size: u64,            // Total uncompressed size
    certificate: ?CertificateInfo,     // Signing certificate (if available)
    dex_info: ?DexInfo,                // DEX analysis (if available)
    native_libs: NativeLibraries,      // Native library info
    split_configs: ?[]const SplitConfig, // AAB split configs
    diagnostics: []const Diagnostic,   // Warnings and errors
    
    pub fn deinit(self: *AnalysisResult) void;
    pub fn hasErrors(self: *const AnalysisResult) bool;
    pub fn hasWarnings(self: *const AnalysisResult) bool;
};
```

### Core Types

All domain types are defined in `core/types.zig`:

```zig
// Artifact type
pub const ArtifactType = enum { apk, aab };

// Metadata from AndroidManifest.xml
pub const Metadata = struct {
    package_id: []const u8,
    app_name: []const u8,
    version_code: u32,
    version_code_str: []const u8,
    version_name: []const u8,
    min_sdk_version: u32,
    target_sdk_version: ?u32,
    install_location: InstallLocation,
    permissions: []const Permission,
    features: []const Feature,
    is_debuggable: bool,
};

// Permission with optional SDK constraint
pub const Permission = struct {
    name: []const u8,
    max_sdk_version: ?u32 = null,
};

// Feature requirement
pub const Feature = struct {
    name: []const u8,
    required: bool = true,
};

// Size breakdown by category
pub const SizeBreakdown = struct {
    dex: CategorySize,
    resources: CategorySize,
    native: CategorySize,
    assets: CategorySize,
    other: CategorySize,
};

// Certificate information (raw fingerprints)
pub const CertificateInfo = struct {
    subject: []const u8,
    issuer: []const u8,
    serial_number: []const u8,
    not_before: i64,
    not_after: i64,
    fingerprint_md5: [16]u8,      // Raw bytes
    fingerprint_sha256: [32]u8,   // Raw bytes
    signature_algorithm: []const u8,
    public_key_algorithm: []const u8,
    public_key_size: u32,
    
    // Format fingerprints for display
    pub fn formatMd5Fingerprint(self: *const CertificateInfo, buf: []u8) []const u8;
    pub fn formatSha256Fingerprint(self: *const CertificateInfo, buf: []u8) []const u8;
};

// DEX analysis result
pub const DexInfo = struct {
    files: []const DexFileInfo,
    total_methods: u64,
    total_classes: u64,
    total_fields: u64,
    is_multidex: bool,
};

// Diagnostic warning or error
pub const Diagnostic = struct {
    code: DiagnosticCode,
    message: []const u8,
    severity: DiagnosticSeverity,
};
```

## Analysis Tools

### APK Comparator

Compares two APK files with enhanced options for filtering, breakdown analysis, and summary statistics:

```zig
const apk = @import("apk-analyzer");

var comparator = apk.ApkComparator.init(allocator);
defer comparator.deinit();

// Compare with options
var result = try comparator.compareFiles("old.apk", "new.apk", .{
    .different_only = true,       // Only show files with differences
    .files_only = false,          // Include directory entries
    .patch_size = true,           // Show estimated patch size
    .include_breakdown = true,    // Include category breakdown
    .sort_by_difference = true,   // Sort by absolute difference
    .category = "dex",            // Filter by category (dex, native, resources, assets, other)
    .min_difference = 1024,       // Minimum difference threshold
    .added_only = false,          // Only show added files
    .removed_only = false,        // Only show removed files
    .modified_only = false,       // Only show modified files
    .limit = 100,                 // Limit number of entries
});
defer result.deinit();

// Access totals
std.debug.print("Total: {} -> {} ({d} bytes)\n", .{
    result.old_total,
    result.new_total,
    result.total_difference,
});

// Access summary statistics
std.debug.print("Files: {} old, {} new\n", .{
    result.summary.old_file_count,
    result.summary.new_file_count,
});
std.debug.print("Added: {}, Removed: {}, Modified: {}\n", .{
    result.summary.added_count,
    result.summary.removed_count,
    result.summary.modified_count,
});

// Largest changes
if (result.summary.largest_increase) |inc| {
    std.debug.print("Largest increase: {s} (+{d} bytes)\n", .{inc.path, inc.difference});
}
if (result.summary.largest_decrease) |dec| {
    std.debug.print("Largest decrease: {s} ({d} bytes)\n", .{dec.path, dec.difference});
}

// Category breakdown
if (result.breakdown) |breakdown| {
    for (breakdown) |bd| {
        std.debug.print("{s}: {} -> {} ({d})\n", .{
            bd.category.toString(),
            bd.old_size,
            bd.new_size,
            bd.difference,
        });
    }
}

// Individual entries
for (result.entries) |entry| {
    std.debug.print("{d} {d} {d} /{s} [{s}]\n", .{
        entry.old_size,
        entry.new_size,
        entry.difference,
        entry.path,
        @tagName(entry.status),
    });
}
```

**Comparison Options:**

| Option | Type | Description |
|--------|------|-------------|
| `different_only` | `bool` | Only show files with differences |
| `files_only` | `bool` | Don't print directory entries |
| `patch_size` | `bool` | Show estimated patch size |
| `include_breakdown` | `bool` | Include category breakdown |
| `sort_by_difference` | `bool` | Sort by absolute difference (descending) |
| `category` | `?[]const u8` | Filter by category: "dex", "native", "resources", "assets", "other" |
| `min_difference` | `?u64` | Minimum absolute difference threshold |
| `added_only` | `bool` | Only show added files |
| `removed_only` | `bool` | Only show removed files |
| `modified_only` | `bool` | Only show modified files |
| `limit` | `?u32` | Limit number of entries returned |

**Entry Status:**

| Status | Description |
|--------|-------------|
| `.modified` | File exists in both APKs with different sizes |
| `.added` | File only in new APK |
| `.removed` | File only in old APK |
| `.unchanged` | File unchanged between versions |

### Download Size Estimator

Estimates Play Store download size (Brotli compression):

```zig
const apk = @import("apk-analyzer");

var estimator = apk.DownloadSizeEstimator.init(allocator);
defer estimator.deinit();

const estimate = try estimator.estimateFile("app.apk");

std.debug.print("File size: {} bytes\n", .{estimate.file_size});
std.debug.print("Download size: {} bytes\n", .{estimate.download_size});
std.debug.print("Compression ratio: {d:.1}%\n", .{estimate.compression_ratio * 100});

// Breakdown by component
std.debug.print("DEX: {} bytes\n", .{estimate.breakdown.dex});
std.debug.print("Native: {} bytes\n", .{estimate.breakdown.native});
std.debug.print("Resources: {} bytes\n", .{estimate.breakdown.resources});
```

### Feature Analyzer

Analyzes features that trigger Play Store filtering:

```zig
const apk = @import("apk-analyzer");

var analyzer = apk.FeatureAnalyzer.init(allocator);
defer analyzer.deinit();

var result = try analyzer.analyzeFile("app.apk", .{
    .include_not_required = true,
});
defer result.deinit();

for (result.features) |feature| {
    std.debug.print("{s}", .{feature.name});
    if (!feature.required) std.debug.print(" not-required", .{});
    std.debug.print("\n", .{});
    
    if (feature.implied_by) |permission| {
        std.debug.print("  implied: requested {s} permission\n", .{permission});
    }
}
```

## Performance Utilities

### BufferPool

Heap-backed buffer pool with ring-buffer strategy for efficient memory reuse:

```zig
const apk = @import("apk-analyzer");

// Initialize with allocator (required - heap-backed)
var pool = apk.BufferPool.init(allocator);
defer pool.deinit();

// Get buffers of different sizes
const small = pool.getSmall();   // 4KB
const medium = pool.getMedium(); // 64KB
const large = pool.getLarge();   // 1MB

// Use buffers...

// Release buffers back to pool
pool.releaseSmall(small);
pool.releaseMedium(medium);
pool.releaseLarge(large);
```

**Key Features:**
- Heap-backed allocation (requires `init(allocator)`)
- Ring-buffer strategy for buffer rotation
- Three size tiers: small (4KB), medium (64KB), large (1MB)
- Thread-safe design

## JSON Serialization

The library uses reflection-based JSON serialization:

```zig
const apk = @import("apk-analyzer");

var result = try analyzer.analyze(data);
defer result.deinit();

// Serialize to writer
const stdout = std.io.getStdOut().writer();
try apk.output.json.serialize(&result, stdout, .{
    .pretty = true,  // Pretty-print with indentation
});

// Or use the JSON view type for custom serialization
const json_view = try apk.AnalysisResultJson.fromResult(&result, allocator);
```

**Output Format:**
- camelCase field names
- Fingerprints formatted as colon-separated hex
- Enums serialized as strings
- Null values for optional fields

## Building and Testing

```bash
# Build the library
zig build

# Run all tests
zig build test

# Run quick tests (core modules only)
zig build test-quick

# Run performance benchmarks
zig build benchmark

# Build with optimizations
zig build -Doptimize=ReleaseFast
```

## Performance

| Operation | Time | Memory |
|-----------|------|--------|
| 50MB APK analysis | <500ms | <100MB |
| 100MB APK analysis | <1s | <150MB |
| ZIP parsing only | <50ms | <10MB |
| Manifest parsing | <10ms | <5MB |

## Error Handling

All operations return error unions with specific error types:

```zig
pub const AnalysisError = error{
    InvalidArchive,          // Not a valid ZIP archive
    UnsupportedFormat,       // Unsupported file format
    MissingManifest,         // AndroidManifest.xml not found
    InvalidManifest,         // Manifest parsing failed
    OutOfMemory,             // Memory allocation failed
    FileTooLarge,            // File exceeds size limits
    MemoryBudgetExceeded,    // Exceeds configured memory budget
};
```

**Graceful Degradation:**

```zig
var result = try analyzer.analyze(data);
defer result.deinit();

// Check for warnings
if (result.hasWarnings()) {
    for (result.diagnostics) |d| {
        std.debug.print("[{s}] {s}: {s}\n", .{
            d.severity.toString(),
            d.code.toString(),
            d.message,
        });
    }
}

// Optional components may be null if parsing failed
if (result.dex_info == null) {
    std.debug.print("DEX analysis unavailable\n", .{});
}
```

## Version

Current version: **0.2.0**

```zig
const apk = @import("apk-analyzer");
std.debug.print("Version: {s}\n", .{apk.version});
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `zig build test`
5. Submit a pull request

## Related Projects

- [Google APK Analyzer](https://android.googlesource.com/platform/tools/base/+/refs/heads/main/apkparser/analyzer/) - Reference implementation in Java
- [Apollo Deploy](https://github.com/apollo-deploy) - Mobile app deployment platform
