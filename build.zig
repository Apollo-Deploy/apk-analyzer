const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Export the library module for consumers
    const apk_module = b.addModule("apk-analyzer", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Library artifact (for static linking)
    const lib = b.addLibrary(.{
        .name = "apk-analyzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    // ========================================================================
    // CLI Executable
    // ========================================================================

    const cli_exe = b.addExecutable(.{
        .name = "apk-analyzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "apk-analyzer",
                    .module = apk_module,
                },
            },
        }),
    });
    b.installArtifact(cli_exe);

    // Run step for CLI
    const run_cmd = b.addRunArtifact(cli_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the CLI tool");
    run_step.dependOn(&run_cmd.step);

    // ========================================================================
    // Cross-compilation targets for prebuilt binaries
    // ========================================================================

    const cross_targets = [_]struct {
        name: []const u8,
        target: std.Target.Query,
    }{
        .{ .name = "x86_64-linux", .target = .{ .cpu_arch = .x86_64, .os_tag = .linux } },
        .{ .name = "aarch64-linux", .target = .{ .cpu_arch = .aarch64, .os_tag = .linux } },
        .{ .name = "x86_64-macos", .target = .{ .cpu_arch = .x86_64, .os_tag = .macos } },
        .{ .name = "aarch64-macos", .target = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        .{ .name = "x86_64-windows", .target = .{ .cpu_arch = .x86_64, .os_tag = .windows } },
    };

    const release_step = b.step("release", "Build release binaries for all platforms");

    for (cross_targets) |ct| {
        const resolved_target = b.resolveTargetQuery(ct.target);

        // Create a module for this target
        const cross_apk_module = b.addModule(ct.name, .{
            .root_source_file = b.path("src/lib.zig"),
            .target = resolved_target,
            .optimize = .ReleaseFast,
        });

        const release_exe = b.addExecutable(.{
            .name = "apk-analyzer",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/cli/main.zig"),
                .target = resolved_target,
                .optimize = .ReleaseFast,
                .imports = &.{
                    .{
                        .name = "apk-analyzer",
                        .module = cross_apk_module,
                    },
                },
            }),
        });

        // Install to bin/<target>/apk-analyzer
        const install = b.addInstallArtifact(release_exe, .{
            .dest_dir = .{ .override = .{ .custom = ct.name } },
        });
        release_step.dependOn(&install.step);
    }

    // ========================================================================
    // Tests
    // ========================================================================

    // Main library tests from src/lib.zig (includes all module tests)
    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // Core types tests (standalone, no external deps)
    const core_types_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/types.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_core_types_tests = b.addRunArtifact(core_types_tests);

    // Core errors tests (standalone, no external deps)
    const core_errors_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/errors.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_core_errors_tests = b.addRunArtifact(core_errors_tests);

    // Output JSON tests (standalone)
    const output_json_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/output/json.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_output_json_tests = b.addRunArtifact(output_json_tests);

    // Analysis options tests (standalone)
    const analysis_options_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/analysis/options.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_analysis_options_tests = b.addRunArtifact(analysis_options_tests);

    // Perf buffer pool tests (standalone)
    const perf_buffer_pool_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/perf/buffer_pool.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_perf_buffer_pool_tests = b.addRunArtifact(perf_buffer_pool_tests);

    // Additional unit tests from tests/unit/
    const dex_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/dex_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "dex",
                    .module = b.createModule(.{
                        .root_source_file = b.path("src/parsers/dex.zig"),
                        .target = target,
                        .optimize = optimize,
                    }),
                },
            },
        }),
    });
    const run_dex_unit_tests = b.addRunArtifact(dex_unit_tests);

    const certificate_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/certificate_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "certificate",
                    .module = b.createModule(.{
                        .root_source_file = b.path("src/parsers/certificate.zig"),
                        .target = target,
                        .optimize = optimize,
                    }),
                },
            },
        }),
    });
    const run_certificate_unit_tests = b.addRunArtifact(certificate_unit_tests);

    const axml_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/axml_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "apk-analyzer",
                    .module = apk_module,
                },
            },
        }),
    });
    const run_axml_unit_tests = b.addRunArtifact(axml_unit_tests);

    const pb_manifest_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/pb_manifest_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "pb_manifest",
                    .module = b.createModule(.{
                        .root_source_file = b.path("src/parsers/pb_manifest.zig"),
                        .target = target,
                        .optimize = optimize,
                    }),
                },
            },
        }),
    });
    const run_pb_manifest_unit_tests = b.addRunArtifact(pb_manifest_unit_tests);

    const result_serialization_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/result_serialization_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "apk-analyzer",
                    .module = apk_module,
                },
            },
        }),
    });
    const run_result_serialization_tests = b.addRunArtifact(result_serialization_tests);

    const zip64_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/unit/zip64_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "zip",
                    .module = b.createModule(.{
                        .root_source_file = b.path("src/parsers/zip.zig"),
                        .target = target,
                        .optimize = optimize,
                    }),
                },
            },
        }),
    });
    const run_zip64_unit_tests = b.addRunArtifact(zip64_unit_tests);

    // Property-based (fuzz) tests
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/property/fuzz_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "apk-analyzer",
                    .module = apk_module,
                },
            },
        }),
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    // Performance benchmark tests
    const benchmark_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/performance/benchmark_test.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{
                    .name = "apk-analyzer",
                    .module = b.addModule("apk-analyzer-bench", .{
                        .root_source_file = b.path("src/lib.zig"),
                        .target = target,
                        .optimize = .ReleaseFast,
                    }),
                },
            },
        }),
    });
    const run_benchmark_tests = b.addRunArtifact(benchmark_tests);

    // Main test step - runs all tests
    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_core_types_tests.step);
    test_step.dependOn(&run_core_errors_tests.step);
    test_step.dependOn(&run_output_json_tests.step);
    test_step.dependOn(&run_analysis_options_tests.step);
    test_step.dependOn(&run_perf_buffer_pool_tests.step);
    test_step.dependOn(&run_dex_unit_tests.step);
    test_step.dependOn(&run_certificate_unit_tests.step);
    test_step.dependOn(&run_axml_unit_tests.step);
    test_step.dependOn(&run_pb_manifest_unit_tests.step);
    test_step.dependOn(&run_result_serialization_tests.step);
    test_step.dependOn(&run_zip64_unit_tests.step);
    test_step.dependOn(&run_fuzz_tests.step);

    // Quick test step - runs only core module tests
    const test_quick_step = b.step("test-quick", "Run quick module tests");
    test_quick_step.dependOn(&run_lib_tests.step);
    test_quick_step.dependOn(&run_core_types_tests.step);
    test_quick_step.dependOn(&run_core_errors_tests.step);
    test_quick_step.dependOn(&run_output_json_tests.step);

    // Separate benchmark step
    const benchmark_step = b.step("benchmark", "Run performance benchmarks");
    benchmark_step.dependOn(&run_benchmark_tests.step);
}
