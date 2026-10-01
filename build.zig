const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Build optimization mode") orelse .ReleaseSmall;
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .cpu_model = .baseline,
            .os_tag = .windows,
        },
    });

    const tpgate = b.addLibrary(.{
        .name = "tpgate",
        .linkage = .dynamic,
        .win32_module_definition = b.path("tpgate.def"),
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(tpgate);
}
