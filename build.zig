const std = @import("std");

const Config = struct {
    blocked: []const []const u8,
    shims: []const [:0]const u8,
    dumps: struct {
        text: bool = false,
        sections: bool = false,
        imports: bool = false,
    },
};
const config: Config = @import("config.zon");

pub fn build(b: *std.Build) void {
    const optimize = b.option(std.builtin.Optimize, "optimize", "Build optimization mode") orelse .small;
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .cpu_model = .baseline,
            .os_tag = .windows,
        },
    });

    const options = b.addOptions();
    options.addOption([]const []const u8, "blocked", config.blocked);
    options.addOption([]const [:0]const u8, "shims", config.shims);
    options.addOption(bool, "dump_text", config.dumps.text);
    options.addOption(bool, "dump_sections", config.dumps.sections);
    options.addOption(bool, "dump_imports", config.dumps.imports);

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
    tpgate.root_module.addOptions("build_options", options);
    b.installArtifact(tpgate);

    const test_step = b.step("test", "Run native tests");
    inline for (.{ "dumps", "restore", "recipe", "fragments", "hooks" }) |name| {
        const module = b.createModule(.{
            .root_source_file = b.path("src/" ++ name ++ ".zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        });
        module.addOptions("build_options", options);
        const tests = b.addTest(.{ .name = name, .root_module = module });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}
