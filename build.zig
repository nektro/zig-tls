const std = @import("std");
const deps = @import("./deps.zig");

pub fn build(b: *std.build.Builder) void {
    b.prominent_compile_errors = true;

    const target = b.standardTargetOptions(.{});

    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zig-tls", "main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    deps.addAllTo(exe);
    exe.linkLibC();
    exe.install();

    const tests = b.addTest("main.zig");
    tests.setTarget(target);
    tests.setBuildMode(mode);
    deps.addAllTo(tests);
    tests.linkLibC();

    const step = b.step("test", "Run unit tests");
    step.dependOn(&tests.step);
}
