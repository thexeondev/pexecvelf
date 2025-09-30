const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zig_dis_x86_64 = b.dependency("zig_dis_x86_64", .{ .target = target, .optimize = optimize });
    const dis_x86_64 = zig_dis_x86_64.module("dis_x86_64");

    const root_module = b.addModule("pexecvelf", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    root_module.addImport("dis_x86_64", dis_x86_64);

    const exe = b.addExecutable(.{ .name = "pexecvelf", .root_module = root_module });
    b.installArtifact(exe);
}
