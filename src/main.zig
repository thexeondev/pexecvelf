const std = @import("std");

const elf_loader = @import("elf_loader.zig");
const Emulator = @import("Emulator.zig");
const win32 = std.os.windows;

pub const std_options: std.Options = .{
    // .log_level = .warn,
};

var emulator_instance: Emulator = .{};

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}){};
    const gpa = debug_allocator.allocator();

    const args = try std.process.argsAlloc(gpa);
    if (args.len < 2) {
        std.log.err("USAGE: pexecvelf.exe [ELF_FILE]", .{});
        std.log.err("No ELF file provided. Exiting.", .{});
        return;
    }

    try win32.callWSAStartup(); // TODO: add a flag to skip WSA initialization?
    const entry_point = try elf_loader.open(gpa, args[1]);

    emulator_instance = .{};
    emulator_instance.init();

    _ = win32.kernel32.AddVectoredExceptionHandler(1, syscallInterceptor);

    // Just jump to the ELF entry point
    asm volatile (
        \\ jmpq *%rax
        :
        : [entry_point] "{rax}" (entry_point),
    );
}

const ud2_opcode = [2]u8{ 0x0F, 0x0B };

fn syscallInterceptor(ptrs: *win32.EXCEPTION_POINTERS) callconv(.winapi) c_long {
    const rip = ptrs.ContextRecord.Rip;
    std.log.debug("Intercepted an exception at rip: 0x{X}", .{rip});

    const opcode = @as([*]u8, @ptrFromInt(rip));
    if (std.mem.eql(u8, opcode[0..2], &ud2_opcode)) { // UD2 that we just placed. TODO: maybe keep track of placed ones to not rape some actual ud2?
        ptrs.ContextRecord.Rip += ud2_opcode.len; // skip UD2 that we've failed on
        emulator_instance.onSyscall(ptrs.ContextRecord);
        return -1;
    }

    return win32.EXCEPTION_CONTINUE_SEARCH;
}
