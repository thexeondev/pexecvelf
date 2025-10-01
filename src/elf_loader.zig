const std = @import("std");
const dis = @import("dis_x86_64");

const elf = std.elf;
const win32 = std.os.windows;

const Allocator = std.mem.Allocator;
const Disassembler = dis.Disassembler;

const syscall_insn_size = 2;
const page_size = 0x10000;

extern "kernel32" fn FlushInstructionCache(
    process: win32.HANDLE,
    base_address: win32.LPCVOID,
    size: win32.SIZE_T,
) callconv(.winapi) win32.BOOL;

pub fn open(gpa: Allocator, file_name: []const u8) !u64 {
    var allocated_pages: std.ArrayList(u64) = .empty;
    defer allocated_pages.deinit(gpa);

    const elf_file = try std.fs.cwd().openFile(file_name, .{ .mode = .read_only });
    var buffer: [1024]u8 = undefined;

    var elf_file_reader = elf_file.reader(&buffer);
    const elf_header = try elf.Header.read(&elf_file_reader.interface);

    std.log.debug("Loaded ELF file, entry point: 0x{X}", .{elf_header.entry});

    var headers = elf_header.iterateProgramHeaders(&elf_file_reader);
    while (headers.next()) |phdr| {
        const header = phdr orelse break;

        std.log.debug("HEADER: type: 0x{X}, offset: 0x{X}", .{ header.p_type, header.p_offset });

        if (header.p_type != elf.PT_LOAD) {
            std.log.warn("todo: unimplemented header type 0x{X} at offset 0x{X}", .{ header.p_type, header.p_offset });
            continue;
        }

        const pages_begin_addr = (std.math.divCeil(u64, header.p_vaddr, 0x10000) catch unreachable) * 0x10000;
        const pages_size = ((header.p_memsz + 0xFFFF) & ~@as(u64, 0xFFFF));

        for (0..pages_size / page_size) |i| {
            const page = pages_begin_addr + (i * page_size);

            if (std.mem.indexOfScalar(u64, allocated_pages.items, page) == null) {
                _ = try win32.VirtualAlloc(
                    @ptrFromInt(page),
                    page_size,
                    win32.MEM_RESERVE | win32.MEM_COMMIT,
                    win32.PAGE_EXECUTE_READWRITE,
                );

                try allocated_pages.append(gpa, page);
            }
        }

        try elf_file_reader.seekTo(header.p_offset);

        const buf = try gpa.alloc(u8, header.p_filesz);
        defer gpa.free(buf);

        try elf_file_reader.interface.readSliceAll(buf);

        if (header.p_flags & elf.SHT_PROGBITS != 0) {
            std.log.debug(
                "Program entry (0x{X}:0x{X}) is marked as executable.",
                .{ header.p_offset, header.p_vaddr },
            );

            const offset = getLoadEntryContentOffset(&elf_header, &header);
            breakSyscallInstructions(header.p_vaddr + offset, buf);
        }

        // Some sections may have 0 file size (just reserved memory), and WriteProcessMemory would crash on zero length. Truly a winapi moment.
        if (buf.len != 0) {
            const process = win32.GetCurrentProcess();
            _ = try win32.WriteProcessMemory(process, @ptrFromInt(header.p_vaddr), buf);
            _ = FlushInstructionCache(process, @ptrFromInt(header.p_vaddr), header.p_memsz);
        }
    } else |err| {
        std.log.err("iterateProgramHeaders failed: {}", .{err});
        return err;
    }

    return elf_header.entry;
}

// Replaces all 'syscall' instructions with 'ud2'
fn breakSyscallInstructions(vaddr: u64, buf: []u8) void {
    var disasm = Disassembler.init(buf);
    while (disasm.pos < buf.len) {
        const insn = disasm.next() catch {
            // Skip over the junk, if needed
            disasm.pos += 1;
            continue;
        } orelse break;

        if (insn.encoding.mnemonic == dis.Encoding.Mnemonic.syscall) {
            std.log.debug("found syscall at 0x{X}", .{vaddr + disasm.pos - syscall_insn_size});
            buf[disasm.pos - 1] = 0x0B; // [0F 05] (syscall) -> [0F 0B] (ud2)
        }
    }
}

fn getLoadEntryContentOffset(elf_header: *const elf.Header, header: *const elf.Elf64_Phdr) u64 {
    // Skip ELF header if this is the first entry
    if (header.p_offset == 0) {
        if (elf_header.shoff > elf_header.phoff) {
            return elf_header.shoff + (elf_header.shentsize * elf_header.shnum);
        } else {
            return elf_header.phoff + (elf_header.phentsize * elf_header.phnum);
        }
    } else return header.p_offset;
}
