const std = @import("std");
const win32 = std.os.windows;

const Emulator = @This();

const max_fd: usize = 1023;
fd_table: [max_fd + 1]?win32.HANDLE = @splat(null),

const NR = enum(u64) {
    read = 0,
    write = 1,
    close = 3,
    socket = 41,
    accept = 43,
    bind = 49,
    listen = 50,
    setsockopt = 54,
    exit = 60,
    clock_gettime = 228,
};

const Errno = enum(i64) {
    EBADF = -9, // Bad file descriptor
    EAGAIN = -11, // Resource temporarily unavailable
    EINVAL = -22, // Invalid argument
    EMFILE = -24, // Too many open files
    ENOSYS = -38, // Function not implemented
    EADDRINUSE = -98, // Address in use

    pub inline fn unsigned(errno: Errno) u64 {
        return @bitCast(@intFromEnum(errno));
    }
};

const STDIN_FILENO: usize = 0;
const STDOUT_FILENO: usize = 1;
const STDERR_FILENO: usize = 2;

pub fn init(emu: *Emulator) void {
    emu.fd_table[STDIN_FILENO] = win32.GetStdHandle(win32.STD_INPUT_HANDLE) catch unreachable;
    emu.fd_table[STDOUT_FILENO] = win32.GetStdHandle(win32.STD_OUTPUT_HANDLE) catch unreachable;
    emu.fd_table[STDERR_FILENO] = win32.GetStdHandle(win32.STD_ERROR_HANDLE) catch unreachable;
}

pub fn onSyscall(emu: *Emulator, context: *win32.CONTEXT) void {
    const syscall_nr = std.meta.intToEnum(NR, context.Rax) catch {
        std.log.err("unhandled syscall number: {}", .{context.Rax});
        win32.kernel32.ExitProcess(3);
    };

    context.Rax = switch (syscall_nr) {
        .read => syscall(sysRead, emu, context),
        .write => syscall(sysWrite, emu, context),
        .close => syscall(sysClose, emu, context),
        .socket => syscall(sysSocket, emu, context),
        .accept => syscall(sysAccept, emu, context),
        .bind => syscall(sysBind, emu, context),
        .listen => syscall(sysListen, emu, context),
        .setsockopt => syscall(sysSetsockopt, emu, context),
        .exit => syscall(sysExit, emu, context),
        .clock_gettime => syscall(sysClockGettime, emu, context),
    };
}

inline fn syscall(comptime impl: anytype, emu: *Emulator, context: *win32.CONTEXT) @typeInfo(@TypeOf(impl)).@"fn".return_type.? {
    return switch (@typeInfo(@TypeOf(impl)).@"fn".params.len - 1) {
        0 => impl(emu),
        1 => impl(emu, context.Rdi),
        2 => impl(emu, context.Rdi, context.Rsi),
        3 => impl(emu, context.Rdi, context.Rsi, context.Rdx),
        4 => impl(emu, context.Rdi, context.Rsi, context.Rdx, context.R10),
        5 => impl(emu, context.Rdi, context.Rsi, context.Rdx, context.R10, context.R8),
        6 => impl(emu, context.Rdi, context.Rsi, context.Rdx, context.R10, context.R8, context.R9),
        else => |num| @compileError("Invalid number of arguments for syscall (" ++ num ++ ")"),
    };
}

fn sysExit(_: *Emulator, error_code: u64) noreturn {
    std.log.info("exit(0x{X})", .{error_code});
    win32.kernel32.ExitProcess(@truncate(error_code));
}

fn sysWrite(emu: *Emulator, fd: u64, buf: u64, count: u64) u64 {
    std.log.info("write(0x{X}, 0x{X}, 0x{X})", .{ fd, buf, count });
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();

    var written: win32.DWORD = 0;
    if (win32.kernel32.WriteFile(handle, @ptrFromInt(buf), @truncate(count), &written, null) == 0) {
        const last_error = win32.GetLastError();
        std.log.warn("WriteFile call failed. LastError: {s} ({})", .{ @tagName(last_error), last_error });
        return Errno.EAGAIN.unsigned();
    } else {
        return written;
    }
}

fn sysRead(emu: *Emulator, fd: u64, buf: u64, count: u64) u64 {
    std.log.info("read(0x{X}, 0x{X}, 0x{X})", .{ fd, buf, count });
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();

    var nread: win32.DWORD = 0;
    if (win32.kernel32.ReadFile(handle, @ptrFromInt(buf), @truncate(count), &nread, null) == 0) {
        const last_error = win32.GetLastError();
        std.log.warn("ReadFile call failed. LastError: {s} ({})", .{ @tagName(last_error), last_error });
        return Errno.EAGAIN.unsigned();
    } else {
        return nread;
    }
}

fn sysClose(emu: *Emulator, fd: u64) u64 {
    std.log.info("close(0x{X})", .{fd});
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();
    emu.fd_table[fd] = null;

    _ = win32.ntdll.NtClose(handle);
    return 0;
}

fn getFreeFD(emu: *Emulator) ?usize {
    for (emu.fd_table, 0..) |fd_option, i| {
        if (fd_option == null) return i;
    } else return null;
}

fn getHandleByFD(emu: *Emulator, fd: u64) ?win32.HANDLE {
    return if (fd <= max_fd) emu.fd_table[fd] else null;
}

fn sysSocket(emu: *Emulator, family: u64, socket_type: u64, protocol: u64) u64 {
    std.log.info("socket(0x{X}, 0x{X}, 0x{X})", .{ family, socket_type, protocol });

    const fd = emu.getFreeFD() orelse return Errno.EMFILE.unsigned();
    const handle = win32.ws2_32.WSASocketA(@intCast(family), @intCast(socket_type), @intCast(protocol), null, 0, 0);

    if (handle == win32.ws2_32.INVALID_SOCKET) return Errno.EAGAIN.unsigned();

    emu.fd_table[fd] = handle;
    return @intCast(fd);
}

fn sysAccept(emu: *Emulator, fd: u64, addr: u64, addrlen: u64) u64 {
    std.log.info("accept(0x{X}, 0x{X}, 0x{X})", .{ fd, addr, addrlen });
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();
    const next_fd = emu.getFreeFD() orelse return Errno.EMFILE.unsigned();

    const result = win32.ws2_32.accept(@ptrCast(handle), @ptrFromInt(addr), @ptrFromInt(addrlen));
    if (result == win32.ws2_32.INVALID_SOCKET) {
        const last_error = win32.GetLastError();
        std.log.warn("ws2_32::accept failed, LastError: {s} ({})", .{ @tagName(last_error), last_error });
        return Errno.EAGAIN.unsigned();
    }

    emu.fd_table[next_fd] = @ptrCast(result);
    return next_fd;
}

const WSAEINVAL: i32 = 10022;
const WSAEADDRINUSE: i32 = 10048;

fn sysBind(emu: *Emulator, fd: u64, addr: u64, addrlen: u64) u64 {
    std.log.info("bind(0x{X}, 0x{X}, 0x{X})", .{ fd, addr, addrlen });
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();

    const result = win32.ws2_32.bind(@ptrCast(handle), @ptrFromInt(addr), @intCast(addrlen));
    if (result == 0) return 0;

    return switch (result) {
        WSAEINVAL => Errno.EINVAL,
        WSAEADDRINUSE => Errno.EADDRINUSE,
        else => blk: {
            std.log.warn("ws2_32::bind failed with code: {}", .{result});
            break :blk Errno.EAGAIN;
        },
    }.unsigned();
}

fn sysListen(emu: *Emulator, fd: u64, backlog: u64) u64 {
    std.log.info("listen(0x{X}, 0x{X})", .{ fd, backlog });
    const handle = emu.getHandleByFD(fd) orelse return Errno.EBADF.unsigned();

    const result = win32.ws2_32.listen(@ptrCast(handle), @intCast(backlog));
    if (result == 0) return 0;

    return Errno.EINVAL.unsigned();
}

fn sysSetsockopt(emu: *Emulator, fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) u64 {
    std.log.info("setsockopt(0x{X}, 0x{X}, 0x{X}, 0x{X}, 0x{X})", .{ fd, level, optname, optval, optlen });
    _ = emu;

    // TODO: Implement this. The target currently uses it only for SO_REUSEADDR, so we're skipping it for now.
    return Errno.ENOSYS.unsigned();
}

const Timespec = extern struct {
    tv_sec: u64,
    tv_nsec: u64,
};

fn sysClockGettime(emu: *Emulator, which_clock: u64, tp: u64) u64 {
    std.log.info("clock_gettime(0x{X}, 0x{X})", .{ which_clock, tp });
    _ = emu;

    const nano_ts = std.time.nanoTimestamp();
    const timespec: *Timespec = @ptrFromInt(tp);

    timespec.tv_sec = @intCast(@divFloor(nano_ts, std.time.ns_per_s));
    timespec.tv_nsec = @intCast(@mod(nano_ts, std.time.ns_per_s));

    return 0;
}
