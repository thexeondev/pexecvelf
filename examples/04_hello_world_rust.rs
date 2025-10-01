// rustc 04_hello_world_rust.rs --emit=obj -Cpanic="abort" -Copt-level=z && ld -o 04_hello_world_rust 04_hello_world_rust.o

#![no_std]
#![no_main]

use core::arch::asm;

type Errno = i64;

#[no_mangle]
pub extern "C" fn _start() {
    let result = write(1, b"Hello, World!\n");
    exit(if result.is_err() { 1 } else { 0 });
}

fn write(fd: u32, buf: &[u8]) -> Result<usize, Errno> {
    let mut res: i64;

    unsafe { asm!(
        "mov rdi, {fd:r}",
        "mov rsi, {buf_ptr}",
        "mov rdx, {buf_len}",
        "mov rax, 1",
        "syscall",
        "mov {result}, rax",
        fd = in(reg) fd,
        buf_ptr = in(reg) buf.as_ptr(),
        buf_len = in(reg) buf.len(),
        result = out(reg) res,
    ) };

    if res < 0 { Err(res) } else { Ok(res as usize) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(1)
}

fn exit(code: u64) -> ! {
    unsafe { asm!(
            "mov rax, 60",
            "mov rdi, {code}",
            "syscall",
            code = in(reg) code
        ) 
    }

    loop {}
}
