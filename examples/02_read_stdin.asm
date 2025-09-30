format ELF64 executable

STDIN equ 0
STDOUT equ 1

segment readable executable
entry start
start:
  mov rax, 0 ; read
  mov rdi, STDIN
  mov rsi, buf
  mov rdx, buf_len
  syscall
  mov rdx, rax

  mov rax, 1 ; write
  mov rdi, STDOUT
  mov rsi, buf
  syscall

  mov rax, 60 ; exit
  mov rdi, 0
  syscall

segment readable writeable
  buf rb 1024
  buf_len = $ - buf
