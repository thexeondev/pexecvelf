format ELF64 executable

segment readable executable
entry start
start:
  mov rax, 60
  mov rdi, 1
  syscall ; exit
