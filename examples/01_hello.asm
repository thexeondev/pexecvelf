format ELF64 executable

segment readable executable
entry start
start:
  mov rax, 1 ; write
  mov rdi, 1 ; stdout
  mov rsi, msg
  mov rdx, msg_len
  syscall

  mov rax, 60 ; exit
  mov rdi, 0
  syscall

segment readable writeable
  msg db "Hello, World", 10
  msg_len = $ - msg
