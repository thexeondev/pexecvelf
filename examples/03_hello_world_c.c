// gcc -nostdlib -nostartfiles -nodefaultlibs 03_hello_world_c.c -o hello_world_c

#define NR_write 1
#define NR_exit 60
#define STDOUT 1
#define EXIT_SUCCESS 0

typedef long unsigned int u64;
char msg[] = "Hello, World!\n";

__attribute__((noreturn))
inline void exit(int error_code) {
    asm volatile(
        "syscall"
        :
        : "a"(NR_exit), "D"(error_code)
        :
    );

    while (1) ;
}

inline u64 write(int fd, char* buf, u64 count) {
    u64 result;
    asm volatile(
        "syscall"
        : "=a"(result)
        : "a"(NR_write), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11"
    );

    return result;
}

void _start() {
    write(STDOUT, msg, sizeof msg);
    exit(EXIT_SUCCESS);
}

