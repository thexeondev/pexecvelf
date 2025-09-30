# PExecvELF
**Portable Executable** that emulates **execve** to interpret **Executable and Linkable Format**

### Why?
This 'emulator' was implemented in order to be able to run Linux executables (ELF) on Windows without using any kind of VM (WSL and etc). It only reimplements the subset of syscalls that [cyrene-sr](https://git.xeondev.com/cyrene-sr/cyrene-sr) uses.

### Usage
Compile it with [Zig 0.15.1](https://ziglang.org/download/0.15.1/zig-x86_64-windows-0.15.1.zip).
```sh
git clone https://git.xeondev.com/xeon/pexecvelf.git
cd pexecvelf
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast
```

Run any ELF file, for example, cyrene-sr gameserver:
```sh
pexecvelf.exe gameserver
```

### TODO
It's planned to extend the functionality of this emulator, as the development of [cyrene-sr](https://git.xeondev.com/cyrene-sr/cyrene-sr) goes forward and more functionality is required. Pull requests are always welcome. It may be also interesting to try and emulate other small linux-only projects using this.

### Join our community
For additional help, you can join our [discord server](https://discord.xeondev.com)

