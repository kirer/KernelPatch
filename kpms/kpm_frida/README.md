# kpm_frida

`kpm_frida` 是一个面向 KernelPatch 的 AArch64 KPM 示例模块目录，模块实际导出的名称现为 `KPM_FRIDA`，版本为 `2.0.0`。它将多组与 Frida、调试器探测相关的隐藏逻辑组合到一个 KPM 中，用于在授权测试环境中降低应用从 `/proc`、文件探测、网络连接和内存扫描中发现调试或注入痕迹的概率。

> 该模块会修改内核态观测结果并安装多个 hook。请只在你拥有控制权且明确授权的设备、内核和测试场景中使用，并在加载前准备好可恢复方案。

## 模块信息

- 目录名：`kpms/kpm_frida`
- KPM 名称：`KPM_FRIDA`
- 版本：`2.0.0`
- 作者：`pandaos`
- 许可证：`GPL v2`
- 架构：`arm64 / AArch64`
- 输出产物：`KPM_FRIDA.kpm`
- 主入口：`kpm_frida.c`

## 功能概览

`kpm_frida_init()` 会依次安装以下五组隐藏逻辑：

- `frida_debugger_hide_install()`：隐藏 `TracerPid`、`t (tracing stop)`、`ptrace_stop` 等调试状态特征。
- `frida_maps_hide_install()`：隐藏 `/proc/[pid]/maps` 中的 Frida 相关映射，并伪装特征线程名。
- `frida_openat_hide_install()`：拦截 `openat`、`faccessat` 对 Frida 相关文件路径的探测。
- `frida_net_hide_install()`：阻止普通进程连接常见 Frida 端口，仅放行 `adbd`。
- `frida_mem_hide_install()`：在 `/proc/[pid]/mem` 读取路径上擦除常见 Frida 特征字符串。

`kpm_frida_exit()` 会按相反顺序卸载这些 hook。

## 子模块说明

### debugger_hide

文件：

- `debugger_hide.c`
- `debugger_hide.h`

该模块通过运行时解析并 hook 下列内核函数：

- `seq_put_decimal_ull`
- `seq_puts`
- `proc_pid_wchan`
- `do_task_stat`

处理逻辑包括：

- 将 `/proc/[pid]/status` 中的 `TracerPid` 强制显示为 `0`
- 将 `t (tracing stop)` 改写为 `S (sleeping)`
- 将 `/proc/[pid]/wchan` 中的 `ptrace_stop` 改为 `0`
- 将 `/proc/[pid]/stat` 中的 tracing stop 状态 `t` 改成 `S`

这部分主要用于弱化 ptrace 调试痕迹。

### frida_hide

文件：

- `frida_hide.c`
- `frida_hide.h`

该模块 hook：

- `show_map_vma`
- `__get_task_comm`

处理逻辑包括：

- 从 `/proc/[pid]/maps` 的新增输出片段中查找并移除包含以下关键字的映射：
  - `frida`
  - `gadget`
  - `linjector`
  - `gmain`
- 将包含以下关键字的线程名伪装为 `binder`：
  - `gum-js-loop`
  - `pool-frida`
  - `pool-spawner`
  - `linjector`
  - `gmain`
  - `gdbus`
  - `frida`

### openat_hide

文件：

- `openat_hide.c`
- `openat_hide.h`

该模块通过 `fp_hook_syscalln()` hook：

- `openat`
- `faccessat`

当用户态程序尝试探测以下路径关键字时，模块会直接返回 `-ENOENT`：

- `re.frida.server`
- `frida-agent-32.so`
- `frida-agent-64.so`
- `frida-agent.so`
- `frida-gadget`
- `linjector`

代码里明确放行了 `/memfd:` 路径，避免误伤基于 memfd 的普通内存文件描述符。

### net_hide

file:
- `net_hide.c`
- `net_hide.h`

hook: `seq_operations->show` for `/proc/net/tcp` and `/proc/net/tcp6`

hidden ports:
- `27042` -> `:69A2` (frida-server default)
- `27043` -> `:69A3` (frida-server alt)
- `23946` -> `:5D8A` (frida cluster)
- `31415` -> `:7AB7` (frida-gadget default)

Uses `fp_hook` to replace `show` function pointer in `tcp4_seq_ops`
and `tcp6_seq_ops`. Calls original show, then checks output for frida
port hex patterns and rolls back `m->count` to hide matching lines.

Note: `connect()` syscall hooking is NOT implemented because safe
user-memory access is unavailable in KPM hook callbacks on PAN kernels.

### mem_hide

文件：

- `mem_hide.c`
- `mem_hide.h`

该模块 hook `access_remote_vm`，仅在读取路径上处理内核缓冲区，不影响写路径。它会在 `/proc/[pid]/mem` 的读取结果中扫描并清零以下 Frida 特征字符串：

- `LIBFRIDA`
- `frida-agent`
- `frida-gadget`
- `frida_agent`
- `frida-server`
- `re.frida.server`
- `frida:rpc`
- `gum-js-loop`
- `GumScript`
- `linjector`

## 代码结构

```text
kpms/kpm_frida/
├── Makefile
├── README.md
├── kpm_frida.c
├── common.h
├── debugger_hide.c
├── debugger_hide.h
├── frida_hide.c
├── frida_hide.h
├── openat_hide.c
├── openat_hide.h
├── net_hide.c
├── net_hide.h
├── mem_hide.c
└── mem_hide.h
```

## 构建要求

该模块需要 AArch64 bare-metal GCC 工具链。`Makefile` 通过 `TARGET_COMPILE` 前缀调用：

- `aarch64-none-elf-gcc`
- `aarch64-none-elf-ld`

模块默认将 `KP_DIR` 视为目录上两级的 KernelPatch 根目录，也可以显式传入。

## Windows 编译

假设 Arm GNU Toolchain 已解压到：

```powershell
D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin
```

执行：

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_frida
make TARGET_COMPILE=aarch64-none-elf- clean all
```

如果需要显式指定 KernelPatch 根目录：

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_frida
make TARGET_COMPILE=aarch64-none-elf- KP_DIR=E:/KPM/KernelPatch clean all
```

## macOS 编译

Apple Silicon 示例：

```bash
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-arm64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_frida
make TARGET_COMPILE=aarch64-none-elf- clean all
```

Intel Mac 示例：

```bash
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-x86_64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_frida
make TARGET_COMPILE=aarch64-none-elf- KP_DIR="$HOME/KernelPatch" clean all
```

## 其它 Makefile 目标

- `make TARGET_COMPILE=aarch64-none-elf- clean`
- `make TARGET_COMPILE=aarch64-none-elf- push`

其中 `push` 会尝试执行：

```text
adb push KPM_FRIDA.kpm /sdcard/Download/
```

## 注意事项

- 该模块目录名是 `kpm_frida`，KPM 实际导出名称是 `KPM_FRIDA`。
- `Makefile` 已去掉无效的 `-I./src` 包含路径。
- `push` 目标依赖本机 `adb` 环境。
- `net_hide.c` 的注释比当前实现更激进；如果你后续要扩展 `/proc/net/tcp` 过滤，建议先核对真实需求和副作用。
- `mem_hide`、`debugger_hide`、`frida_hide` 都会直接修改内核暴露给用户态的观测结果，建议先在可恢复测试机上验证兼容性。
