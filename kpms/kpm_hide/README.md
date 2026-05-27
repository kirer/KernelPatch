# KPM_HIDE

`KPM_HIDE` 是一个面向 KernelPatch 的 AArch64 KPM 模块，版本为 `2.0.0`。它将多组内核侧隐藏逻辑组合到同一个模块中，用于在授权测试环境中降低 APatch、Zygisk 等相关运行痕迹被普通应用进程观测到的概率。

> 该模块会修改内核态观测结果并安装多个 hook。请只在你拥有控制权且明确授权的设备、内核和测试场景中使用，并在加载前准备好可恢复方案。

## 模块信息

- KPM 名称：`KPM_HIDE`
- 版本：`2.0.0`
- 作者：`KernelPatch`
- 许可证：`GPL v2`
- 架构：`arm64 / AArch64`
- 输出产物：`KPM_HIDE.kpm`
- 入口文件：`kpm_tools.c`

## 功能概览

`kpm_tools_init()` 会按顺序初始化共享工具函数和五个子模块：

- `kpm_utils`：通过 `kallsyms_lookup_name()` 解析 `vmalloc`、`vfree`、`__arch_copy_from_user` 等公共函数指针。
- `hide_maps`：过滤应用进程读取 `/proc/<pid>/maps` 和 `/proc/<pid>/smaps` 时看到的指定内存映射痕迹。
- `hide_apatch`：替换部分 syscall table 入口，在 APatch 排除进程中绕过 KernelPatch/APatch 的 syscall hook 链。
- `hide_mount`：过滤 `/proc/mounts`、`/proc/self/mountinfo`、`/proc/self/mountstats` 中的指定挂载痕迹，并修正 `mountinfo` 的 ID 关系。
- `hide_misc`：处理 SELinux 上下文、目录项和符号链接读取相关的检测面。
- `hide_net`：过滤 `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/unix` 中的指定网络特征。

卸载时，`kpm_tools_exit()` 会按相反顺序卸载各子模块 hook。

## 子模块说明

### hide_maps

该模块 hook `proc_pid_maps_op->show`，并在存在 `proc_pid_smaps_op` 时同时 hook `proc_pid_smaps_op->show`。原始 `show` 写入 `seq_file` 后，模块读取本次新增的输出行，如果命中过滤条件，就把 `m->count` 回滚到输出前的位置，从而隐藏该行。

当前过滤特征包括：

- `/memfd:wwb`
- `[anon:wwb]`

过滤逻辑只对 `uid > 10000` 的应用进程生效，避免影响系统进程的正常观测。

### hide_apatch

该模块针对 64 位 syscall table 和 32 位 compat syscall table 安装包装函数。包装函数会检查当前 UID 是否属于 APatch 排除进程：

- 如果进程被排除并且已解析到原始内核 syscall，则直接调用原始 syscall。
- 如果进程未被排除，则继续调用 KernelPatch/APatch 原先保存在 syscall table 中的 hook 链入口。

64 位处理的 syscall 包括 `truncate`、`execve`、`fstatat`、`faccessat`、`statx`、`unlinkat`、`mkdirat`、`mknodat`、`linkat`、`symlinkat`、`renameat2`、`fchmodat`、`fchownat`、`utimensat`。

32 位 compat 处理的 syscall 包括 `execve`、`fstatat64`、`faccessat`。

其中 `fstatat`、`faccessat`、`statx` 及对应 compat 包装还会对 `/debug_ramdisk` 做额外处理，在特定场景下返回 `-ENOENT`。

### hide_mount

该模块通过 `hook_wrap2()` 包装以下内核函数：

- `show_vfsmnt`
- `show_mountinfo`
- `show_vfsstat`

命中指定关键字的挂载输出会被隐藏。当前过滤关键字包括 `APatch`、`revanced`、`zygisk`、`dex2oat`、`/data/adb/modules`、`/debug_ramdisk`。

对于 `/proc/self/mountinfo`，模块还会维护 mount ID 映射、隐藏节点重定向和 peer group 映射，减少隐藏行后留下的 ID 断层或父子关系异常。

### hide_misc

该模块安装多个 syscall hook：

- `fgetxattr`：当应用进程读取 `security.selinux` 并得到 `u:r:magisk:s0` 或 `u:r:su:s0` 时，将返回内容替换为 `u:r:surfaceflinger:s0`。
- `getsockopt`：对 socket 获取到的 `u:r:magisk:s0` 或 `u:r:su:s0` 做同样替换。
- `getdents64`：从目录项结果中过滤 `debug_ramdisk`。
- `readlinkat`：遇到 `zygisk_gadget`、`zygisk_lsposed`、`memfd:wwb` 相关路径时，将结果替换为 `/dev/null`。

这些处理同样只面向应用进程生效。

### hide_net

该模块 hook 网络相关的 `seq_operations->show`，过滤 `/proc/net` 中的指定特征：

- `/proc/net/tcp`：隐藏包含 `:31A4` 的 TCP 行，即端口 `12708`。
- `/proc/net/tcp6`：使用相同端口过滤逻辑。
- `/proc/net/unix`：隐藏包含 `wwb` 的 Unix socket 行。

模块优先解析 `tcp4_seq_ops`，如果该符号不存在，会尝试回退到 `tcp_seq_ops`。

## 构建要求

该 KPM 需要 AArch64 bare-metal GCC 工具链，`Makefile` 通过 `TARGET_COMPILE` 前缀调用编译器：

- `aarch64-none-elf-gcc`
- `aarch64-none-elf-ld`

项目根目录默认按模块目录的 `../..` 推导，也可以通过 `KP_DIR` 显式指定。

## Windows 编译

假设 Arm GNU Toolchain 解压在：

```powershell
D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin
```

执行：

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_hide
make TARGET_COMPILE=aarch64-none-elf- clean all
```

如果需要显式指定 KernelPatch 根目录：

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_hide
make TARGET_COMPILE=aarch64-none-elf- KP_DIR=E:/KPM/KernelPatch clean all
```

## macOS 编译

Apple Silicon 示例：

```bash
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-arm64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_hide
make TARGET_COMPILE=aarch64-none-elf- clean all
```

Intel Mac 示例：

```bash
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-x86_64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_hide
make TARGET_COMPILE=aarch64-none-elf- KP_DIR="$HOME/KernelPatch" clean all
```

成功后会生成：

```text
KPM_HIDE.kpm
```

清理产物：

```bash
make TARGET_COMPILE=aarch64-none-elf- clean
```

## 目录结构

```text
kpms/kpm_hide/
├── .gitignore
├── Makefile
├── README.md
├── kpm_tools.c
├── kpm_utils.c
├── kpm_utils.h
├── hide_maps.c
├── hide_maps.h
├── hide_apatch.c
├── hide_apatch.h
├── hide_mount.c
├── hide_mount.h
├── hide_misc.c
├── hide_misc.h
├── hide_net.c
└── hide_net.h
```

## 注意事项

- 模块依赖 KernelPatch 提供的 hook、syscall、kallsyms、pgtable 等接口，需要目标内核和 KernelPatch 版本匹配。
- 多个子模块依赖运行时符号解析；如果目标内核裁剪或重命名了相关符号，模块会跳过对应功能或初始化失败。
- `hide_apatch` 会写 syscall table，并临时调整页表权限；这类操作风险较高，建议先在可恢复测试机上验证。
- `hide_mount` 会改写 `seq_file` 输出内容和 mount ID，目标内核的输出格式变化可能影响稳定性。
- 本目录不再维护 `justfile`，建议直接使用 `Makefile` 和上面的 Windows/macOS 命令构建。
