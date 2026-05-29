# KPM_SHIELD

`KPM_SHIELD` 是 `KPM_HIDE` 和 `KPM_FRIDA` 的合并升级版，将两个模块的 11 组隐藏逻辑统一到一个 KPM 中，并通过细粒度的运行时参数系统控制功能的开关和过滤模式。

> **为什么合并？** `KPM_HIDE` 和 `KPM_FRIDA` 同时 hook `tcp4_seq_ops->show` / `tcp6_seq_ops->show`，导致无法同时安装。合并后的单个模块消除了所有 hook 冲突，并提供了比原模块更灵活的参数控制。

## 模块信息

- KPM 名称：`KPM_SHIELD`
- 版本：`1.0.0`
- 架构：`arm64 / AArch64`
- 许可证：`GPL v2`
- 作者：`KernelPatch`
- 输出产物：`KPM_SHIELD.kpm`

## 功能概览

9 个功能开关，默认全部开启，可通过参数独立控制：

| 开关 | 来源 | 功能 |
|------|------|------|
| `maps` | kpm_hide + kpm_frida | 隐藏 /proc/pid/maps 注入痕迹 + frida VMA 名称 |
| `comm` | kpm_frida | 伪装 frida 线程名为 "binder"（`__get_task_comm`） |
| `apatch` | kpm_hide | 绕行 APatch syscall hook 链（替换 sys_call_table） |
| `mount` | kpm_hide | 隐藏 APatch/zygisk mount 点 + mount ID 重写 |
| `misc` | kpm_hide | SELinux 替换 + getdents64 过滤 + readlinkat 隐藏 |
| `net` | 合并 | 隐藏 /proc/net/tcp, tcp6, unix 指定端口/地址 |
| `debugger` | kpm_frida | 隐藏 TracerPid/wchan/stat 调试器痕迹 |
| `openat` | kpm_frida | 拦截 openat/faccessat/fstatat 的 frida 文件探测 |
| `mem` | kpm_frida | 擦除 /proc/pid/mem 读取中的 frida 字符串签名 |

## 架构对比

```
原方案（两个模块，冲突无法共存）：
┌──────────────┐     ┌──────────────┐
│  KPM_HIDE    │     │  KPM_FRIDA   │
│  ├ hide_maps │     │  ├ frida_maps│
│  ├ hide_apatch│    │  ├ debugger  │
│  ├ hide_mount│     │  ├ openat    │
│  ├ hide_misc │     │  ├ net_hide  │  ← ⚡ tcp4/tcp6 show 冲突！
│  └ hide_net  │     │  └ mem       │
└──────────────┘     └──────────────┘
        ⚡                      ⚡
     tcp4_seq_ops->show   tcp4_seq_ops->show   ← 同一函数指针

合并后：
              ┌───────────────────┐
              │    KPM_SHIELD     │
              │  ├ shield_maps    │  ← maps + comm 共享 maps_pat 配置
              │  ├ shield_apatch  │  ← sys_call_table 层替换
              │  ├ shield_mount   │  ← 支持自定义 mount_pat
              │  ├ shield_misc    │  ← 支持自定义 selinux_from/to
              │  ├ shield_net     │  ← 合并两套过滤（单 hook）
              │  ├ shield_debugger│
              │  ├ shield_openat  │  ← inline hook 层拦截
              │  └ shield_mem     │
              └───────────────────┘
```

## 各模块原理

### shield_maps（maps + comm）

三层 hook，共享同一套 `maps_pat` 配置：

1. **`proc_pid_maps_op->show` / `proc_pid_smaps_op->show`**（fp_hook）
   - 原始 show 写入 `seq_file` 后，检查输出行是否命中 `maps_pat`
   - 命中则回滚 `m->count` 到写入前位置，整行消失

2. **`show_map_vma`**（hook_wrap2 before/after）
   - 在每个 VMA 描述写入 `seq_file` 时，检查新增内容是否命中 `maps_pat`
   - 命中则回滚，单行 VMA 消失（比第 1 层更细粒度）

3. **`__get_task_comm`**（hook_wrap3 after）
   - 当内核读取进程名（`/proc/pid/status` 的 `Name:` 字段等）时检查是否命中 `comm_pat`
   - 命中则将名字替换为 `"binder"`

### shield_apatch

替换 64 位 sys_call_table 的 14 个入口和 32 位 compat sys_call_table 的 3 个入口。包装函数检查 `get_ap_mod_exclude(uid)`：

- **excluded 进程** → 直接调用原始内核 syscall（绕过 APatch/KP hook 链）
- **非 excluded 进程** → 落入 KP hook 链

额外对 `fstatat` / `faccessat` / `statx` 做 `/debug_ramdisk` 拦截（返回 `-ENOENT`）。

### shield_mount

`hook_wrap2` 包装 3 个内核函数：`show_vfsmnt` / `show_mountinfo` / `show_vfsstat`。

输出行命中 `mount_pat` 时整行隐藏。对于 `show_mountinfo`，还会维护 mount ID 映射和 peer group 重映射，消除隐藏后残留的 ID 缺口。

### shield_misc

4 个 syscall after-hook（`fp_hook_syscalln`）：

| hook | 动作 |
|------|------|
| `fgetxattr` (security.selinux) | 读取的 label 命中 `selinux_from` 时替换为 `selinux_to` |
| `getsockopt` | 同上逻辑，处理 socket 路径的 SELinux 查询 |
| `getdents64` | 过滤目录项中命中 `dent_pat` 的条目 |
| `readlinkat` | 路径命中 `readlink_pat` 时替换为 `/dev/null` |

### shield_net（合并关键）

合并后只安装**一次** hook 在 `tcp4_seq_ops->show` / `tcp6_seq_ops->show` / `unix_seq_ops->show`：

- TCP 行：同时检查端口（`tcp_ports`，十六进制如 `31A4`）和地址（`tcp_addrs`，小端十六进制如 `0100007F`），全部命中才隐藏。默认同时覆盖原 kpm_hide 的 `12708` 和 kpm_frida 的 `27042/27043`
- Unix 行：检查是否包含 `unix_pat` 中的任一模式

### shield_debugger

4 个 hook 隐藏调试器痕迹：

| hook 点 | 方式 | 效果 |
|--------|------|------|
| `seq_put_decimal_ull` | before hook 改参数 | TracerPid → 0 |
| `seq_puts` | before hook 改参数 | `"t (tracing stop)"` → `"S (sleeping)"` |
| `proc_pid_wchan` | after hook 改 buf | `"ptrace_stop"` → `"0"` |
| `do_task_stat` | after hook 改 buf | 进程状态 `t` → `S` |

### shield_openat

3 个 syscall before-hook（`fp_hook_syscalln`）拦截 `openat` / `faccessat` / `fstatat`。从用户态复制文件路径，命中 `block_paths` 中任一模式则 `skip_origin + ret=-2`（`-ENOENT`）。

> 与 `shield_apatch` 的关系：两者作用于不同层级。`apatch` 替换 sys_call_table 决定"谁处理 syscall"，`openat` 在 inline hook 层做 before 拦截。两者可同时开启，非 excluded 进程的 openat 调用会先经过 openat before hook 过滤，再由 apatch wrapper 分发。

### shield_mem

`hook_wrap5` 包装 `access_remote_vm`（`/proc/pid/mem` 读取的底层实现）。在 after hook 中扫描返回的缓冲区，将以下 frida 签名字符串原地清零：

`Frida` `FRIDA` `frida-agent` `frida-gadget` `frida-server` `re.frida.server` `libfrida`

只处理读路径（`FOLL_WRITE` 跳过），不影响写操作。

## 参数系统

### 功能开关

格式：`key=1`（开启）或 `key=0`（关闭），逗号分隔。

```
maps=1,comm=1,apatch=1,mount=1,misc=1,net=1,debugger=1,openat=1,mem=1
```

不传参数时**所有功能默认开启**。

### 过滤模式

格式：`key=val1;val2;val3`，分号分隔多个值，逗号分隔不同 key。

| 参数 | 默认值 | 控制 |
|------|--------|------|
| `maps_pat` | `memfd:wwb;[anon:wwb];frida;gadget;linjector;gmain` | maps/smaps/VMA 隐藏模式 |
| `comm_pat` | `gum-js-loop;pool-frida;pool-spawner;linjector;gmain;gdbus;frida` | 线程名伪装模式 |
| `tcp_ports` | `31A4;69A2;69A3` | TCP 隐藏端口（十六进制） |
| `tcp_addrs` | `0100007F` | TCP 地址过滤（小端十六进制的 127.0.0.1） |
| `unix_pat` | `wwb` | Unix socket 隐藏模式 |
| `block_paths` | `re.frida.server;frida-agent;frida-gadget;linjector` | 文件探测拦截路径 |
| `selinux_from` | `u:r:magisk:s0;u:r:su:s0` | 需要替换的 SELinux label |
| `selinux_to` | `u:r:surfaceflinger:s0` | 替换成的 SELinux label |
| `mount_pat` | `APatch;revanced;zygisk;dex2oat;/data/adb/modules;/debug_ramdisk` | mount 点隐藏模式 |
| `dent_pat` | `debug_ramdisk` | 目录项隐藏模式 |
| `readlink_pat` | `zygisk_gadget;zygisk_lsposed;memfd:wwb` | readlink 路径隐藏模式 |

### 参数示例

**只开 net + debugger，自定义端口：**
```
maps=0,comm=0,apatch=0,mount=0,misc=0,net=1,debugger=1,openat=0,mem=0,tcp_ports=270F;31A4
```

**全开，但修改 frida 拦截路径清单：**
```
block_paths=re.frida.server;frida-agent;my-custom-tool
```

**只开 maps，修改隐藏模式为仅 frida：**
```
maps=1,comm=0,apatch=0,mount=0,misc=0,net=0,debugger=0,openat=0,mem=0,maps_pat=frida;gadget;gmain
```

**加载时不传参数（等效于全部默认开启）：**
```
（留空）
```

### ctl0 运行时重配置

加载后可通过 ctl0 更新配置（但已安装的 hook 不会卸载，只能调整过滤模式）：

```bash
# 更新 TCP 端口列表
echo "tcp_ports=270F;31A4" > /proc/kpmpatch/ctl0/KPM_SHIELD

# 关闭 maps 功能（hook 仍在，但过滤逻辑检查开关后跳过）
echo "maps=0" > /proc/kpmpatch/ctl0/KPM_SHIELD
```

## 嵌入模式

`event` 非空时模块进入嵌入模式（开机自启），此时只初始化默认配置而不安装任何 hook，避免在 kallsyms 未就绪时触发死机。hook 延迟到 APatch 调用 ctl0 时安装。

## 构建要求

需要 AArch64 bare-metal GCC 工具链。

- **macOS Homebrew**：`brew install arm-none-eabi-gcc`
- **ARM 官方工具链**：[Arm GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

## macOS 编译

```bash
# Homebrew（推荐）
brew install arm-none-eabi-gcc
cd ~/KernelPatch/kpms/kpm_shield
make clean all

# 显式指定工具链
make TARGET_COMPILE=aarch64-none-elf- clean all
```

成功生成 `KPM_SHIELD.kpm`（约 66KB）。

## Windows 编译

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_shield
make TARGET_COMPILE=aarch64-none-elf- clean all
```

## 部署步骤

```bash
# 1. ADB 推送
adb push KPM_SHIELD.kpm /sdcard/Download/

# 2. APatch 加载（手动模式）
#    APatch → KPM 管理 → 加载 KPM_SHIELD.kpm
#    参数留空 = 全部默认开启
#    参数示例（自定义）：maps=1,net=1,debugger=1,tcp_ports=270F;31A4

# 3. 嵌入模式
#    APatch → KPM 管理 → 嵌入 KPM_SHIELD.kpm
#    开机后模块会自动设置默认配置，hook 通过 ctl0 延迟安装
```

## 目录结构

```text
kpms/kpm_shield/
├── Makefile
├── README.md
├── shield_main.c          # 主入口、参数解析、编排
├── shield_config.h        # 配置结构体定义
├── shield_config.c        # 默认值、参数解析、模式匹配
├── shield_utils.h         # 共享工具（vmalloc、seq_file、is_app_process
├── shield_utils.c         # 工具函数全局变量
├── shield_maps.c/h        # maps/smaps + VMA + 线程名隐藏
├── shield_apatch.c/h      # sys_call_table 绕行
├── shield_mount.c/h       # mount 点隐藏 + ID 重写
├── shield_misc.c/h        # SELinux/getdents64/readlinkat
├── shield_net.c/h         # TCP/Unix socket 隐藏（合并）
├── shield_debugger.c/h    # 调试器痕迹隐藏
├── shield_openat.c/h      # 文件探测拦截
└── shield_mem.c/h         # 内存签名擦除
```

## 注意事项

- 所有 hook 均修改内核暴露给用户态的观测结果，建议先在有恢复方案的测试机上验证。
- 多个子模块依赖 `kallsyms_lookup_name()` 解析内核符号。目标内核裁剪或重命名了相关符号时，模块会跳过对应功能。
- `shield_apatch` 会直接写 sys_call_table 并临时调整页表权限，风险较高。
- `shield_mount` 会改写 `seq_file` 输出和 mount ID，目标内核输出格式变化可能影响稳定性。
- 嵌入模式下首次安装 hook 依赖 ctl0 触发，APatch 需要正确实现延迟安装机制。
- `prctl_hide` 未包含在模块中（实测在 Xiaomi 2201123C / Android 13 / Kernel 5.10.101 上导致死机），功能已被 `__get_task_comm` hook（`comm` 开关）安全替代。
- 加载模块后再启动 frida-server，否则已存在的线程/映射不会被隐藏。

## 许可证

GPL v2。与 KernelPatch 项目一致。
