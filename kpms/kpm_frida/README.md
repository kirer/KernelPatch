# kpm_frida

`kpm_frida` 是一个面向 KernelPatch 的 AArch64 KPM 模块，模块导出名称为 `KPM_FRIDA`，版本 `2.0.0`。它将五组与 Frida、调试器探测相关的隐藏逻辑组合到一个 KPM 中，用于在授权测试环境中降低应用从 `/proc`、文件探测、网络连接和内存扫描中发现调试或注入痕迹的概率。

> 该模块会修改内核态观测结果并安装多个 hook。请只在你拥有控制权且明确授权的设备、内核和测试场景中使用，并在加载前准备好可恢复方案。

## 架构概览

KPM_FRIDA 采用**内核态 + 用户态双层防护**架构：

```
┌─────────────────────────────────────────────────┐
│                  用户态 (Userspace)               │
│  ┌──────────────┐  ┌───────────────────────────┐ │
│  │  iptables     │  │  frida-server (root)     │ │
│  │  (UID 白名单) │  │  /data/local/tmp/fo      │ │
│  └──────┬───────┘  └───────────────────────────┘ │
│         │                                        │
│  ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│         │          内核态 (Kernel)                │
│  ┌──────┴──────────────────────────────────────┐ │
│  │  KPM_FRIDA (5 个子模块)                      │ │
│  │  ├─ debugger_hide  TracerPid/wchan/stat     │ │
│  │  ├─ frida_hide     maps & 线程名             │ │
│  │  ├─ openat_hide    openat/faccessat/fstatat  │ │
│  │  ├─ net_hide       /proc/net/tcp 端口        │ │
│  │  └─ mem_hide       /proc/pid/mem 签名清理    │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

## 模块信息

- 目录名：`kpms/kpm_frida`
- KPM 名称：`KPM_FRIDA`
- 版本：`2.0.0`
- 作者：`pandaos`
- 许可证：`GPL v2`
- 架构：`arm64 / AArch64`
- 输出产物：`KPM_FRIDA.kpm`
- 主入口：`kpm_frida.c`

## 隐藏原理详解

### 反作弊常见检测手段

游戏反作弊系统通常通过以下途径检测 Frida/调试器：

| 层级 | 检测方法 | 原理 |
|------|---------|------|
| 端口扫描 | `connect(127.0.0.1, 27042)` | 探测 frida-server 默认端口是否在监听 |
| /proc 文件 | `readlinkat(/proc/self/fd/*)` | 遍历 fd 找 frida 相关路径 |
| /proc 文件 | `open("/proc/self/maps")` | 读取内存映射找 frida-agent 库 |
| /proc 文件 | `read("/proc/self/status")` | 检查 TracerPid 是否为 0 |
| /proc 文件 | `read("/proc/net/tcp")` | 查看端口占用找 frida 端口 |
| 进程内存 | `read("/proc/self/mem")` | 扫描进程内存找 LIBFRIDA 等签名 |
| 线程名 | `prctl(PR_GET_NAME)` | 枚举线程名找 gum-js-loop 等 |
| 库枚举 | `dl_iterate_phdr()` | 遍历已加载 SO 库 |

### 各模块防护逻辑

`kpm_frida_init()` 依次安装以下五组隐藏，`kpm_frida_exit()` 按相反顺序卸载。

#### 1. debugger_hide — 隐藏调试器痕迹

**文件**：`debugger_hide.c`

**Hook 点**：`seq_put_decimal_ull` / `seq_puts` / `proc_pid_wchan` / `do_task_stat`

| 检测点 | 原始行为 | 隐藏后 |
|--------|---------|--------|
| `/proc/pid/status` TracerPid | 非零值（被 ptrace） | `0` |
| `/proc/pid/status` State | `t (tracing stop)` | `S (sleeping)` |
| `/proc/pid/stat` 进程状态 | `t` | `S` |
| `/proc/pid/wchan` | `ptrace_stop` | `0` |

**原理**：通过 hook 内核 `seq_file` 输出函数，在用户态读取 `/proc` 文件时实时篡改输出缓冲区内容。`seq_put_decimal_ull` 的 before hook 检测到即将输出 `TracerPid` 值时将参数强制改为 0；`seq_puts` 将 `"t (tracing stop)"` 替换为 `"S (sleeping)"`；`proc_pid_wchan` 的 after hook 将 `"ptrace_stop"` 替换为 `"0"`；`do_task_stat` 将进程状态字符 `t` 改为 `S`。

#### 2. frida_hide — 隐藏内存映射和线程名

**文件**：`frida_hide.c`

**Hook 点**：`show_map_vma` / `__get_task_comm`

| 检测点 | 原始行为 | 隐藏后 |
|--------|---------|--------|
| `/proc/pid/maps` | 包含 `frida-agent.so`、`gadget` 等行 | 整行删除 |
| 线程名 | `gum-js-loop`、`pool-frida` 等 | 伪装为 `binder` |

**原理**：
- `show_map_vma` 是内核输出 `/proc/pid/maps` 每行内容的核心函数。before hook 记录当前 `seq_file->count`（缓冲区位置），after hook 检查新增内容是否包含 `frida` / `gadget` / `linjector` / `gmain` 关键字，命中则回退 `m->count` 使该行被"吞掉"。
- `__get_task_comm` 是 `/proc/pid/task/*/comm` 和 `prctl(PR_GET_NAME)` 在内核侧的底层实现。after hook 检查返回值是否匹配 7 个特征名（`gum-js-loop`、`pool-frida`、`pool-spawner`、`linjector`、`gmain`、`gdbus`、`frida`），命中则用 `memcpy` 原地替换为 `"binder"`。

#### 3. openat_hide — 阻断 Frida 文件路径探测

**文件**：`openat_hide.c`

**Hook 点**：`openat` (syscall 56) / `faccessat` (syscall 48) / `fstatat` (syscall 79)

**黑名单关键字**（不区分路径位置）：
- `re.frida.server` — frida-server 的包名标记
- `frida-agent-32.so` / `frida-agent-64.so` / `frida-agent.so`
- `frida-gadget` / `linjector`

**原理**：在 syscall 入口点 before hook 中调用 `compat_strncpy_from_user` 将用户态路径字符串拷贝到内核栈缓冲区，匹配黑名单关键字后直接设置 `args->ret = -2` (`ENOENT`) 并跳过原始调用。

**安全措施**：
- 显式放行 `/memfd:` 路径，避免误伤 Android 运行时基于 memfd 的内存操作
- 仅 hook syscall 入口，不涉及文件系统层，对正常 I/O 零影响

#### 4. net_hide — 隐藏端口 + iptables 阻断连接

**文件**：`net_hide.c`

本模块采用**两重防护**：

**A. 内核态：隐藏 `/proc/net/tcp` 和 `/proc/net/tcp6` 中的端口行**

**Hook 点**：`tcp4_seq_ops->show` / `tcp6_seq_ops->show`

通过 `fp_hook` 替换 seq_operations 的 show 函数指针，先调用原始函数，然后检查输出中是否包含 frida 端口的十六进制表示：

| 端口 | 十六进制 (网络字节序) | 用途 |
|------|----------------------|------|
| 27042 | `:69A2` | frida-server 默认端口 |
| 27043 | `:69A3` | frida-server 备用端口 |
| 23946 | `:5D8A` | frida cluster 端口 |
| 31415 | `:7AB7` | frida-gadget 默认端口 |

命中则回退 `m->count` 移除该行。

**B. 用户态：iptables UID 白名单阻断端口连接**

由于此内核（5.10.101）的 `__arm64_sys_connect` 未在 kallsyms 中导出，无法在内核态 hook connect 系统调用。因此改用 iptables 在用户态阻断检测：

```bash
# root/system 进程 (UID 0-9999) — 放行（frida-server 自身通信）
iptables -A OUTPUT -p tcp --dport 27042 -m owner --uid-owner 0-9999 -j ACCEPT
# 其他进程 (普通 APP) — 拒绝（游戏无法端口扫描）
iptables -A OUTPUT -p tcp --dport 27042 -j REJECT --reject-with tcp-reset
```

**为什么需要 iptables**：内核态 net_hide 只能隐藏 `/proc/net/tcp` 中的显示，但无法阻止游戏直接调用 `connect()` 探测端口是否可达。iptables 在 netfilter 层面直接 REJECT 非 root 进程的连接请求，游戏 `connect()` 会立即收到 `ECONNREFUSED`，相当于端口不存在。

**为什么用 UID 白名单而非全部阻断**：`frida -U -f` 的工作流程中，frida-server 自身也需要与 frida-agent 通信（通过 127.0.0.1:27042）。如果全部阻断，`frida -U -f` 将无法完成注入。UID 白名单只放行 root/system，游戏进程 (u0_aXXX) 仍被拦截。

#### 5. mem_hide — 清理 /proc/pid/mem 中的 Frida 签名

**文件**：`mem_hide.c`

**Hook 点**：`access_remote_vm`

**清理签名列表**：
- `LIBFRIDA` — frida 核心库的 ELF 导出标记
- `frida-agent` / `frida-gadget` / `frida_agent` / `frida-server`
- `re.frida.server` — frida-server 的 Java 包名
- `frida:rpc` / `gum-js-loop` / `GumScript` / `linjector`

**原理**：`access_remote_vm` 是 `process_vm_readv` 和 `/proc/pid/mem` 读取在内核侧的底层实现。after hook 在读取完成后扫描内核缓冲区，将匹配到的签名用 `memset(0)` 原地清零。

**安全措施**：
- 仅处理读取路径（`!(gup_flags & FOLL_WRITE)`），不影响写路径
- 扫描上限 64KB（`MAX_SCRUB_LEN`），防止大块读取导致 CPU 软锁定
- 仅清理实际读取字节数内的数据（`args->ret` 为实际读取长度）

## 已知不可 hook 的检测点

以下检测方法无法在内核态拦截，或 hook 会导致严重风险：

| 检测方法 | 风险 | 说明 |
|----------|------|------|
| `readlinkat(/proc/self/fd/*)` | 🔴 内核 panic | hook readlinkat/statx 会导致手机死机重启 |
| `prctl(PR_GET_NAME)` 内核 hook | 🔴 内核 panic | 会导致手机卡死，已从模块中移除 (`prctl_hide.c`) |
| `dl_iterate_phdr()` | ⚠️ 无法内核拦截 | 纯用户态函数，无 syscall 调用 |
| `connect()` syscall hook | ⚠️ 无法 hook | `__arm64_sys_connect` 未导出，改用 iptables |
| `strstr()` 扫描内存 | ⚠️ 部分缓解 | mem_hide 可清理 `/proc/mem` 路径，但直接内存读取无法拦截 |

## 代码结构

```text
kpms/kpm_frida/
├── Makefile
├── README.md
├── kpm_frida.c             # 主入口，注册/卸载所有子模块
├── common.h
├── debugger_hide.c         # 隐藏 TracerPid / wchan / stat
├── debugger_hide.h
├── frida_hide.c            # 隐藏 maps / 线程名
├── frida_hide.h
├── openat_hide.c           # 阻断 frida 文件路径探测
├── openat_hide.h
├── net_hide.c              # 隐藏 /proc/net/tcp 端口
├── net_hide.h
├── mem_hide.c              # 清理 /proc/mem 中 frida 签名
├── mem_hide.h
├── prctl_hide.c            # ⚠️ 已移除（会导致死机）
├── prctl_hide.h
└── 实战/
    ├── README.md            # 实战分析记录
    ├── detect_trace.js      # frida 反作弊检测追踪脚本
    └── iptables_frida.sh    # iptables UID 白名单脚本
```

## 部署步骤

每次手机重启后需执行以下步骤：

```bash
# 1. 推送文件（首次执行）
adb push 实战/iptables_frida.sh /data/local/tmp/

# 2. APatch → 加载 KPM_FRIDA.kpm

# 3. 应用 iptables 规则
adb shell "su -c 'sh /data/local/tmp/iptables_frida.sh'"

# 4. 启动 frida-server
adb shell "su -c '/data/local/tmp/fo -D &'"

# 5. 注入并追踪
frida -U -f com.garena.game.kgtw -l 实战/detect_trace.js
```

> **注意**：iptables 规则在重启后丢失，每次重启都需要重新执行步骤 3。可通过 APatch post-fs-data 脚本自动执行。

## 实战验证

已在以下环境验证通过：

| 项目 | 详情 |
|------|------|
| 设备 | Xiaomi 2201123C (cupid) |
| Android | 13, Kernel 5.10.101, ARM64 |
| Root | APatch + Zygisk |
| 目标 APP | 傳說對決 (com.garena.game.kgtw) |
| frida-server | v16.7.19, 路径 `/data/local/tmp/fo` |
| 测试结果 | ✅ 游戏正常运行 78+ 秒，零反作弊检测触发 |

`实战/detect_trace.js` 脚本 hook 以下函数追踪反作弊行为：

- `_exit` / `kill` — 谁终止了进程
- `dl_iterate_phdr` — 库枚举
- `prctl(PR_GET_NAME)` — 线程名扫描
- `open` / `readlinkat` — /proc 文件探测
- `connect` — 端口扫描
- `ptrace` — 调试器检测

## 构建要求

该模块需要 AArch64 bare-metal GCC 工具链（`aarch64-none-elf-gcc` 或 `aarch64-elf-gcc`）。

Makefile 会按以下优先级查找编译器：

1. 显式传入的 `TARGET_COMPILE` 前缀
2. 自动检测：`aarch64-none-elf-gcc` → `aarch64-elf-gcc`
3. 若都未找到则报错退出

模块默认将 `KP_DIR` 视为目录上两级的 KernelPatch 根目录，也可以显式传入。

## macOS 编译

### 方式一：Homebrew 安装（推荐）

```bash
brew install arm-none-eabi-gcc
```

安装后 `aarch64-elf-gcc` 即位于 PATH 中，直接运行：

```bash
cd ~/KernelPatch/kpms/kpm_frida
make clean all
```

Makefile 会自动检测到 `aarch64-elf-` 前缀，无需手动指定。

### 方式二：手动下载 ARM 工具链

从 [Arm GNU Toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) 下载对应架构：

- Apple Silicon: `arm-gnu-toolchain-*-darwin-arm64-aarch64-none-elf.tar.xz`
- Intel Mac: `arm-gnu-toolchain-*-darwin-x86_64-aarch64-none-elf.tar.xz`

解压到 `/opt/` 后执行：

```bash
# Apple Silicon
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-arm64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_frida
make clean all

# Intel Mac（需要显式指定 KP_DIR）
export PATH="/opt/arm-gnu-toolchain-15.2.rel1-darwin-x86_64-aarch64-none-elf/bin:$PATH"
cd ~/KernelPatch/kpms/kpm_frida
make KP_DIR="$HOME/KernelPatch" clean all
```

### 显式指定工具链前缀

```bash
make TARGET_COMPILE=aarch64-none-elf- clean all
```

### macOS 常见问题

- **`make: *** TARGET_COMPILE not set`**：未安装工具链或不在 PATH 中。请先通过 Homebrew 安装 `arm-none-eabi-gcc`。
- **`aarch64-none-elf-gcc: command not found`**：Homebrew 安装的工具链前缀为 `aarch64-elf-`。可直接 `make clean all` 自动检测。
- **权限错误**：手动下载的工具链可能需要 `xattr -cr /opt/arm-gnu-toolchain-*` 清除 macOS 隔离属性。

## Windows 编译

```powershell
$env:PATH='D:\arm-gnu-toolchain-15.2.rel1-mingw-w64-i686-aarch64-none-elf\bin;' + $env:PATH
cd E:\KPM\KernelPatch\kpms\kpm_frida
make TARGET_COMPILE=aarch64-none-elf- clean all
```

## 其它 Makefile 目标

```bash
make clean              # 清理构建产物
make push               # 通过 adb 推送到 /sdcard/Download/
```

## 注意事项

- 该模块目录名是 `kpm_frida`，KPM 实际导出名称是 `KPM_FRIDA`。
- **不要将 `prctl_hide` 编入模块**，hook `prctl(PR_GET_NAME)` 会导致手机死机。
- **不要添加 `readlinkat` / `statx` hook**，会导致内核 panic 重启。
- iptables 规则在重启后丢失，需重新执行或配置 post-fs-data 自动加载。
- `push` 目标依赖本机 `adb` 环境。
- 加载 KPM 模块后再启动 frida-server，否则已存在的 frida 线程/映射不会被隐藏。
- 所有 hook 都会修改内核暴露给用户态的观测结果，建议先在可恢复测试机上验证。
