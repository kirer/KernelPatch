# kpm_frida

`kpm_frida` 是一个面向 KernelPatch 的 AArch64 KPM 模块，模块导出名称为 `KPM_FRIDA`，版本 `2.0.0`。它将五组与 Frida、调试器探测相关的隐藏逻辑组合到一个 KPM 中，用于在授权测试环境中降低应用从 `/proc`、文件探测、网络连接和内存扫描中发现调试或注入痕迹的概率。

> 该模块会修改内核态观测结果并安装多个 hook。请只在你拥有控制权且明确授权的设备、内核和测试场景中使用，并在加载前准备好可恢复方案。

## 架构概览

KPM_FRIDA 的防护思路：**内核态 Hook 隐藏痕迹 + 用户态换端口规避扫描**。

```
┌──────────────────────────────────────────────────┐
│                   用户态 (Userspace)               │
│  ┌──────────────────────────────────────────────┐ │
│  │  frida-server (root)     监听 :51742          │ │
│  │  /data/local/tmp/fo -l 0.0.0.0:51742 -D      │ │
│  └──────────────────┬───────────────────────────┘ │
│                     │ adb forward :51742→:51742   │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
│                     │   内核态 (Kernel)            │
│  ┌──────────────────┴───────────────────────────┐ │
│  │  KPM_FRIDA (5 个子模块)                       │ │
│  │  ├─ debugger_hide   TracerPid/wchan/stat     │ │
│  │  ├─ frida_hide      maps & 线程名             │ │
│  │  ├─ openat_hide     openat/faccessat/fstatat │ │
│  │  ├─ net_hide        /proc/net/tcp 隐藏端口    │ │
│  │  └─ mem_hide        /proc/pid/mem 签名清理    │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

**核心思路**：游戏反作弊只扫描 `27042`/`27043` 等 frida 默认端口。把 frida-server 换到随机高端口（如 `51742`），游戏 `connect(127.0.0.1, 27042)` 直接落空，零 iptables 依赖。

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

### 反作弊常见检测手段与对策

游戏反作弊系统通常通过以下途径检测 Frida/调试器：

| 层级 | 检测方法 | 对策 | 状态 |
|------|---------|------|------|
| 端口扫描 | `connect(127.0.0.1, 27042)` | **frida-server 监听随机端口** | ✅ |
| /proc 文件 | `read("/proc/net/tcp")` | net_hide 隐藏端口行 | ✅ |
| /proc 文件 | `open("/proc/self/maps")` | frida_hide 隐藏映射行 | ✅ |
| /proc 文件 | `read("/proc/self/status")` | debugger_hide TracerPid→0 | ✅ |
| 进程内存 | `read("/proc/self/mem")` | mem_hide 清理签名 | ✅ |
| 线程名 | `prctl(PR_GET_NAME)` | frida_hide 伪装为 binder | ✅ |
| 文件探测 | `stat/openat` frida 路径 | openat_hide 返回 ENOENT | ✅ |
| 库枚举 | `dl_iterate_phdr()` | 无法内核拦截 | ⚠️ |
| fd 扫描 | `readlinkat(/proc/self/fd/*)` | hook 会导致内核 panic | ❌ |

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

#### 4. net_hide — 隐藏 /proc/net/tcp 中的 frida 端口

**文件**：`net_hide.c`

**Hook 点**：`tcp4_seq_ops->show` / `tcp6_seq_ops->show`

通过 `fp_hook` 替换 `seq_operations` 的 `show` 函数指针，先调用原始函数，然后检查输出中是否包含 frida 端口的十六进制表示，命中则回退 `m->count` 移除该行：

| 端口 | 十六进制 (网络字节序) | 用途 |
|------|----------------------|------|
| 27042 | `:69A2` | frida-server 默认端口 |
| 27043 | `:69A3` | frida-server 备用端口 |
| 23946 | `:5D8A` | frida cluster 端口 |
| 31415 | `:7AB7` | frida-gadget 默认端口 |

> **注意**：`connect()` syscall hook 无法实现（`__arm64_sys_connect` 未在 kallsyms 导出）。但通过 **随机端口** 策略已完美规避——端口扫描只针对默认端口，换端口后全部落空。

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

## 随机端口方案 — 规避端口扫描

游戏反作弊最常见的检测是 `connect(127.0.0.1, 27042)` 扫描 frida 默认端口。最优雅的对策不是 iptables 拦截，而是**压根不监听默认端口**。

```bash
# 启动 frida-server 在随机高端口
su -c /data/local/tmp/fo -l 0.0.0.0:51742 -D

# 建立端口转发
adb forward tcp:51742 tcp:51742

# 通过转发端口连接
frida -H 127.0.0.1:51742 -f com.garena.game.kgtw
```

对比 iptables 方案的优势：

| 方面 | iptables | 随机端口 |
|------|---------|---------|
| 持久化 | 重启丢失，需脚本重新执行 | 启动命令即生效 |
| 副作用 | 清空 OUTPUT 链，影响其他规则 | 无 |
| 依赖 | 需要 netfilter 模块 | 无额外依赖 |
| 隐蔽性 | 端口不可达但 iptables 规则可见 | 默认端口压根无监听 |
| 简洁度 | 需要维护脚本 | 一行命令 |

`net_hide` 模块同时将新端口从 `/proc/net/tcp` 中隐藏，防止通过 `/proc` 枚举发现。

## 已知不可 hook 的检测点

以下检测方法无法在内核态拦截，或 hook 会导致严重风险：

| 检测方法 | 风险 | 说明 |
|----------|------|------|
| `readlinkat(/proc/self/fd/*)` | 🔴 内核 panic | hook readlinkat/statx 会导致手机死机重启 |
| `prctl(PR_GET_NAME)` 内核 hook | 🔴 内核 panic | 会导致手机卡死，已从模块中移除 (`prctl_hide.c`) |
| `dl_iterate_phdr()` | ⚠️ 无法内核拦截 | 纯用户态函数，无 syscall 调用 |
| `connect()` syscall hook | ⚠️ 无法 hook | `__arm64_sys_connect` 未导出，用随机端口规避 |
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
    └── iptables_frida.sh    # 遗留的 iptables 方案（已不推荐）
```

## 部署步骤

```bash
# 1. APatch → 加载 KPM_FRIDA.kpm

# 2. 启动 frida-server 在随机端口
adb shell "su -c '/data/local/tmp/fo -l 0.0.0.0:51742 -D &'"

# 3. 建立端口转发
adb forward tcp:51742 tcp:51742

# 4. 注入并追踪
frida -H 127.0.0.1:51742 -f com.garena.game.kgtw -l 实战/detect_trace.js
```

> **端口选择**：避开 `27042`/`27043`/`23946`/`31415` 这些 frida 默认端口即可，任意高端口都行。

## 实战验证

已在以下环境验证通过：

| 项目 | 详情 |
|------|------|
| 设备 | Xiaomi 2201123C (cupid) |
| Android | 13, Kernel 5.10.101, ARM64 |
| Root | APatch + Zygisk |
| 目标 APP | 傳說對決 (com.garena.game.kgtw) |
| frida-server | v16.7.19, 路径 `/data/local/tmp/fo` |
| 方案 | 随机端口 51742 + KPM 五模块 |
| 测试结果 | ✅ 游戏正常运行 25+ 秒，零反作弊检测触发 |

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
- frida-server 端口的十六进制值如果不在 `net_hide` 的已知列表里，`/proc/net/tcp` 不会隐藏（但 `connect()` 扫描已经落空，影响不大）。
- `push` 目标依赖本机 `adb` 环境。
- 加载 KPM 模块后再启动 frida-server，否则已存在的 frida 线程/映射不会被隐藏。
- 所有 hook 都会修改内核暴露给用户态的观测结果，建议先在可恢复测试机上验证。
