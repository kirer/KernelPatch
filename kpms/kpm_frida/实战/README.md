# 实战分析

## 反作弊检测点

通过 frida 追踪脚本 `detect_trace.js` 捕获的目标 APP 反作弊行为：

| 检测方法 | 对应模块 | 状态 |
|---|---|---|
| **端口扫描** `connect(127.0.0.1, 27042)` | iptables UID 白名单 | ✅ |
| **/proc/net/tcp** 端口查看 | net_hide (内核 hook) | ✅ |
| **TracerPid** `/proc/self/status` | debugger_hide | ✅ |
| **进程状态** t (tracing stop) | debugger_hide | ✅ |
| **maps 隐藏** `/proc/pid/maps` | frida_hide | ✅ |
| **线程名伪装** `gum-js-loop` → `binder` | frida_hide | ✅ |
| **文件探测** `stat/openat` frida 路径 | openat_hide | ✅ |
| **内存签名** `LIBFRIDA` 等 | mem_hide | ✅ |
| **库枚举** `dl_iterate_phdr` | 无法内核拦截 | ⚠️ |
| **fd 扫描** `readlinkat(/proc/self/fd/*)` | hook 会导致内核 panic | ❌ |

## 验证结果

**2026-05-29 测试**：
- 设备：Xiaomi 2201123C, Android 13, Kernel 5.10.101
- 目标：傳說對決 (com.garena.game.kgtw)
- frida 注入后游戏稳定运行 78+ 秒，零反作弊检测触发
- 期间仅捕获到正常的 `prctl(PR_GET_NAME)` 线程命名事件

## 文件说明

| 文件 | 用途 |
|---|---|
| `detect_trace.js` | frida 脚本，hook 关键 API 追踪反作弊行为 |
| `iptables_frida.sh` | UID 白名单 iptables，拦截非 root 进程访问 frida 端口 |

## 部署步骤（每次重启后）

```bash
# 1. APatch 加载 KPM_FRIDA.kpm

# 2. 应用 iptables
adb shell "su -c 'sh /data/local/tmp/iptables_frida.sh'"

# 3. 启动 frida-server
adb shell "su -c '/data/local/tmp/fo -D &'"

# 4. 注入追踪（%resume 恢复主线程）
frida -U -f com.garena.game.kgtw -l detect_trace.js
```

## 为什么需要 iptables

内核态 `net_hide` 只能隐藏 `/proc/net/tcp` 中的端口显示，但无法阻止游戏直接调用 `connect()` 探测端口是否可达。iptables 在 netfilter 层面直接 REJECT 非 root 进程的连接，游戏 `connect()` 立即收到 `ECONNREFUSED`。

**UID 白名单设计**：root/system (UID 0-9999) 放行，保证 frida-server 自身通信正常；游戏等普通 app 被拦截。如果全阻断会导致 `frida -U -f` 无法完成注入。
