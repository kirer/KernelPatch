# 实战分析

## 反作弊检测点与对策

通过 frida 追踪脚本 `detect_trace.js` 捕获的目标 APP 反作弊行为：

| 检测方法 | 对策 | 状态 |
|---|---|---|
| **端口扫描** `connect(127.0.0.1, 27042)` | 随机端口（`-l 0.0.0.0:51742`） | ✅ |
| **/proc/net/tcp** 端口查看 | net_hide (内核 hook) | ✅ |
| **TracerPid** `/proc/self/status` | debugger_hide | ✅ |
| **进程状态** `t (tracing stop)` | debugger_hide | ✅ |
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
- frida 注入后游戏稳定运行 25+ 秒，零反作弊检测触发
- 期间仅捕获到正常的 `prctl(PR_GET_NAME)` 线程命名事件

## 文件说明

| 文件 | 用途 |
|---|---|
| `detect_trace.js` | frida 脚本，hook 关键 API 追踪反作弊行为 |
| `iptables_frida.sh` | 遗留的 iptables 方案（已被随机端口方案替代，仅供参考） |

## 部署步骤

```bash
# 1. APatch 加载 KPM_FRIDA.kpm

# 2. 启动 frida-server 在随机端口（避开 27042/27043/23946/31415）
adb shell "su -c '/data/local/tmp/fo -l 0.0.0.0:51742 -D &'"

# 3. 建立端口转发
adb forward tcp:51742 tcp:51742

# 4. 注入追踪
frida -H 127.0.0.1:51742 -f com.garena.game.kgtw -l detect_trace.js
```

## 随机端口 vs iptables

随机端口方案比 iptables 更优雅：

| 方面 | iptables | 随机端口 |
|------|---------|---------|
| 持久化 | 重启丢失 | 命令即生效 |
| 副作用 | 清空 OUTPUT 链 | 无 |
| 隐蔽性 | 规则可见 | 默认端口无监听 |
| 简洁度 | 需维护脚本 | 一行命令 |

**原理**：游戏反作弊硬编码扫描 `connect(127.0.0.1, 27042)`。把 frida-server 监听到 `:51742`，端口扫描直接落空——端口压根不存在，不需要 iptables 拦截。
