/**
 * detect_trace.js - 反作弊检测点追踪 (精简版)
 *
 * 只 hook 关键检测函数，避免 strstr 等高频函数导致崩溃。
 *
 * 用法:
 *   frida -U -f com.garena.game.kgtw -l detect_trace.js
 */

var START = Date.now();
var LOG  = [];

function log(msg) {
    var entry = "[" + (Date.now() - START) + "ms] " + msg;
    LOG.push(entry);
    console.log(entry);
}

// ============================================================
// 1. 进程终止 — 最关键：谁杀了进程
// ============================================================
var origExit = Module.findExportByName(null, "_exit");
if (origExit) {
    Interceptor.replace(origExit, new NativeCallback(function(code) {
        console.log("\n╔══════════════════════════════════════╗");
        console.log("║  _exit(" + code + ") 被调用!              ║");
        console.log("║  存活: " + (Date.now() - START) + "ms, 事件: " + LOG.length + "     ║");
        console.log("║  调用栈:                             ║");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n║  "));
        console.log("╠══════════════════════════════════════╣");
        console.log("║  最后 25 条事件:                      ║");
        var s = Math.max(0, LOG.length - 25);
        for (var i = s; i < LOG.length; i++)
            console.log("║  " + LOG[i].substring(0, 68));
        console.log("╚══════════════════════════════════════╝");
        var real = new NativeFunction(origExit, 'void', ['int']);
        real(code);
    }, 'void', ['int']));
    log("[HOOK] _exit (replace)");
}

// kill
var kill_fn = Module.findExportByName(null, "kill");
if (kill_fn) {
    Interceptor.attach(kill_fn, {
        onEnter: function(args) {
            var pid = args[0].toInt32();
            if (pid === Process.id || pid <= 0)
                log("!!! kill(pid=" + pid + ", sig=" + args[1] + ")");
        }
    });
    log("[HOOK] kill");
}

// ============================================================
// 2. dl_iterate_phdr — 库枚举（反作弊核心检测点）
// ============================================================
var dip = Module.findExportByName(null, "dl_iterate_phdr");
if (dip) {
    var dcount = 0;
    Interceptor.attach(dip, {
        onEnter: function(args) { this.cb = args[0]; },
        onLeave: function(ret) {
            dcount++;
            if (dcount <= 15)
                log("dl_iterate_phdr() #" + dcount + " cb=" + this.cb);
            else if (dcount === 16)
                log("dl_iterate_phdr() ... (silenced)");
        }
    });
    log("[HOOK] dl_iterate_phdr");
}

// ============================================================
// 3. 线程名检测
// ============================================================
var prctl_fn = Module.findExportByName(null, "prctl");
if (prctl_fn) {
    Interceptor.attach(prctl_fn, {
        onEnter: function(args) { this.opt = args[0].toInt32(); },
        onLeave: function(ret) {
            if (this.opt === 16 && ret.toInt32() === 0) {
                try { log("prctl(PR_GET_NAME) → \"" + this.context.x1.readCString() + "\""); }
                catch(e) {}
            }
        }
    });
    log("[HOOK] prctl(PR_GET_NAME)");
}

// ============================================================
// 4. /proc 访问
// ============================================================
function checkProc(args, idx) {
    try {
        var p = args[idx].readCString();
        if (p && p.indexOf("/proc/") === 0) return p;
        if (p && (p.indexOf("frida") >= 0 || p.indexOf("gadget") >= 0)) return p;
    } catch(e) {}
    return null;
}

var open_fn = Module.findExportByName(null, "open");
if (open_fn) {
    Interceptor.attach(open_fn, {
        onEnter: function(args) { var p = checkProc(args, 0); if (p) log("open(\"" + p + "\")"); }
    });
    log("[HOOK] open");
}

var rlat = Module.findExportByName(null, "readlinkat");
if (rlat) {
    Interceptor.attach(rlat, {
        onEnter: function(args) { var p = checkProc(args, 1); if (p) log("readlinkat(\"" + p + "\")"); }
    });
    log("[HOOK] readlinkat");
}

// ============================================================
// 5. connect
// ============================================================
var conn_fn = Module.findExportByName(null, "connect");
if (conn_fn) {
    Interceptor.attach(conn_fn, {
        onEnter: function(args) {
            try {
                if (args[1].readU16() === 2) {
                    var pb = args[1].add(2).readU16();
                    var port = ((pb >> 8) & 0xFF) | ((pb & 0xFF) << 8);
                    log("connect() → port " + port);
                }
            } catch(e) {}
        }
    });
    log("[HOOK] connect");
}

// ============================================================
// 6. ptrace
// ============================================================
var pt_fn = Module.findExportByName(null, "ptrace");
if (pt_fn) {
    Interceptor.attach(pt_fn, {
        onEnter: function(args) { log("ptrace(req=" + args[0].toInt32() + ")"); }
    });
    log("[HOOK] ptrace");
}

// ============================================================
// 7. 定时报告
// ============================================================
setInterval(function() {
    var e = Date.now() - START;
    if (e > 3000 && e < 3100) console.log("\n═══ [3s] " + LOG.length + " events, alive ═══");
    if (e > 8000 && e < 8100) console.log("\n═══ [8s] " + LOG.length + " events, alive ═══");
}, 1000);

console.log("\n═══ Tracker Ready PID:" + Process.id + " ═══\n");
