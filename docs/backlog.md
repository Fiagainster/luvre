# Backlog — 搁置中的大件（2026-11-18，v0.5.0 发版后整理）

> 原则：**按做题需求拉动，不预投入**。每项写了「启动信号」——真实做题撞到了再开工。
> 小件与临时想法不进这里，直接做；这里的每项都是 2~5 天级的工程。

---

## 1. 结构体 / 数据类型编辑 + Union 面板

- **为什么**：「查看器 → 工作台」的分水岭。现在能改名函数/备注，但结构体只能看不能改——
  解 VM/协议类题时伪代码里满屏 `*(int *)(x + 0x1c)`，手工心算偏移。
- **入口提示**：Ghidra 的 `DataTypeManager` API（`StructureDataType` / `UnionDataType`），
  经 EngineManager 单 worker 走；前端在反编译符号右键菜单加「改为结构体成员访问」。
- **预估**：3–5 天（API 深，前端面板另计）。
- **启动信号**：连续两道题因为改不了结构体而去开 Ghidra 本体的时候。

## 2. Pattern Language 轻量版（参考 ImHex）

- **为什么**：CTF 解结构数据刚需（magic/长度字段/偏移数组），解码实验室管解码不管「布局」。
- **入口提示**：先做 10% 子集——整数（LE/BE）/定长数组/字符串/指针跳转，放在 ⊞ 内存 HEX
  面板叠加渲染；声明式 JSON 而非 ImHex 的自有语言（学习成本为零）。
- **预估**：3–5 天。
- **启动信号**：做题时又在纸上画十六进制布局的时候。

## 3. pycdc 集成（.pyc → 源码）

- **为什么**：PyInstaller 解包已闭环（v0.4.0），最后一环是 pyc 反编译——现在出口是「复制
  路径 → 开 PyLingual/pycdc」两段式。
- **入口提示**：pycdc 是 C++，两条路——①子进程调用户自装的 pycdc 二进制（`lvr doctor`
  探测）；②等社区 wheel。①先做，入口放在解包条目预览页。
- **预估**：1–2 天（路线①）。
- **启动信号**：做题又碰到 `.pyc` 想偷懒的时候。

## 4. x64dbg 桥

- **为什么**：Windows PE 的 mature 调试器（脚本/图形化/插件生态）；gdb 桥在 Windows 上
  是 mingw gdb，体验有差距。
- **入口提示**：复刻 gdb 桥的架构（传输层/会话/状态机/前端页签）；x64dbg 无 headless MI，
  要走其脚本插件（x64dbgpy 或命令管道）——比 gdb 桥费劲。
- **预估**：3–5 天 + 插件调试的坑。
- **启动信号**：某道 Windows 题用 mingw gdb 明显卡壳（如 interrupt 不可用这类）而
  x64dbg 能解的时候。已知的第一个 such case：`-exec-interrupt` 对原生目标无效
  （dev-notes #36）。

## 5. patch 跨会话持久化

- **为什么**：⤓ 写回副本（v0.5.0）已覆盖「要一个能跑的补丁文件」；跨会话补丁历史
  （重新打开样本自动重放补丁）是锦上添花。
- **入口提示**：补丁历史存 `_lvr/patches.json`（addr/static bytes），打开样本时问一句
  「发现 N 条历史补丁，重放？」——必须问，静默重放会吓人。
- **预估**：1 天。
- **启动信号**：做题时真的因为「忘了上次补了哪」而重复劳动的时候。

## 6. 环境验证补口子

- **裸机 Linux 动态调试**：WSL（真实 Linux 内核 + 本机 gdb）已在 v0.5.0 全链实测；裸机
  发行版理论上等价，剩口子是「诚实」而非功能。
- **macOS**：零验证。Ghidra 引擎跨平台，风险点在路径发现与 gdb 传输。
- **启动信号**：有对应机器在手边的时候，半天收掉。

---

## 已知环境怪癖备忘（详见 dev-notes #32–#37）

- Ghidra 12.2 需要 **JDK 25**（class file 69.0），21 会 UnsupportedClassVersionError
- WSL：Ghidra 工程别放 /mnt/*（9p 随机写极慢）；LaunchSupport 间歇静默 rc=1 可用
  pyghidra `launcher.java_home` property 绕过；wsl.exe 会话退出杀进程要 setsid
- Windows 本机 gdb 的 `-exec-interrupt` 对原生目标无效（sync 模式限制）
