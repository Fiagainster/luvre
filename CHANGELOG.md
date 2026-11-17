# 更新日志 / Changelog

所有显著变更记录在此。格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本遵循语义化。

## [0.5.1] — 2026-11-18

README 与评估文档随 v0.5.0 的收尾打磨（代码无变更）。

### 变更
- **README 图片改 GitHub 绝对地址**：PyPI 的 readme_renderer 会剥离相对路径 `<img>`——
  PyPI 项目页此前一张图都看不到（GitHub 上一直正常）。改绝对 URL 后随本版本生效
- **evaluation.md 刷新到 v0.5.0 时点**：测试数 253+7、发布成熟度（PyPI/GIF 已落地）、
  已知债更新（app.js 已拆模块、Linux 宿主已实测）
- **新增 docs/backlog.md**：搁置中的大件归档（结构体编辑/Pattern Language/pycdc/
  x64dbg 桥/patch 持久化/环境验证口子），每项带「为什么/入口提示/预估/启动信号」，
  按做题需求拉动、不预投入；README 路线图指向该文件

## [0.5.0] — 2026-11-18

gdb 动态链补完最后一公里：内存补丁（NOP/写字节/一键还原/写回样本副本）+ 条件断点（条件/ignore-count）+ ASLR 静态↔运行期换算器 + 线程面板 + 前端按域拆模块 + 本地 API 防护。全程以真实样本 UI 实操验证——ch20.bin（WSL gdb）、challenge1.exe（本机 gdb，DYNAMICBASE/ASLR）、ch18/ch16 静态、WSL Ubuntu-22.04 真实 Linux 宿主全链（dev-notes 踩坑 #32–#37）。

### 新增

- **gdb 内存补丁面板**（⚙ 动态调试页签）：NOP 填充（x86 `0x90`，字节数可调）与原始字节写入（hex），走 MI `-data-write-memory-bytes`——经 gdb 落地，断点陷阱与指令缓存自动一致，停中打完补丁直接放行验证；写完自动回读上方内存面板做可视确认。全流程实测：ch20（ELF/WSL）NOP 掉 `jne` 失败分支，错误输入走到 `Well done man` 成功分支；challenge1.exe（PE/本机，**ASLR 下**）以运行期重算地址 NOP 掉 strcmp 后的 `jne`，错误输入打印 `Correct! You got the flag!`
- **gdb 条件断点**：断点输入旁新增条件框（gdb 表达式，如 `$ebx==0x37`），走 `-break-insert -c`；`/api/gdb/break/cond` 可对既有断点附加/清除条件（`-break-condition`）；断点表以琥珀 chip 展示条件，pending 断点重放同样携带条件。实测 ch20 哈希环 `$ebx==0x37` 精确命中第 108 字节（寄存器 ebx=0x37 面板可证）
- **前端按域拆模块**（零构建多 script 方案，非 ES module）：app.js（2933 行单体）拆为 `app-core`（helpers/弹窗/右键菜单/全局状态）· `app-decoder`（解码实验室）· `app-graph`（调用图）· `app-gdb`（动态调试）· `app-workstation`（工作台面板）· `app-boot`（boot 接线）六个文件，共享全局词法作用域，加载顺序由 index.html 固定；全部通过 node 拼接重复声明检查与真实浏览器 boot 冒烟
- **本地 API 防护（Origin/Host 校验）**：带 `Origin` 头的请求必须与 `Host` 同源，回环绑定时 `Host` 必须是回环名——关死「任意网页对 localhost API 发 no-cors POST」的 drive-by 与 DNS rebinding 两扇门；非浏览器客户端（curl/测试）不送这两个头、不受影响。实测：恶意 Origin 的 GET/POST `/api/open` 与伪造 Host 全部 403
- **JobFarm 完成任务淘汰**：done/error 任务 30 分钟 TTL + 200 个硬上限，spawn 时惰性清扫——长会话的 job 字典不再无限增长
- **API 健壮性**：畸形/非 UTF-8 请求体现在返回干净的 400（附原因），不再 500 + 堆栈刷日志
- **ASLR 静态↔运行期地址换算器**：gdb 页签贴静态或运行期地址自动互转、点击结果一键填入补丁地址。基址解析双源自适应——Linux gdb 走 `info proc mappings`（首个本模块映射 start−offset），mingw gdb 对该命令报 "Not supported on this target" 则回落 `info files` 节区行与静态节表配对求 delta。实测：challenge1.exe（每次运行基址不同）换算值与 entry point 实际运行地址核验一致；ch20.bin（非 PIE）delta=0 自洽
- **补丁一键还原（↩）**：每次写补丁前先读原始字节作还原凭据，↩ 写回上一次补丁前的字节（还原失败凭据不丢）。实测：NOP → ↩ → 内存面板 `75 1b` 回归 → 放行程序恢复判错
- **补丁写回样本副本（⤓）**：把本会话全部补丁经节表映射（vaddr→file offset，仅文件-backed 区域，.bss 报 unmapped）写进 `_lvr/patched/<样本名>_patched_<ts>` 副本——原文件永不触碰。实测：challenge1 补丁副本脱离调试器独立运行打印 `Correct! You got the flag!`，原件同输入 `Wrong flag!`
- **断点 ignore-count**：「跳过N次」输入走 `-break-after`，断点表显示 `skip N`。实测：ch20 哈希环 skip=3 → 第 4 次命中时 ebx=0xa0（163−3），数学精确
- **线程面板**：`-thread-info` 列出线程 chips（当前线程高亮、帧函数名随行），点击即 `-thread-select` 切换。实测：challenge1 真实双线程目标（T1@strcmp + T2@ntdll 工厂）正确显示
- **gdb 传输选择记忆**：localStorage 记住上次的传输选项——reload 后静默回落默认值曾让本机 gdb 工作流悄悄变成 WSL 会话（实操捕获）
- **demo GIF**：`docs/screenshots/demo.gif`（解题全流程：反编译 → 断点 → ASLR 换算 → NOP → Correct → 解码实验室出 flag）

### 修复

- **重跑已退出的目标后所有停靠状态显示为「正常退出」**（ch20 实测捕获）：`-exec-run` 的 `^running` 只置 running=True 不清 exited 标志，渲染层 exited 优先级最高——条件断点命中被永久盖成「正常退出」、寄存器面板不出现。修法：running 转换时清除 exited（目标运行中即非已退出）；fake gdb 回归测试固化
- **`*0x…` 写进内存表达式被 gdb 当解引用**（ch20 实测捕获）：`-data-read/write-memory-bytes` 的 ADDRESS 是表达式上下文，断点语法的 `*` 前缀在这里意味着「取该地址的内存内容当地址」——`*0x080480d9` 静默变成 `Cannot access memory at address 0x75491b75`。后端 `_addr_expr()` 统一剥引导 `*`（读写两处），patch 输入框 placeholder 改为表达式写法
- **断点条件输入框残留**（challenge1 实测捕获）：加断点只清位置框不清条件框，上一个断点的 `$eax==0` 静默粘到下一个无条件断点上——看起来没条件，其实有。修法：bp-add 成功即清两框
- **刷新页面后 stale 会话提示丢失**（challenge1 实测捕获）：切样本后页内 open 路径有「会话仍指向旧样本」提示，但刷新恢复路径没有——启动按钮被隐藏且零解释，而后端明明支持一键自动切换。修法：stale 检查并入 1.2s 轮询渲染层（同一目标只提示一次），open 与 reload 两条路径都覆盖
- **gdb 内存面板把 hex 表达式的回读显示成 0x00000000 起**：patch 回读看起来像「写到了地址 0」——纯 hex 地址表达式现在显示真实地址，符号表达式（$rsp）保留相对编号
- **gdb 页签栅格不可收缩把控制台挤出视口**（demo 录制捕获）：补丁带下移后栅格改了不可收缩变体，程序输出滚出屏幕——改回可收缩 + 最小高度，720p 下三列与控制台/补丁带同屏
- **多位置断点表渲染空行**（gdb 把同符号多处命中折叠成 `<MULTIPLE>` 时，无 func/addr 的子条目渲染成只有 ✕ 的空行）——过滤无内容条目
- **GdbSession.exit 关闭 stdin/stdout/stderr 管道**——reader 线程干净收尾，消除 ResourceWarning

## [0.4.4] — 2026-11-15

PyPI 正式上线 + 真题审计打磨：解码实验室 XOR 结果区三层布局连环坑根修（叠画→压瘪→压成 9px 残条）、boot 静默失联自检、README 立场改写、ch20 复现手记全事实化（逐条对照工具重验 + 本地解题脚本 + int 0x80 读法教学）。

### 新增

- **PyPI 正式发布**：`pip install luvre` 可装（[pypi.org/project/luvre](https://pypi.org/project/luvre)）。发布链路走 GitHub Actions Trusted Publishing（OIDC 免 token）——`.github/workflows/publish.yml` 监听 release published 事件：自动构建 sdist + wheel → 产物挂回 Release → 上传 PyPI；手动 dispatch 带 dry_run 开关可只验证构建
- **README 个性化改写**：新增「为什么 2026 年还手搓？」立场段（AI 军备竞赛的现实、No AI inside 的本地哲学、"AI 结对开发拒绝代劳工具"的自嘲）；名字故事补全克苏鲁旧梗；引言加一句结对开发 hook
- **ch20 解题脚本 `docs/scripts/solve_ch20.py`**：种子哈希 + 异或消去推密码的本地 Python 版（纯标准库），自带校验循环回验；输入格式容错（纯 hex / 空格分隔 / ⧉ hexdump 带地址列均认），超长输入自动钳制并警告（0x08048000 起会混入 ELF 头的 footgun），假种子 0x3C283DD3 出现时直接提示回查 §4。附 `ch20_code_hex.txt`（.text 163 B）供不开样本验证脚本
- **boot 自检**：启动接线是一条长异步流，中途抛异常时后续按钮静默失联（表象就是"点了没反应"）——独立于 boot 的顶层延时检查六个关键按钮，接线不全时弹红色 toast 指名失联清单并提示刷新，不再无声死掉

### 修复

- **解码实验室 XOR 结果区三层连环坑（真·看不见，不是观感问题）**：①结果区出现后 flex 把 `.decoder-grid` 压瘪，第一列按钮排溢出 grid 盒子往下画、叠在结果行与状态栏上——解码页签改为可整体滚动、grid 禁止收缩（`flex: 1 0 auto`）、输入框保底 96px；②但 grid 禁缩后结果区成了列里**唯一的可收缩滚动容器**，flex 把它压成 9px 残条——内容全被裁掉、页签又因"刚好塞下"不出滚动条，表象变成"结果生成但完全看不见、滚动条拖不动"——结果区 `flex-shrink: 0` 根修，空间不够时页签真正滚动；③结果区弹出时 `scrollIntoView(nearest)` 自动滚到可见位置。另加标题栏（「XOR 爆破结果 · 计数」+ **✕ 关闭**按钮，此前没有任何关闭手段）
- **裸反汇编地址列溢出**：`.ln` 固定 44px 装不下 10 字符地址（`0x08048080`），右溢 20px 压住字节列成"缝合怪"——raw 视图地址列加宽到 76px
- **HEX 工具栏纯符号按钮可发现性为零**：⚗/⚡/⧉ 只有 hover title，用户找不到"发送按钮"——补可见文案（zh：⚗ 解码 / ⚡ 反汇编 / ⧉ 复制；en：decode / disasm / copy）；块选择器上限 22ch→17ch、右侧信息条可收缩，加宽后工具栏不再溢出
- **XOR 分数列左对齐参差**（100/99.5/96.7 锯齿）改右对齐；解码输出编码下拉的 title 缩短为一行
- **`writeup-ch20.md` 重写**：逐条对照真实 UI 重做——§1 改为字符串面板的真实 5 条输出（1 台词 + 4 节名垃圾）并解释 Ghidra 为何漏台词（NUL 终结符边界）；§3 补 int 0x80 读法（调用号/参数寄存器约定、逐字汇编示例、32 位 `int 0x80` 与 64 位 `syscall` 两张表不可混用、调用号翻译暂不代劳的诚实边界）；§5 修正 A 表地址（0x8049155，0x8049154 是换行符）；§6 重写为真实按钮流程（一页 163 B 无需 Shift、(163 bytes) 标签核对、291 B footgun）；§7 从"浏览器 console 粘 JS"改为本地 Python 脚本；全文解释链补齐"为什么这一步这么走"

## [0.4.3] — 2026-11-15

改名发布：lovelyreverse → luvre（取证圈已有成名的 Lovely* 工具系列，同社区同前缀易被误认为同族产品）。luvre 读作卢浮宫（把二进制当藏品上台解剖）。

### 变更

- **项目更名 lovelyreverse → luvre**：CLI `lvr` 与端口 7331 均不变；数据目录 `%LOCALAPPDATA%/luvre`（`~/.luvre`）首次运行自动从旧名迁移；≤0.4.2 的历史发行包仍叫 `lovelyreverse-*`。爱心吉祥物与配色不受影响（本就无字）；README 五张截图随新品牌重拍（英文深色 ×3 / 中文亮色 ×2）
- **gdb 传输选项按宿主自适应**：`/api/gdb/env` 补 `platform` 字段；POSIX 宿主的前端删掉 WSL 选项与发行版输入框，「Windows 本机 gdb」改标「本机 gdb（PATH）」并默认 local；Windows 无 WSL（`wsl_ok=false`）同样收敛。`gdb_start` 加 POSIX 硬闸兜底（stale 页面/裸 API 传 `wsl` 直接报错），探测中轮询不再叠加同步重探
- **README/发行形态说明**：前置要求新增 gdb 可选项 bullet（仅动态调试需要），便携版说明注明其只覆盖静态链、动态调试始终需宿主自备 gdb

### 修复

- **CI Ubuntu 全挂（v0.4.0 起三个版本）**：`mbcs` 是 Windows 专属 codec 名，io_encoding 原逻辑「wsl=utf-8 / 其余=mbcs」在 POSIX 上选到它必炸——ubuntu runner 自带真 gdb，本机传输真实可达，写 MI 行时 `LookupError: unknown encoding: mbcs`。改为一行条件：POSIX 一律 utf-8（dev-notes #31）
- **gdb tab 漏 `data-i18n`**：EN 界面中心 tab 栏残留中文「动态调试」——补属性，并统一 ⛭ 齿轮符号

## [0.4.2] — 2026-11-15

真题两轮（Root-Me ch13/ch18/ch20 纯 UI 做题暴露的短板；复现手记 `docs/writeup-ch13.md`、`docs/writeup-ch20.md`，dev-notes 踩坑 #27–#30）。

### 新增

- **gdb 命令框**：控制台上方输入任意 gdb CLI 命令，走 MI `-interpreter-exec console` 直达（`handle SIGTRAP nostop pass` 放行自陷样本、`x/16xw`、`info proc mappings`…）——ch13 自陷型样本的唯一钥匙
- **HEX 多页送解码实验室**：Shift+发送一次连取最多 8 页自动拼接（块尾 clamp）——自哈希样本要 163 字节完整代码段，单页 chunk 不够
- **解码实验室输出编码切换**：utf-8 / gbk / latin-1（字节保真）下拉，非 UTF-8 样本不再一屏 FFFD
- **HEX 复制按钮 ⧉**：当前窗口数据导出为标准 hexdump（`0x%08x  hex |ascii|`）
- **gdb 切样本自动重启会话**：旧会话指向别的程序时自动退出重启，前端给出 stale 提示——不再被 "already active" 静默吞掉启动点击

### 修复

- **gdb 控制台中文路径 mojibake（根修）**：WSL gdb 的 MI C 字符串里 raw UTF-8 字节与 `\xHH`/`\NNN` 转义混编，行级 UTF-8 先行解码把多字节序列拦腰截断 → reader 改 latin-1 字节透明读，unescape 字节级收集后按传输编码统一 decode（dev-notes #27，test_mi 8 例回归固化）
- **HEX 输 unmapped 绝对地址倍地址读失败**：0x08049120 被当块内偏移原样发送（实际请求 ram:10091120）→ 前端先定位所属块换算；查不到则 toast 列出可读范围，不再发注定失败的请求
- **裸 `python -m lovelyreverse` 启动崩溃**：顶层 Namespace 缺 serve 子命令默认值（AttributeError: ghidra）→ `_normalize_argv` 补 serve 前缀，`-h/--help/--version` 白名单放行
- **wsl 探测炸 Popen 内部 reader 线程**：`wsl.exe` stderr 的 UTF-8 中文警告按 locale GBK 严格解码 → UnicodeDecodeError 出在不可捕获的 `_readerthread` 线程；subprocess 显式 `encoding="utf-8", errors="replace"`（wsl 两处 + java -version 一处）（dev-notes #29）
- **ELF section 名全显示 undefined**：binfile 解析器从不读 `.shstrtab` → 解析 e_shstrndx 两遍定位（非法索引回退首个 STRTAB），名字与 overlay 计算解耦
- **gdb stdin 投递语义不明**：placeholder 注明「仅会话启动时投递一次，改动需重启会话」
- **gdb 控制台三处显示问题**（ch13 手记）：目标退出后停留旧视图 → exited 态也刷新列表/控制台；程序 stdout 与 MI 流交错被归类 noise 隐藏 → 去前缀按程序输出直接显示；上一个文件的函数过滤器残留 → 打开新文件时清空

### 真题验证

- **ch13**（884 B 裸 syscall 汇编，signal 链 + XOR 解密）：裸反汇编避花指令 + 解码实验室一条链解 484 B → 密码静态解出 → gdb 命令框放行 SIGTRAP 动态闭环（[writeup-ch13.md](https://github.com/Fiagainster/luvre/blob/main/docs/writeup-ch13.md)）
- **ch20.bin**（Root-Me 自哈希 crackme，732 B）：裸反汇编读出 syscall 骨架 → HEX 多页拉满 163 字节代码 → 页内算种子 **0xAC77E166** → 直推密码 **`HardW@re_Br3akPoiNT_r0ckS`** → gdb 桥喂 stdin 动态闭环成功
- **ch18.bin**（VM opcode 型，5 KB）：纯 UI 解出；strace 实证程序任何输入下零 write——成败只能靠 gdb 内存确认（dev-notes #28）

## [0.4.1] — 2026-11-14

真题打磨（Root-Me KeygenMe by int_0x80 全程工具化做题暴露的短板）。

### 新增

- **指令级单步 ⇣| 指令 / →| 指令**：strip 样本上 gdb 行级 `step` 报 "Cannot find bounds of current function"，补 `-exec-stepi` / `-exec-nexti`（带 stop 态守卫）
- **gdb 环境变量启动参数**：启动表单新增 env 输入（逗号分隔 KEY=VALUE，含空格值自动加引号）——GTK 等 GUI 样本需要 `DISPLAY=:99` 才能进 WSL 调试

### 修复

- **裸反汇编向后余量**：读取窗口向前扩最多 512 B（入口按指定地址起扫）。混淆样本的 call-实为-jmp 目标常落在命名入口前几个字节（Root-Me 的 0x804935c 首条即 `jmp 0x8049355`），旧实现窗口从入口开扫，第一条向后 JMP 就断流；现在接力解码跨过向后跳转直达 ret。顺带修正：JMP 直落 ret 时终止原因误报 "窗口结束" → 现报 "ret"
- **`disasm-raw` 地址运算**：Ghidra GenericAddress 不支持减 int，统一走 `getOffset()` / `subtract()`（上一条修复引入的回归）
- **运行态查询快速失败**：同步模式 gdb 在目标运行时执行 MI 命令会挂满超时——断点列表现在先查运行态直接报错，不再卡前端 25 s
- **CLI 控制台编码**：启动时把 stdout/stderr 重配为 UTF-8（errors=replace）——GBK 控制台打印 gdb 输出中的替换字符会炸请求线程

## [0.4.0] — 2026-11-13

**动态调试上线**：gdb 桥打通 Windows（mingw gdb 17.2）与 Linux（WSL gdb 12.1）双侧，APK 静态分析落地。

### 新增

- **⚙ 动态调试页签**：会话启动（当前样本自动装载）/ 断点（*地址 或函数名，**会话前放置的断点进 pending 队列，启动自动补挂**）/ 运行·继续·单步·出函数·**中断**（fgets 阻塞等运行态可用）/ 写寄存器与表达式（`$rax = 0` 绕反调试）/ 全寄存器面板（PC 玫瑰高亮，点击复制）/ 调用栈 / 内存读取（$rsp、任意表达式，一键送解码实验室）/ gdb 控制台实时输出
- **双传输**：`WSL · Linux ELF`（wsl.exe gdb 12.1）/ `Windows 本机`（mingw gdb 17.2），同一 MI 实现
- **程序参数与 stdin 暂存**：fgets/scanf 类 crackme 的喂输入场景
- **APK 静态分析**：zip 解包（遍历防护）落盘 `_lvr/unpacked_apk/`；**dex string pool 提取**（uleb128 + MUTF-8，纯 stdlib）——类名/URL/密钥一眼可见，一键复制/送解码实验室

### 真题验证

- **Linux（WSL）**：自编 ptrace 反调试 crackme —— 断点命中 → `$rax=0` 绕过 → strcmp@plt 偷 serial `345`，全链路 5.8s
- **Windows**：challenge1.exe —— base64_encode 符号断点 → 寄存器取参 → 内存偷 XOR 缓冲（key 0x12 实测推导）→ ucrtbase!strcmp 偷硬编码密文 → 解出 flag（xor_base64_easy）
- **APK**：合成样本 6 条目 + 2 dex，类名/C2 URL/密钥全数提取

### 修复

- GDB/MI 解析：const 停字符集缺 `=`/`{` 导致 `frame={...}` 列表炸掉；补 hex 转义解码
- `^running` 是结果记录而非异步记录——mingw 同步模式下运行态迁移必须在此处
- Windows gdb stdio 是 ANSI(GBK)：io_encoding 按传输选择（wsl=utf-8 / local=mbcs）；程序路径走 gdb argv（CreateProcessW 宽字符），MI stdin 传中文路径必炸；样本复制到 %TEMP% 会被 Defender 吞（ThreatID 2147958378 实录）
- IFUNC 断点迁移：`break strcmp` 会被 gdb 挪进 libc 实现并在 glibc 初始化期误触——做题时应断 `*strcmp@plt`
- WSL /tmp 在 VM 重启后清空——fixture 编译产物放持久目录

## [0.3.3] — 2026-11-12

### 新增

- **⚡ 裸反汇编（混淆兜底，把手解码交给工具）**：反编译被重叠指令 / CALL-实为-JMP / 反调试打断时，不再需要切 HEX 视图逐字节手解码。新页签从任意地址起，capstone 按真实执行流解码：
  - 无条件直接 JMP 跟随目标，不取 fall-through；条件跳转按 fall-through 走
  - **CALL 实为 JMP 识别**：callee 以向后直接 JMP 开头（丢返回地址的混淆签名）时跟进 callee，压栈的返回地址标记「死返回」跳过，不再落进垃圾字节
  - 反调试垃圾字节（int3/ud2/不可解码）自动恢复到最近条件跳转的目标（最多 16 次），恢复点在列表中标注
  - 终止原因页脚（ret / 垃圾 / 间接跳转 / 环 / 上限），跳转目标可点击跟进；HEX 视图 ⚡ 一键从当前字节起解
  - 纯 capstone 实现（`disasm.py` 纯模块 + 引擎 `disasm_raw` + `/api/disasm-raw`），Ghidra 反编译器对重叠指令的污染完全绕开；真样本验证：Root-Me KeygenMe 一键还原全部 142 条真实执行路径（3 处 RDTSC 反调试、7 处死返回、imul 主循环全数命中）

### 修复

- **HEX 跳转框输入完整 vaddr 误按块内偏移**：只检查当前块包含关系，跨块地址（如 ELF 头块里输 `.text` 地址）读越界报错 → 在全部内存块中定位包含该地址的块并自动切换
- **HEX 跳转框不支持回车**：只能点按钮 → 补 Enter 键绑定（与裸反汇编地址框一致）
- **程序加载后空态文案 stale**：中央面板在程序加载后仍显示「先打开一个二进制…」引导文案 → `loadProgram` 装完数据即换成「从左侧选择一个函数」（首次 wipe 后 `code.empty.dec` 无人恢复的遗留）
- **跳转框输入函数名无直达**：名字分支只过滤左侧列表、中心区不动，看起来像没反应 → 精确命中直接选中该函数进反编译；过滤后唯一命中也自动选中

### 实战验证

- Root-Me KeygenMe（重叠指令混淆 GTK2 ELF）全链路浏览器手操解出：反编译被混淆污染时以内存 HEX 视图逐字节手解码兜底，`serial = Σ name[i]^(i+2) mod 2⁶⁴`；**该手解过程随即被自动化为本期 ⚡ 裸反汇编功能**（离线 6 地标 + 浏览器 E2E 全通过）；链路与踩坑入档 docs/dev-notes.md

## [0.3.2] — 2026-11-12

通宵真人手操实测版：以浏览器手操方式把 10 个题库样本全链路过一遍（做题链 → 调用图 → 解码实验室 → 解包），发现的体验/交互/功能问题就地修复。

### 修复

- **xref 卡片文字重叠**：`UNCONDITIONAL_CALL` 等 Ghidra 长类型名溢出固定列盖住地址 → 映射为短标签（CALL/DATA/PTR…），完整名保留在悬浮提示
- **检查器标题 `0X` 大写**：`text-transform: uppercase` 污染地址显示 → 地址豁免，恢复 `0x` 小写惯例
- **空态文案矛盾**：未加载程序时中央提示「从左侧选择一个函数」而列表为空 → 未加载时改为打开引导文案
- **解码实验室参数失同步**：处理链参数绑 `onchange` 依赖失焦时序，快速输入后立即执行拿旧参数 → 改绑 `input` 逐键同步
- **重命名后伪代码不刷新**：标题/函数列表同步但代码体仍是旧签名 → 改名后自动重新反编译当前函数
- **切样本搜索残留**：统一搜索关键词跨样本残留 → 切样本即清空输入框与结果区
- **函数列表滚动竞态**：快速滚动到底触发重叠 append 导致行重复 → in-flight 守卫；append 失败不再静默
- **签名命中不可解释**：搜 "flag" 命中 `__nh_malloc`（签名含 `_NhFlag`）看似错报 → 命中行下显示签片段落
- **解包 pyc 无处可拿**：非可执行条目预览只有警告 → 显示 `_lvr/unpacked` 落盘完整路径 + 一键复制（做题链闭环）
- **送解码实验室字节数不更新**：送入后大小标签保持旧值 → 立即按模式计算显示

### 实测覆盖

challenge1 / c_sm4（SM4 S-box 命中）/ pyre（解包 68 条目）/ crackme_easy（字符串锚点→精确行高亮）/ flower（685 函数滚动加载）/ MazE（ELF）/ ez_debug（4047 函数，1.6MB 尾巴正确识别为 COFF 符号表）/ Ferris（熵 7.93 判疑似加壳）

## [0.3.1] — 2026-11-11

六项做题反馈批量修复：打开残留/卡顿、xref 置顶卡片、统一搜索 + 解码预设、解包链根因、上传语义。

## [0.3.0] — 2026-11-11

- **做题链联动**：查壳结论面板（干净/疑似加壳 + 下一步提示）、字符串单击查引用/双击跳进反编译精确行、导入点击直达调用者
- **全站右键菜单 v2**：10 类对象（反编译符号/选中文本/xref 行/常量行/函数行/字符串/导入/导出/搜索结果/汇编行）
- **工程目录迁移**：Ghidra 工程移到样本同级 `_lvr/`，C 盘不再增长

## [0.2.1] — 2026-11-11

- `lvr doctor` 一键体检 + 首次启动 fail-fast 检查
- 修复：打开失败后 Ghidra 工程 lock 泄漏（坏样本不再堵死引擎）

## [0.2.0] — 2026-11-11

- **中文界面**（默认中文，⚙ 一键切 English）+ **浅色主题**（石墨玫瑰暗色保留），偏好本地记忆
- 函数重命名 + 备注（伪代码内即时同步）
- 最近打开历史、一键送解码实验室、快捷键（g 跳转、/ 过滤、1-4 页签、n 重命名、m 备注、? 帮助）
- 窄屏自适应

## [0.1.0] — 2026-11-11

首个可用版本。

- **分析核心**：PyGhidra 进程内驱动 Ghidra——函数列表 / C 伪代码（标识符可点击跳转）/ 汇编清单 / 内存十六进制 / 字符串 / 导入导出 / 交叉引用
- **调用图**：Ghidra 式层次布局（caller 上 / callee 下，重心排序减少交叉），双击节点增量展开
- **加密常量识别**：40+ 签名（AES/SM4/SM3/MD5/SHA/TEA/Blowfish/Camellia/ChaCha/Base64/CRC/ECC），大小端自动展开，命中归属函数
- **解码实验室**：28 种操作链式叠加 + XOR 单字节爆破 + 已知明文推密钥
- **文件分诊**：纯 Python PE/ELF 解析、逐节熵、Overlay 附加数据检测（MinGW COFF 符号表误报排除）
- **批量反编译**：全函数导出 zip
- 测试：92 单元/服务层 + 真实 Ghidra 引擎集成测试
