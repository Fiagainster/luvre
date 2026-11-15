#!/usr/bin/env python3
r"""ch20 解题脚本 — 种子哈希 + 异或消去推密码（writeup-ch20.md §7 的本地版）。

替代"往浏览器 console 粘 JS"：同样的两步算术，本地 Python 一次跑完，
并自带校验循环回验（模拟 crackme 的比对逻辑，确认推出的密码能通过）。

用法（二选一）：
  1. 文件输入：把从 luvre HEX 面板 ⧉ 复制 / 解码实验室拿到的代码字节 hex
     存成文本文件（允许混有空格、换行、0x 前缀），然后
       python solve_ch20.py ch20_code_hex.txt
  2. 直接粘贴：python solve_ch20.py --hex "b8040000..."

常用选项：
  --len N      只取前 N 个字节（默认 163，即 ch20 的代码段长度）。
               拉多了会自动钳制并警告——从 0x08048000 起拉会把 ELF 头
               一起带回来（291 B），不钳制种子就算错了。
  --seed HEX   跳过哈希直接指定种子（想验证 A 表或密码推导时用）。
  --a HEX      覆盖 A 表（默认内置 ch20 的 25 字节表）。

预期输出：seed = 0xac77e166，密码 HardW@re_Br3akPoiNT_r0ckS，末尾 CHECK PASS。
"""

import argparse
import re
import sys

# Windows 控制台默认 GBK/CP936，Git Bash 里会变成乱码；统一按 UTF-8 输出
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# ch20 的 A 表：HEX 面板 0x08049155 起的 25 字节（writeup §5）
DEFAULT_A = ("1e cd 2a d5 34 87 fc 78 64 35 9d ec de 15 ac 97 99 af 96 da"
             " 79 26 4f 32 e0")
DEFAULT_LEN = 163  # FUN_08048115 的哈希范围 [0x08048080, 0x8048123)


def rol32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def ror32(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def parse_hex(text, what):
    """宽松解析：容忍空格/换行/逗号，也认 ⧉ 复制的 hexdump 格式。

    hexdump 行长这样（地址前缀 + ASCII 列都要剥掉，否则地址字节会混进数据）：
      0x08048080  b8 04 00 00  ...  |....|
    """
    cleaned = []
    for line in text.splitlines():
        line = line.split("|")[0]  # 丢掉 hexdump 的 ASCII 列
        m = re.match(r"\s*(0x[0-9a-fA-F]+)", line)
        if m:  # 行首是地址前缀 → 剥掉
            line = line[m.end():]
        cleaned.append(line)
    s = "".join(ch for ch in " ".join(cleaned).lower() if ch in "0123456789abcdef")
    if len(s) % 2:
        sys.exit(f"{what}: 奇数个 hex 字符（{len(s)}），检查复制是否截断")
    return bytes.fromhex(s)


def hash_seed(code):
    """FUN_08048115 的忠实复刻（writeup §4）。

    关键：add cl,[eax] 只动 ECX 低 8 位，rol ecx,3 把高位绕回低位——
    所以每轮从"当前 S 的低 8 位"加起，不能把 cl 当独立累加器带出循环
    （那样会算出假种子 0x3C283DD3）。
    """
    s = 0
    for b in code:
        lo = ((s & 0xFF) + b) & 0xFF          # add cl, [eax]
        s = rol32((s & 0xFFFFFF00) | lo, 3)   # rol ecx, 3
    return s


def derive_password(seed, a_bytes):
    """校验循环的逆写（writeup §2）：input[j] = A[j] ^ low8(ror32(seed, 25-j))。

    j 从 25 数到 1、每轮先右旋再比；换成 0 起下标 c = 0..24 即 25-c。
    """
    return bytes(a ^ (ror32(seed, 25 - c) & 0xFF)
                 for c, a in enumerate(a_bytes))


def verify(seed, a_bytes, pw):
    """按 crackme 原逻辑正向回验：A[j] ^ input[j] 应等于旋出的低 8 位。"""
    s = seed
    for j in range(len(a_bytes), 0, -1):
        s = ror32(s, 1)                       # 每轮先旋 1 位
        if a_bytes[j - 1] ^ pw[j - 1] != s & 0xFF:
            return False, j
    return True, 0


def main():
    ap = argparse.ArgumentParser(
        description="ch20 种子哈希 + 异或消去推密码（本地版）")
    ap.add_argument("file", nargs="?", help="含代码字节 hex 的文本文件")
    ap.add_argument("--hex", dest="hexstr", help="直接给代码字节 hex")
    ap.add_argument("--len", type=int, default=DEFAULT_LEN,
                    help=f"取前 N 字节（默认 {DEFAULT_LEN}）")
    ap.add_argument("--seed", help="跳过哈希，直接指定种子 hex")
    ap.add_argument("--a", help="覆盖 A 表 hex（默认 ch20 的 25 字节）")
    args = ap.parse_args()

    # ── 1. 代码字节 ──
    if args.hexstr:
        raw = parse_hex(args.hexstr, "code hex")
    elif args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw = parse_hex(f.read(), "code hex")
    else:
        ap.error("给一个 hex 文件路径，或用 --hex 直接粘贴")

    n = args.len
    if len(raw) > n:
        print(f"[warn] 输入 {len(raw)} 字节 > 需要的 {n} 字节，已钳制前 {n} 字节。"
              f"（若从 0x08048000 起拉，会混入 ELF 头——确认起点是 0x08048080）")
    code = raw[:n]
    print(f"[*] 代码字节：{len(code)} B（头 {code[:4].hex()} 尾 {code[-3:].hex()}）")

    # ── 2. 种子 ──
    if args.seed:
        seed = int(args.seed, 16)
        print(f"[*] 种子（外部指定）= 0x{seed:08x}")
    else:
        seed = hash_seed(code)
        print(f"[*] 自哈希种子 = 0x{seed:08x}")
        if seed == 0x3C283DD3:
            print("[!] 这是 §4 里那个假种子——cl 被当独立累加器了，检查 hash_seed")

    # ── 3. A 表 + 推密码 ──
    a_bytes = parse_hex(args.a, "A 表") if args.a else parse_hex(DEFAULT_A, "A 表")
    print(f"[*] A 表：{len(a_bytes)} 字节")
    pw = derive_password(seed, a_bytes)
    try:
        pw_text = pw.decode("ascii")
    except UnicodeDecodeError:
        pw_text = pw.hex()
        print("[!] 密码不是纯 ASCII（种子或 A 表有误？），给出 hex：" + pw_text)
    print(f"[+] 密码（{len(pw)} 字符）：{pw_text}")

    # ── 4. 正向回验 ──
    ok, at = verify(seed, a_bytes, pw)
    print("[+] CHECK PASS — 与 crackme 校验循环逐位一致" if ok
          else f"[!] CHECK FAIL @ j={at} —— 种子或 A 表不对")


if __name__ == "__main__":
    main()
