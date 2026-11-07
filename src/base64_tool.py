#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF 杂项小工具：Base64 编解码 / 多层自动剥壳

用法:
    python base64_tool.py -e "hello"                  # 编码
    python base64_tool.py -d "aGVsbG8="               # 解码
    python base64_tool.py -d -f flag.txt              # 从文件读入再解码
    python base64_tool.py --auto "VmpK..."            # 一层层解到底
    python base64_tool.py -r "cvpbPGS{...}"           # ROT13（正反同一场）
    echo "aGVsbG8=" | python base64_tool.py -d -      # 从标准输入读

为什么不用 `base64 -d` 就够？
  1. 缺 padding 时系统命令直接报错，这里会自动补齐
  2. URL-safe 变体（- 和 _）系统命令不认，这里会自动归一
  3. 多层嵌套要手敲好几遍，这里 --auto 一次跑完
  4. 中间夹了 ROT13 层（如 picoCTF「13」）也不怕，--auto 能识别
"""

import argparse
import base64
import binascii
import codecs
import re
import string
import sys

# Base64 标准字符表：A-Z a-z 0-9 + / 以及补齐用的 =
STD_CHARS = set(string.ascii_letters + string.digits + "+/=")
# URL-safe 变体：把 + / 换成 - _
URL_CHARS = set(string.ascii_letters + string.digits + "-_=")


def looks_like_b64(text: str) -> bool:
    """粗判一段文本像不像 Base64。

    只做字符集和长度检查，不作严格校验——真正的合法性交给 b64decode。
    """
    text = text.strip()
    if len(text) < 4:
        return False
    # 出现 - 或 _ 就按 URL-safe 字符表判断
    alphabet = URL_CHARS if ("-" in text or "_" in text) else STD_CHARS
    return all(ch in alphabet for ch in text)


def decode_once(text: str):
    """尝试解一层。

    返回 bytes 表示成功，返回 None 表示这段根本不是 Base64（或解不动）。
    """
    text = "".join(text.split())          # 去掉所有空白和换行
    if not looks_like_b64(text):
        return None

    text = text.replace("-", "+").replace("_", "/")   # URL-safe 归一
    text += "=" * (-len(text) % 4)                    # 补足 padding

    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


# 常见二进制文件头：解出这些才承认「剥壳到底，出二进制了」
MAGIC_PREFIXES = (
    b"PK\x03\x04", b"\x89PNG", b"\xff\xd8\xff", b"GIF8",      # zip/png/jpg/gif
    b"Rar!", b"7z\xbc\xaf", b"%PDF", b"\x1f\x8b", b"BZh",    # rar/7z/pdf/gz/bz2
    b"\x7fELF",
)

# flag 的典型前缀（picoCTF{ / flag{ / FLAG{ ...）
FLAG_HINT_RE = re.compile(r"(?:ctf|flag)\{", re.IGNORECASE)


def _sane(text: str) -> bool:
    """判断解出来的文本像不像「正常内容」。

    Base64 很容易把普通英文误当成合法编码、解出一串乱码，
    所以每一层结果都过一遍这个检查，乱码就当是解不动。
    """
    if not text:
        return False
    allowed = set(string.ascii_letters + string.digits + "_{}!?.,:;-'\"()/@#$%^&*+=[]<>|~ `\\\n\t")
    ratio = sum(ch in allowed for ch in text) / len(text)
    return ratio >= 0.9


def rot13(text: str) -> str:
    """ROT13，正反是同一个变换。"""
    return codecs.encode(text, "rot13")


def rot13_worth_it(text: str) -> bool:
    """判断当前文本要不要套一层 ROT13。

    只有「翻完出现 ctf{ / flag{ 这类前缀、翻之前没有」才算，
    避免把普通英文句子翻成乱码，也避免把已经是 flag 的文本翻回去。
    """
    if text == rot13(text):        # 没有字母，ROT13 无意义
        return False
    return bool(FLAG_HINT_RE.search(rot13(text))) and not bool(FLAG_HINT_RE.search(text))


def auto_decode(text: str, max_rounds: int = 10):
    """反复解码直到解不动。

    返回 (history, final)：
      history —— [(层号, 该层结果或 bytes), ...]
      final   —— 最终文本；若某层解出二进制则为 None
    """
    history = []
    current = text.strip()
    last_was_rot13 = False

    for i in range(max_rounds):
        raw = decode_once(current)
        if raw is None:
            # Base64 解不动了，看看是不是中间藏了一层 ROT13。
            # 刚做过 ROT13 就不再翻回去，防止两层之间来回横跳。
            if not last_was_rot13 and rot13_worth_it(current):
                piece = rot13(current)
                history.append((f"第 {i + 1} 层 (ROT13)", piece))
                current = piece
                last_was_rot13 = True
                continue
            break
        last_was_rot13 = False

        try:
            piece = raw.decode("utf-8")
        except UnicodeDecodeError:
            # 解出了不可打印的二进制：只有对上已知文件头才算真剥到底
            if raw.startswith(MAGIC_PREFIXES):
                history.append((f"第 {i + 1} 层", raw))
                return history, None
            break                     # 更像误判出的乱码，到此为止
        if not _sane(piece):
            break                     # utf-8 能解但全是怪字符，也是误判

        history.append((f"第 {i + 1} 层", piece))

        # 解完和原文一样，说明到顶了，避免死循环
        if piece.strip() == current.strip():
            break
        current = piece

    return history, current


def read_input(args) -> str:
    """按 -f / - 中的参数决定输入从哪来。"""
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if args.text == "-":
        return sys.stdin.read()
    return args.text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Base64 编解码 / 多层自动剥壳",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("text", nargs="?", default="", help="要处理的字符串，填 - 表示从标准输入读")
    parser.add_argument("-e", "--encode", action="store_true", help="编码")
    parser.add_argument("-d", "--decode", action="store_true", help="解码（单层）")
    parser.add_argument("-a", "--auto", action="store_true", help="多层自动解码，直到解不动")
    parser.add_argument("-r", "--rot13", action="store_true", help="ROT13 一次（正反同一场）")
    parser.add_argument("-f", "--file", help="从文件读取内容")
    parser.add_argument("-n", "--rounds", type=int, default=10, help="--auto 的最大层数，默认 10")
    args = parser.parse_args()

    data = read_input(args)

    if args.encode:
        print(base64.b64encode(data.encode("utf-8")).decode())
        return 0

    if args.rot13:
        print(rot13(data))
        return 0

    if args.decode:
        raw = decode_once(data)
        if raw is None:
            print("[!] 这不是合法 Base64，检查一下有没有混进空格、中文标点或抄错字符", file=sys.stderr)
            return 1
        try:
            print(raw.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"[i] 解出的是二进制数据（{len(raw)} 字节），已写入 out.bin", file=sys.stderr)
            with open("out.bin", "wb") as fh:
                fh.write(raw)
        return 0

    if args.auto:
        history, final = auto_decode(data, args.rounds)
        if not history:
            print("[!] 第一层就解不动，输入不是 Base64", file=sys.stderr)
            return 1
        for label, piece in history:
            if isinstance(piece, bytes):
                print(f"{label}: <二进制 {len(piece)} 字节>")
                with open("out.bin", "wb") as fh:
                    fh.write(piece)
                print("[i] 已写入 out.bin")
            else:
                print(f"{label}: {piece.strip()}")
        print("-" * 40)
        print(f"共 {len(history)} 层，最终结果：")
        print(final.strip() if final is not None else "<二进制，见 out.bin>")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
