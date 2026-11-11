#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTF 杂项小工具：文件头识别（magic number）

用法:
    python file_checker.py dolls.jpg                 # 看它到底是什么
    python file_checker.py a.jpg b.zip c.txt          # 一次看多个
    python file_checker.py dolls.jpg --scan           # 扫出文件里所有内嵌签名及偏移
    python file_checker.py flag.txt --head 16         # 只看前 16 字节的原始 hex

为什么不用系统 `file` 就够？
  1. `file` 只报类型，不告诉你扩展名和实际类型不一致 —— 而这是 CTF 的第一道坎
  2. `file` 认不出「无 BOM 的 UTF-16」，只会说 data，但那种文件往往是 flag
  3. `file` 不报内嵌签名偏移，套娃题还得再跑一次 binwalk
  4. 报错信息照着这个工具的输出能直接写进笔记：判定 + 依据 + 偏移

三个固定动作的顺序（先便宜后贵）：
    file  ->  strings  ->  binwalk
这个工具干的是第一步，只是把「判定」和「依据」一起给你。
"""

import argparse
import sys

# (偏移, 魔数, 名称, 对应扩展名, 备注)
# 偏移指魔数在文件里的起始位置：绝大多数是 0，少数格式（如 mp4 的 ftyp）在固定偏移。
MAGIC = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG image", ".png", ""),
    (0, b"\xff\xd8\xff", "JPEG image", ".jpg", ""),
    (0, b"GIF87a", "GIF image", ".gif", ""),
    (0, b"GIF89a", "GIF image", ".gif", ""),
    (0, b"\x00\x00\x01\x00", "ICO icon", ".ico", ""),
    (0, b"PK\x03\x04", "ZIP archive", ".zip", "也涵盖 docx/xlsx/pptx/jar/apk"),
    (0, b"PK\x05\x06", "ZIP archive (empty)", ".zip", ""),
    (0, b"\x1f\x8b\x08", "GZIP", ".gz", ""),
    (0, b"BZh", "BZIP2", ".bz2", ""),
    (0, b"\xfd7zXZ\x00", "XZ", ".xz", ""),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", ".7z", ""),
    (0, b"Rar!\x1a\x07", "RAR", ".rar", ""),
    (0, b"%PDF-", "PDF document", ".pdf", ""),
    (0, b"\x7fELF", "ELF executable", "", "Linux 可执行文件"),
    (0, b"MZ", "PE / DOS executable", ".exe", "弱特征：只有 2 字节"),
    (0, b"\xca\xfe\xba\xbe", "Java class / Mach-O fat", ".class", ""),
    (0, b"SQLite format 3\x00", "SQLite database", ".db", ""),
    (0, b"OggS", "OGG", ".ogg", ""),
    (0, b"fLaC", "FLAC", ".flac", ""),
    (0, b"ID3", "MP3 (ID3 tag)", ".mp3", ""),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound", ".doc", "旧版 doc/xls/ppt"),
    (0, b"\xef\xbb\xbf", "UTF-8 text (with BOM)", ".txt", ""),
    (0, b"\xff\xfe", "UTF-16LE text (with BOM)", ".txt", ""),
    (0, b"\xfe\xff", "UTF-16BE text (with BOM)", ".txt", ""),
    (0, b"-----BEGIN", "PEM (cert / private key)", ".pem", ""),
    (0, b"#!", "script (shebang)", "", ""),
]

# 弱特征：字节太短，容易在文本里误命中，输出时要提醒别当结论
WEAK = {b"BM", b"MZ", b"ID3"}

# 扫描时的噪声签名：这些魔数太短或太常见，在压缩数据里几乎必然命中。
# 注意不能用「长度 < 5」一刀切 —— zip 的 PK\x03\x04 也是 4 字节，但那正是套娃题要找的。
NOISY = {
    b"\x00\x00\x01\x00",   # ICO：四个接近零的字节，压缩数据里遍地都是
    b"\xff\xfe",           # UTF-16LE BOM
    b"\xfe\xff",           # UTF-16BE BOM
    b"BM",                 # BMP
    b"MZ",                 # PE
    b"ID3",                # MP3 tag
    b"#!",                 # shebang
}

# 文本类扩展名：识别结果是 .txt 时，这些扩展名都算对得上，不该报不一致
TEXT_EXTS = {
    ".txt", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv", ".json",
    ".xml", ".html", ".htm", ".yml", ".yaml", ".ini", ".conf", ".cfg",
    ".toml", ".py", ".sh", ".c", ".h", ".cpp", ".java", ".js", ".ts",
    ".go", ".rs", ".sql", ".env",
}

# 主识别只读这么多字节，够覆盖全部魔数（最长的是 OLE2 的 8 字节 + 固定偏移）
HEAD_BYTES = 32


def to_hex(raw: bytes) -> str:
    """把字节转成带空格的十六进制，方便对照笔记。"""
    return " ".join("%02X" % b for b in raw)


def identify(data: bytes):
    """按魔数表判定类型。

    返回 (名称, 偏移, 魔数, 扩展名, 备注, 是否弱特征)；认不出返回 None。
    """
    head = data[:HEAD_BYTES]
    # 长魔数优先，避免 PK 之类的短前缀抢走 ZIP 系列的判断
    for offset, magic, name, ext, note in sorted(MAGIC, key=lambda m: len(m[1]), reverse=True):
        if head[offset:offset + len(magic)] == magic:
            return name, offset, magic, ext, note, magic in WEAK

    # RIFF 容器要再看第 8 字节才知道是 WAV 还是 AVI
    if head[:4] == b"RIFF":
        kind = head[8:12]
        if kind == b"WAVE":
            return "WAV audio", 0, b"RIFF....WAVE", ".wav", "", False
        if kind == b"AVI ":
            return "AVI video", 0, b"RIFF....AVI ", ".avi", "", False
        return "RIFF container", 0, b"RIFF", "", "未知子类型", False

    # MP4/MOV 的 ftyp 固定在偏移 4
    if head[4:8] == b"ftyp":
        return "MP4 / MOV (ISO BMFF)", 4, b"ftyp", ".mp4", "", False

    # 无 BOM 的 UTF-16：没有文件头可认，只能靠「零字节位置」判
    enc = guess_utf16(data)
    if enc:
        return "%s text (no BOM)" % enc, 0, data[:8], ".txt", "靠零字节分布判定", False

    # 最后兜一层纯文本：没有魔数，但字节基本都能打印出来
    if looks_like_text(data):
        return "plain text (ASCII/UTF-8)", 0, data[:8], ".txt", "无魔数，靠可打印比例判定", False

    return None


def looks_like_text(data: bytes, sample: int = 512) -> bool:
    """判断是不是纯文本。

    三条：前 512 字节里不出现 NUL；能按 UTF-8 解出来（中文是多字节，
    不能用 ASCII 可打印率去卡）；解出的字符可打印占比 >= 95%。
    解不出 UTF-8 时退回纯 ASCII 判断，兼容 GBK 之类的本地编码。
    """
    chunk = data[:sample]
    if not chunk or b"\x00" in chunk:
        return False

    text = None
    # 512 字节的截断可能正好切在多字节字符中间，最多往后让 3 个字节
    for cut in (0, 1, 2, 3):
        part = chunk[:len(chunk) - cut] if cut else chunk
        try:
            text = part.decode("utf-8")
            break
        except UnicodeDecodeError:
            continue

    if text is None:
        printable = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
        return printable / len(chunk) >= 0.95
    if not text:
        return False

    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return good / len(text) >= 0.95


def guess_utf16(data: bytes, sample: int = 256):
    """没有 BOM 时猜 UTF-16。

    判据：ASCII 字符在 UTF-16 里高位补 00，于是零字节会**隔一个出现**。
    偶数位全是零 -> BE；奇数位全是零 -> LE。
    这条规则就是 `xxd` 里看到 `70 00 69 00 63 00` 时的判断过程。
    """
    chunk = data[:sample]
    if len(chunk) < 8:
        return None
    even = chunk[0::2]
    odd = chunk[1::2]
    even_zero = even.count(0) / len(even)
    odd_zero = odd.count(0) / len(odd)
    if odd_zero > 0.6 and even_zero < 0.2:
        return "UTF-16LE"
    if even_zero > 0.6 and odd_zero < 0.2:
        return "UTF-16BE"
    return None


def guess_dims(data: bytes, name: str):
    """顺手解析 PNG / GIF / BMP 的宽高，纯属赠品。"""
    try:
        if name.startswith("PNG") and len(data) >= 24:
            w = int.from_bytes(data[16:20], "big")
            h = int.from_bytes(data[20:24], "big")
            return "%d x %d" % (w, h)
        if name.startswith("GIF") and len(data) >= 10:
            w = int.from_bytes(data[6:8], "little")
            h = int.from_bytes(data[8:10], "little")
            return "%d x %d" % (w, h)
        if name.startswith("BMP") and len(data) >= 26:
            w = int.from_bytes(data[18:22], "little", signed=True)
            h = int.from_bytes(data[22:26], "little", signed=True)
            return "%d x %d" % (w, abs(h))
    except (IndexError, ValueError):
        pass
    return ""


def scan(data: bytes, limit: int = 20, include_noisy: bool = False):
    """扫出文件里所有签名出现的位置，相当于一个极简 binwalk。

    返回 (hits, skipped)：
      hits    —— [(偏移, 名称, 魔数), ...]，按偏移排序
      skipped —— 被噪声门槛挡掉的命中数
    """
    hits = []
    skipped = 0
    seen = set()
    for offset, magic, name, _ext, _note in MAGIC:
        if not include_noisy and magic in NOISY:
            # 先数一下有多少，用于在输出里说明「挡掉了多少」
            skipped += 0 if data.find(magic) < 0 else 1
            continue
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            start = idx + 1
            # 同一位置的同一签名只报一次
            key = (idx, magic)
            if key in seen:
                continue
            seen.add(key)
            hits.append((idx, name, magic))
            if len(hits) >= limit * 4:
                break
    hits.sort(key=lambda h: h[0])
    return hits[:limit], skipped


def check_one(path: str, args) -> int:
    """处理单个文件，返回 0 表示认出来了，3 表示认不出。"""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print("[!] 读不了 %s：%s" % (path, exc), file=sys.stderr)
        return 2

    print("== %s ==" % path)
    print("  大小    %d 字节" % len(data))

    if args.head:
        # 只要原始字节时，不猜类型，直接给 hex
        print("  前 %d 字节  %s" % (min(args.head, len(data)), to_hex(data[:args.head])))
        return 0

    size = len(data) if len(data) else 1
    result = identify(data)

    if result is None:
        print("  判定    <认不出来>")
        print("  前 8 字节  %s" % to_hex(data[:8]))
        print("  下一步  试着 strings 找可读文字，或 binwalk 扫内嵌签名")
        return 3

    name, offset, magic, ext, note, weak = result
    print("  判定    %s" % name)
    print("  依据    %s  @ 0x%X" % (to_hex(magic), offset))
    if note:
        print("  备注    %s" % note)
    dims = guess_dims(data, name)
    if dims:
        print("  尺寸    %s" % dims)

    # 扩展名与实际类型对不上：CTF 里这是考点，日常里这是事故
    actual_ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    mismatch = ext and actual_ext and ("." + actual_ext) != ext
    if mismatch and ext == ".txt" and ("." + actual_ext) in TEXT_EXTS:
        mismatch = False              # 文本类扩展名（.md/.py/.json）不算不一致
    if mismatch:
        print("  [!] 扩展名 .%s 与实际类型 %s 不一致" % (actual_ext, ext))
    if weak:
        print("  [!] 弱特征，只有 %d 字节，可能是巧合" % len(magic))

    if args.scan or args.scan_all:
        hits, skipped = scan(data, include_noisy=args.scan_all)
        print("  内嵌签名 %d 处" % len(hits))
        for idx, hit_name, hit_magic in hits:
            flag = "  主文件" if idx == offset else ""
            print("    0x%08X  %-28s 占比 %5.1f%%%s"
                  % (idx, hit_name, idx * 100.0 / size, flag))
        if skipped:
            print("  [i] 已忽略 %d 类易误报签名（ICO/BOM/MZ 等），加 --scan-all 可看" % skipped)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="文件头识别（magic number）：判定 + 依据 + 内嵌签名偏移",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("files", nargs="+", help="要检查的文件，可以给多个")
    parser.add_argument("--scan", action="store_true", help="额外扫出文件里所有内嵌签名及偏移")
    parser.add_argument("--scan-all", action="store_true", help="扫描时连 2-4 字节的短路名也报（噪声多）")
    parser.add_argument("--head", type=int, default=0, help="只打印前 N 字节的 hex，不做判定")
    args = parser.parse_args()

    # Windows 上接管道时 stdout 会退回 GBK，遇到特殊字符直接崩，这里兜一层
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

    worst = 0
    for path in args.files:
        code = check_one(path, args)
        worst = max(worst, code)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
