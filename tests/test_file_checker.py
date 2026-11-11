#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""file_checker 的回归测试。

跑法：
    cd ctf-misc-tools && python -m unittest discover -s tests -v

全部用内存里现造的字节，不依赖样本文件，换机器也能跑。
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import file_checker  # noqa: E402


PNG_SIG = b"\x89PNG\r\n\x1a\n"


def make_png(width=594, height=1104):
    """造一个只有头部合法的 PNG：签名 + IHDR 的宽高。"""
    ihdr = width.to_bytes(4, "big") + height.to_bytes(4, "big")
    return PNG_SIG + b"\x00\x00\x00\x0dIHDR" + ihdr + b"\x08\x06\x00\x00\x00"


class TestIdentify(unittest.TestCase):
    def test_png(self):
        got = file_checker.identify(make_png())
        self.assertIsNotNone(got)
        name, offset, magic, ext = got[0], got[1], got[2], got[3]
        self.assertEqual(name, "PNG image")
        self.assertEqual(offset, 0)
        self.assertEqual(magic, PNG_SIG)
        self.assertEqual(ext, ".png")

    def test_jpeg(self):
        got = file_checker.identify(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00")
        self.assertEqual(got[0], "JPEG image")

    def test_zip(self):
        got = file_checker.identify(b"PK\x03\x04" + b"\x14\x00" * 10)
        self.assertEqual(got[0], "ZIP archive")

    def test_elf(self):
        got = file_checker.identify(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        self.assertEqual(got[0], "ELF executable")

    def test_mp4_ftyp_at_offset_4(self):
        # mp4 的签名不在 0 而在 4，这是识别时最容易漏的一种
        got = file_checker.identify(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 8)
        self.assertEqual(got[0], "MP4 / MOV (ISO BMFF)")
        self.assertEqual(got[1], 4)

    def test_unknown(self):
        self.assertIsNone(file_checker.identify(b"\x01\x02\x03\x04\x05\x06\x07\x08"))


class TestUtf16(unittest.TestCase):
    def test_utf16le_no_bom(self):
        # 对应 flag.txt 那种情况：每字符后跟 00，没有文件头可认
        data = "picoCTF{abc}".encode("utf-16-le")
        got = file_checker.identify(data)
        self.assertIsNotNone(got)
        self.assertIn("UTF-16LE", got[0])

    def test_utf16be_no_bom(self):
        data = "picoCTF{abc}".encode("utf-16-be")
        got = file_checker.identify(data)
        self.assertIn("UTF-16BE", got[0])

    def test_utf16le_with_bom_is_not_confused(self):
        data = b"\xff\xfe" + "hello".encode("utf-16-le")
        got = file_checker.identify(data)
        self.assertIn("UTF-16LE", got[0])

    def test_plain_ascii_is_not_utf16(self):
        # 纯 ASCII 里没有规律的零字节，不能误判成 UTF-16
        self.assertIsNone(file_checker.guess_utf16(b"hello world, this is plain text."))

    def test_chinese_text_is_text(self):
        # 中文是 UTF-8 多字节，不能拿 ASCII 可打印率去卡
        got = file_checker.identify("# 标题\n这是一段中文说明。\n".encode("utf-8") * 4)
        self.assertIsNotNone(got)
        self.assertIn("plain text", got[0])

    def test_binary_is_not_text(self):
        self.assertIsNone(file_checker.identify(bytes(range(8)) * 40))


class TestScan(unittest.TestCase):
    def test_finds_appended_zip(self):
        # 造一个「图 + 尾部接 zip」的典型样本，偏移必须是 1000
        data = make_png() + b"\x00" * (1000 - len(make_png())) + b"PK\x03\x04" + b"\x00" * 20
        hits, _ = file_checker.scan(data)
        offsets = [h[0] for h in hits]
        self.assertIn(1000, offsets)
        self.assertEqual(hits[0][0], 0)          # 主文件在最前

    def test_noisy_signatures_hidden_by_default(self):
        # MZ 这类两字节签名默认不报，避免把压缩数据里的巧合当结论
        data = b"MZ" + b"\x00" * 40
        hits, skipped = file_checker.scan(data)
        self.assertNotIn("PE / DOS executable", [h[1] for h in hits])
        self.assertGreater(skipped, 0)

    def test_scan_all_includes_noisy(self):
        data = b"MZ" + b"\x00" * 40
        hits, _ = file_checker.scan(data, include_noisy=True)
        self.assertIn("PE / DOS executable", [h[1] for h in hits])


class TestDims(unittest.TestCase):
    def test_png_dims(self):
        self.assertEqual(file_checker.guess_dims(make_png(594, 1104), "PNG image"), "594 x 1104")


if __name__ == "__main__":
    unittest.main()
