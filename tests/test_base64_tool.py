#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""base64_tool.py 的回归测试。

运行方式（在仓库根目录）:
    python -m unittest discover -s tests -v
"""

import base64
import os
import subprocess
import sys
import unittest

TOOL = os.path.join(os.path.dirname(__file__), "..", "src", "base64_tool.py")


def run_tool(*cli_args):
    """端到端跑一遍命令行，返回 (returncode, stdout, stderr)。"""
    proc = subprocess.run(
        [sys.executable, TOOL, *cli_args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestSingleLayer(unittest.TestCase):
    def test_encode(self):
        code, out, _ = run_tool("-e", "hello")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), base64.b64encode(b"hello").decode())

    def test_decode_normal(self):
        code, out, _ = run_tool("-d", "aGVsbG8=")
        self.assertEqual((code, out.strip()), (0, "hello"))

    def test_decode_missing_padding(self):
        # 少一个 = 也能解
        code, out, _ = run_tool("-d", "aGVsbG8")
        self.assertEqual((code, out.strip()), (0, "hello"))

    def test_decode_urlsafe(self):
        # 含 - 和 _ 的 URL-safe 变体
        raw = base64.urlsafe_b64encode(b">>?url??").decode()   # Pj4_dXJsP_8= 这类
        code, out, _ = run_tool("-d", raw)
        self.assertEqual((code, out.strip()), (0, ">>?url??"))

    def test_decode_garbage(self):
        code, _, err = run_tool("-d", "这不是Base64！")
        self.assertEqual(code, 1)
        self.assertIn("不是合法 Base64", err)


class TestRot13(unittest.TestCase):
    CIPHER = "cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"   # picoCTF「13」的原题密文
    PLAIN = "picoCTF{not_too_bad_of_a_problem}"

    def test_rot13_manual(self):
        code, out, _ = run_tool("-r", self.CIPHER)
        self.assertEqual((code, out.strip()), (0, self.PLAIN))
        # ROT13 正反同一场，再翻一次回到密文
        code, out2, _ = run_tool("-r", self.PLAIN)
        self.assertEqual(out2.strip(), self.CIPHER)

    def test_auto_picks_up_rot13_layer(self):
        # 外面再包一层 Base64，模拟「base64(rot13(flag))」套娃
        wrapped = base64.b64encode(self.CIPHER.encode()).decode()
        code, out, _ = run_tool("--auto", wrapped)
        self.assertEqual(code, 0)
        self.assertIn("ROT13", out)
        self.assertIn(self.PLAIN, out)

    def test_auto_does_not_mangle_plain_text(self):
        # 普通 Base64 链条里没有 flag，不应被 ROT13 翻成乱码
        wrapped = base64.b64encode(b"plain sentence no braces").decode()
        code, out, _ = run_tool("--auto", wrapped)
        self.assertNotIn("ROT13", out)
        self.assertIn("plain sentence no braces", out)


class TestMultiLayer(unittest.TestCase):
    def test_auto_three_layers(self):
        text = "three layers deep"
        for _ in range(3):
            text = base64.b64encode(text.encode()).decode()
        code, out, _ = run_tool("--auto", text)
        self.assertEqual(code, 0)
        self.assertIn("共 3 层", out)
        self.assertIn("three layers deep", out)


if __name__ == "__main__":
    unittest.main()
