# ctf-misc-tools

CTF 杂项（Misc）方向的小工具集，随学习进度逐步增加。

全部工具只用 Python 标准库，无需 `pip install`，单文件可直接运行。

## 已完成

### `src/base64_tool.py` — Base64 编解码 / 多层自动剥壳

比系统自带 `base64 -d` 多三个能力：

- 缺 padding（末尾 `=`）时自动补齐
- URL-safe 变体（`-` `_`）自动归一为 `+` `/`
- `--auto` 连续解多层，直到解不动为止——应对套娃题

```bash
python base64_tool.py -e "hello"                  # 编码
python base64_tool.py -d "aGVsbG8="               # 解码一层
python base64_tool.py --auto "Y0dsamIwTlVS..."    # 连续解到底
python base64_tool.py -d -f flag.txt              # 从文件读
echo "aGVsbG8=" | python base64_tool.py -d -      # 从标准输入读
```

解出二进制（图片、压缩包等）时会写进 `out.bin`，不会把终端刷乱。

## 规划中

- `http_log_parser.py` — Web 访问日志解析与可疑请求筛查
- `file_checker.py` — 文件头识别（magic number）

## 目录结构

```
.
├── README.md
└── src/          # 工具脚本
    └── base64_tool.py
```
