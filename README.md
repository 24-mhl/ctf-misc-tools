# ctf-misc-tools

CTF 杂项（Misc）方向的小工具集，随学习进度逐步增加。

全部工具只用 Python 标准库，无需 `pip install`，单文件可直接运行。

## 已完成

### `src/base64_tool.py` — Base64 编解码 / 多层自动剥壳

比系统自带 `base64 -d` 多三个能力：

- 缺 padding（末尾 `=`）时自动补齐
- URL-safe 变体（`-` `_`）自动归一为 `+` `/`
- `--auto` 连续解多层，直到解不动为止——应对套娃题
- `--auto` 能识别中间藏的 ROT13 层（如 picoCTF「13」），也可用 `-r` 手动翻转
- 误判防护：普通英文不会被硬解成乱码；解出二进制时只认已知文件头（zip/png/pdf…）

```bash
python base64_tool.py -e "hello"                  # 编码
python base64_tool.py -d "aGVsbG8="               # 解码一层
python base64_tool.py --auto "Y0dsamIwTlVS..."    # 连续解到底
python base64_tool.py -r "cvpbPGS{...}"           # ROT13（正反同一场）
python base64_tool.py -d -f flag.txt              # 从文件读
echo "aGVsbG8=" | python base64_tool.py -d -      # 从标准输入读
```

回归测试：`python -m unittest discover -s tests -v`

解出二进制（图片、压缩包等）时会写进 `out.bin`，不会把终端刷乱。

### `src/http_log_parser.py` — Web 访问日志初筛

把 Apache/Nginx 的 `access.log` 变成一份可读的应急初筛报告，回答四个问题：谁在打、打了什么、用什么打的、打成了没有。

```bash
python http_log_parser.py ../samples/sample_access.log
python http_log_parser.py access.log --top 5
```

六个检测规则：SQL 注入、路径穿越、命令注入、敏感文件探测、目录扫描/管理接口探测（含 `sqlmap`、`nmap`、`nikto` 等扫描器 UA）。

设计上的两个要点：

- **按「是否得手」排序，而不是按「命中次数」排序**。打了 11 次全失败的攻击者，威胁等级低于打了 5 次就登录进去的那一个。
- **得手判定只用硬标准**：2xx 且命中实质规则，或同一 IP 对同一路径先失败 ≥3 次后成功（爆破特征）。正常用户登录成功不会被误报。

附 `samples/sample_access.log` 作为测试样本（全部使用 RFC 5737 文档保留网段，非真实 IP）。

### `src/file_checker.py` — 文件头识别（magic number）

回答「这到底是什么」，并且给出**依据**：命中的魔数、所在偏移、文件大小。

```bash
python file_checker.py dolls.jpg                  # 判定 + 依据
python file_checker.py a.jpg b.zip c.txt          # 一次看多个
python file_checker.py dolls.jpg --scan           # 找出所有内嵌签名及偏移
python file_checker.py flag.txt --head 16         # 只看前 16 字节 hex，不做判定
```

比系统 `file` 多四个能力：

- **扩展名不符会报警**。`dolls.jpg` 实际是 PNG 时直接提示 `扩展名 .jpg 与实际类型 .png 不一致`——这是 CTF 杂项最常见的第一道坎
- **认无 BOM 的 UTF-16**。`file` 对这类文件只报 `data`，但 `picoCTF{...}` 那种每字符补 `00` 的 flag 正是它；判据是零字节是否隔位分布
- **报内嵌签名偏移**，相当于一个极简 binwalk。`dolls.jpg` 会报出 `0x0004286C ZIP archive`（= 272492），和 binwalk 完全一致
- **噪声有门槛**。`MZ`、`ICO`、UTF-16 BOM 这些 2-4 字节签名在压缩数据里遍地都是，默认不报；要看全量加 `--scan-all`。注意门槛不能按长度一刀切——`PK\x03\x04` 也是 4 字节，但那是套娃题要找的东西

魔数表覆盖 20 余种格式：PNG/JPEG/GIF/BMP/ICO、ZIP/GZIP/BZIP2/XZ/7z/RAR、PDF、ELF/PE、Java class、SQLite、WAV/AVI（RIFF 容器）、MP4/MOV（`ftyp` 固定偏移 4）、OLE2（旧版 Office）、PEM、shebang，以及带 BOM 的各路文本。

## 目录结构

```
.
├── README.md
├── samples/
│   └── sample_access.log
├── src/          # 工具脚本
│   ├── base64_tool.py
│   ├── file_checker.py
│   └── http_log_parser.py
└── tests/        # 回归测试
    ├── test_base64_tool.py
    └── test_file_checker.py
```

回归测试全部用内存里现造的字节，不依赖样本文件：`python -m unittest discover -s tests -v`
