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

## 规划中

- `file_checker.py` — 文件头识别（magic number）

## 目录结构

```
.
├── README.md
├── samples/
│   └── sample_access.log
└── src/          # 工具脚本
    ├── base64_tool.py
    └── http_log_parser.py
```
