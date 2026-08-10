#!/usr/bin/env python3
"""
restore.py — 与 chunk_*.txt 放在同一目录下运行,从纯文本 chunk 中还原出
完整的目录树(带 sha256 校验)。

用法:
    python restore.py                # 还原到 ./restored/
    python restore.py --out myrepo   # 还原到指定目录
    python restore.py --dry-run      # 只校验、列出文件清单,不落盘

不依赖任何第三方库。
"""
import argparse
import base64
import glob
import hashlib
import os
import re
import sys

BEGIN = "##### NETVAL-PACK-FILE-BEGIN #####"
END = "##### NETVAL-PACK-FILE-END #####"


def parse_chunk_text(text: str):
    records = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].strip() == BEGIN:
            path = None
            sha256 = None
            size = None
            i += 1
            if not lines[i].startswith("PATH: "):
                raise ValueError(f"expected PATH line, got: {lines[i]!r}")
            path = lines[i][len("PATH: "):]
            i += 1
            if not lines[i].startswith("SHA256: "):
                raise ValueError(f"expected SHA256 line, got: {lines[i]!r}")
            sha256 = lines[i][len("SHA256: "):].strip()
            i += 1
            if not lines[i].startswith("SIZE: "):
                raise ValueError(f"expected SIZE line, got: {lines[i]!r}")
            size = int(lines[i][len("SIZE: "):].strip())
            i += 1
            if lines[i].strip() != "BASE64:":
                raise ValueError(f"expected BASE64: line, got: {lines[i]!r}")
            i += 1
            b64_lines = []
            while lines[i].strip() != END:
                b64_lines.append(lines[i].strip())
                i += 1
            i += 1  # consume END line
            b64 = "".join(b64_lines)
            records.append({"path": path, "sha256": sha256, "size": size, "b64": b64})
        else:
            i += 1
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="restored", help="还原目标目录")
    ap.add_argument("--dry-run", action="store_true", help="只校验不落盘")
    ap.add_argument(
        "--chunks-dir", default=".", help="chunk_*.txt 所在目录(默认当前目录)"
    )
    args = ap.parse_args()

    chunk_paths = sorted(glob.glob(os.path.join(args.chunks_dir, "chunk_*.txt")))
    if not chunk_paths:
        print("没有找到 chunk_*.txt,请确认与本脚本放在同一目录。", file=sys.stderr)
        sys.exit(1)

    all_records = []
    for cp in chunk_paths:
        with open(cp, "r", encoding="utf-8") as f:
            text = f.read()
        recs = parse_chunk_text(text)
        print(f"[读取] {cp}: {len(recs)} 个文件条目")
        all_records.extend(recs)

    if not all_records:
        print("未解析出任何文件条目,粘贴内容可能不完整或被截断。", file=sys.stderr)
        sys.exit(1)

    ok = 0
    bad = []
    for rec in all_records:
        try:
            data = base64.b64decode(rec["b64"])
        except Exception as e:
            bad.append((rec["path"], f"base64 解码失败: {e}"))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != rec["size"] or digest != rec["sha256"]:
            bad.append(
                (
                    rec["path"],
                    f"校验失败: 期望 size={rec['size']} sha256={rec['sha256']}, "
                    f"实际 size={len(data)} sha256={digest}",
                )
            )
            continue
        ok += 1
        if not args.dry_run:
            dest = os.path.join(args.out, rec["path"])
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)

    print(f"\n校验通过: {ok}/{len(all_records)}")
    if bad:
        print(f"\n{len(bad)} 个文件有问题(很可能是粘贴时截断或改动了换行符):")
        for path, reason in bad:
            print(f"  - {path}: {reason}")
        sys.exit(2)
    else:
        if args.dry_run:
            print("dry-run 模式,未写入任何文件。全部文件校验通过,可以去掉 --dry-run 正式还原。")
        else:
            print(f"已全部还原到: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
