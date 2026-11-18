"""Reproduce the packaged notices from pinned upstream license comments."""

import argparse
import json
from pathlib import Path
import re


def render(native):
    manifest = json.loads((native / "lwip-source.json").read_text())
    vendor = native / "vendor/lwip"
    groups = {}
    copying_only = []
    for name in manifest["notice_files"]:
        assert name in manifest["sha256"], name
        source = (vendor / name).read_text()
        comments = re.findall(r"/\*(.*?)\*/", source, re.S)
        licenses = []
        for comment in comments:
            if "copyright" not in comment.lower():
                continue
            if "redistribution" not in comment.lower() and "permission" not in comment.lower():
                continue
            text = "\n".join(re.sub(r"^\s*\* ?", "", line).rstrip()
                             for line in comment.splitlines()).strip()
            licenses.append(text)
            groups.setdefault(text, []).append(name)
        if not licenses:
            assert "copyright" not in source.lower(), f"unrecognized upstream license comment: {name}"
            copying_only.append(name)
    result = [
        "lwIP 2.2.1 - STABLE-2_2_1_RELEASE",
        f"Upstream commit: {manifest['commit']}",
        manifest["upstream"],
        "",
        "Upstream COPYING:",
        (vendor / "COPYING").read_text().rstrip(),
        "",
        "Files without a separate copyright/license comment (COPYING above):",
        *(f"  {name}" for name in copying_only),
        "",
        "Additional source/header notices (identical comments grouped):",
    ]
    for text, names in groups.items():
        result.extend(["", "Files:", *(f"  {name}" for name in names), "", text])
    return "\n".join(result) + "\n", len(groups)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    native = Path(__file__).resolve().parents[1]
    expected, count = render(native)
    asset = native / "notice-assets/licenses/lwip.txt"
    if args.write:
        asset.parent.mkdir(parents=True, exist_ok=True)
        asset.write_text(expected)
    assert asset.read_text() == expected, "packaged lwIP notices differ from pinned source"
    print(f"stock_lwip_notices: {count} distinct license comments and COPYING match packaged asset")
