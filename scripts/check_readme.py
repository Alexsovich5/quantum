"""Check that every path named in README.md exists, or print the repo layout.

    python scripts/check_readme.py          # exit 1 listing missing paths
    python scripts/check_readme.py --tree   # print a layout tree of the files
                                            # git tracks (plus untracked files
                                            # that are not ignored)
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")

EXTENSION = re.compile(r"\.[A-Za-z][A-Za-z0-9]*$")
INLINE_CODE = re.compile(r"`([^`]+)`")


def tracked_files():
    out = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
    )
    files = set()
    for line in out.decode("utf-8").splitlines():
        if line and os.path.exists(os.path.join(ROOT, line)):
            files.add(line)
    return sorted(files)


def build_tree(paths):
    tree = {}
    for path in paths:
        node = tree
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.setdefault(part + "/", {})
        node[parts[-1]] = None
    return tree


def render_tree(tree, depth=0):
    lines = []
    for name in sorted(tree, key=lambda n: (n.lower(), n)):
        lines.append("  " * depth + name)
        if tree[name] is not None:
            lines.extend(render_tree(tree[name], depth + 1))
    return lines


def layout_paths(block_lines):
    """Turn an indented layout tree back into full paths."""
    stack = []
    paths = []
    for line in block_lines:
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        depth = (len(line) - len(stripped)) // 2
        name = stripped.strip()
        stack = stack[:depth]
        paths.append("".join(stack) + name)
        if name.endswith("/"):
            stack.append(name)
    return paths


def is_path_token(token):
    if "://" in token or token.startswith("-"):
        return False
    return "/" in token or bool(EXTENSION.search(token))


def readme_paths(text):
    paths = []
    in_fence = False
    in_layout = False
    section = None
    layout_block = []
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
        if line.startswith("```"):
            if in_fence:
                if in_layout:
                    paths.extend(layout_paths(layout_block))
                in_fence = in_layout = False
                layout_block = []
            else:
                in_fence = True
                in_layout = section == "Layout"
            continue
        if in_fence:
            if in_layout:
                layout_block.append(line)
            continue
        for span in INLINE_CODE.findall(line):
            for token in span.split():
                token = token.strip(".,;:()")
                if token and is_path_token(token):
                    paths.append(token)
    return paths


def missing_paths(text):
    seen = []
    for path in readme_paths(text):
        if path not in seen and not os.path.exists(os.path.join(ROOT, path)):
            seen.append(path)
    return seen


def main(argv):
    if "--tree" in argv:
        print("\n".join(render_tree(build_tree(tracked_files()))))
        return 0
    with open(README, encoding="utf-8") as fh:
        missing = missing_paths(fh.read())
    if missing:
        print("README.md names paths that do not exist:")
        for path in missing:
            print("  " + path)
        return 1
    print("README.md: all named paths exist")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
