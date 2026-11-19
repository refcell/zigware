#!/usr/bin/env python3
"""Checks the links of the repository's Markdown against the local tree: README.md,
examples/*/README.md, docs/*.md, docs/lanes/*.md, and every README.md under src/.

Usage: check-links.py [markdown files]

Every relative link, image, and HTML src or href must name a file or directory that exists
(so every demo GIF and MP4 does), and every #anchor must match a heading or an HTML id in its
target file, slugged as GitHub slugs them. Links into this repository on github.com are
checked the same way; other external links are not fetched.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO_URL = re.compile(r"^https://github\.com/refcell/zigware/(?:blob|tree|raw)/main/")
FENCE = re.compile(r"^ {0,3}(```|~~~).*?^ {0,3}\1[^\n]*$", re.M | re.S)
INLINE_CODE = re.compile(r"`[^`\n]*`")
TARGETS = [
    re.compile(r"\]\(\s*<?([^)\s>]+)"),  # [text](target) and ![alt](target)
    re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)", re.M),  # [ref]: target
    re.compile(r"""\b(?:src|href)\s*=\s*["']([^"']+)["']"""),  # HTML attributes
]
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$", re.M)
HTML_ID = re.compile(r"""\b(?:id|name)\s*=\s*["']([^"']+)["']""")


def strip_code(text):
    """Blanks code blocks and spans, keeping their newlines so line numbers stay right."""
    blank = lambda match: re.sub(r"[^\n]", " ", match.group(0))
    return INLINE_CODE.sub(blank, FENCE.sub(blank, text))


def slug(heading):
    """GitHub's heading anchor: plain text, lowercased, punctuation dropped, spaces to '-'."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links keep their text
    text = re.sub(r"<[^>]+>", "", text).replace("`", "").lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


anchor_cache = {}


def anchors(path):
    if path not in anchor_cache:
        text = FENCE.sub("", path.read_text())
        found, counts = set(HTML_ID.findall(text)), {}
        for heading in HEADING.findall(text):
            base = slug(heading)
            n = counts.get(base, 0)
            counts[base] = n + 1
            found.add(base if n == 0 else f"{base}-{n}")
        anchor_cache[path] = found
    return anchor_cache[path]


def check_target(source, target):
    """Returns an error string, or None when the target resolves."""
    if REPO_URL.match(target):
        resolved_base = ROOT
        target = REPO_URL.sub("", target)
    elif re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
        return None  # external, or mailto:
    else:
        resolved_base = source.parent
    path_part, _, fragment = target.partition("#")
    path_part = path_part.split("?", 1)[0]
    path = (resolved_base / path_part).resolve() if path_part else source
    if not path.exists():
        return "missing file"
    if ROOT not in path.parents and path != ROOT:
        return "outside the repository"
    if fragment and path.is_file() and path.suffix == ".md":
        if fragment.lower() not in anchors(path):
            return f"missing anchor #{fragment}"
    return None


def main(argv):
    files = [Path(a).resolve() for a in argv] or [ROOT / "README.md"] + sorted(
        [*ROOT.glob("examples/*/README.md"), *ROOT.glob("docs/*.md"),
         *ROOT.glob("docs/lanes/*.md"), *ROOT.glob("src/**/README.md")])
    checked, errors = 0, []
    for source in files:
        text = strip_code(source.read_text())
        for pattern in TARGETS:
            for match in pattern.finditer(text):
                target = match.group(1)
                checked += 1
                error = check_target(source, target)
                if error:
                    line = text.count("\n", 0, match.start()) + 1
                    rel = source.relative_to(ROOT)
                    errors.append(f"{rel}:{line}: {target}: {error}")
    for error in errors:
        print(f"check-links: {error}")
    if errors:
        return 1
    print(f"check-links: ok ({checked} links in {len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
