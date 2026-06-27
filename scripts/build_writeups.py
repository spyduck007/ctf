from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


DOCS_DIR = Path("docs/write-ups")
INDEX_FILE = DOCS_DIR / "index.md"
HOMEPAGE_FILE = Path("docs/index.md")

GENERATED_START = "<!-- writeups:generated:start -->"
GENERATED_END = "<!-- writeups:generated:end -->"

TAG_LABELS = {
}


def _parse_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _parse_frontmatter_without_yaml(frontmatter: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    current_list_key: str | None = None

    for raw_line in frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        list_item = re.match(r"^\s*-\s+(.*)$", line)
        if list_item and current_list_key:
            metadata.setdefault(current_list_key, []).append(_parse_scalar(list_item.group(1)))
            continue

        current_list_key = None
        key_value = re.match(r"^([A-Za-z0-9_-]+):(?:\s*(.*))?$", line)
        if not key_value:
            continue

        key, value = key_value.groups()
        if value is None or value == "":
            metadata[key] = []
            current_list_key = key
        else:
            metadata[key] = _parse_scalar(value)

    return metadata


def parse_frontmatter(file_path: Path) -> dict[str, Any] | None:
    content = file_path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return None

    frontmatter = match.group(1)
    if yaml:
        try:
            parsed = yaml.safe_load(frontmatter)
        except yaml.YAMLError:
            return None
        return parsed if isinstance(parsed, dict) else None

    return _parse_frontmatter_without_yaml(frontmatter)


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def get_all_writeups() -> list[dict[str, Any]]:
    writeups = []

    for file_path in sorted(DOCS_DIR.glob("*.md")):
        filename = file_path.name
        if filename in {"index.md", "_template.md"}:
            continue

        metadata = parse_frontmatter(file_path)
        if not metadata:
            print(f"Skipping {file_path}: missing or invalid frontmatter")
            continue

        tags = normalize_list(metadata.get("tags"))
        categories = normalize_list(metadata.get("categories"))
        combined_tags = list(dict.fromkeys(tags + categories))
        category = combined_tags[0] if combined_tags else ""
        ctf = combined_tags[1] if len(combined_tags) > 1 else ""

        writeups.append(
            {
                "title": str(metadata.get("title") or file_path.stem.replace("-", " ").title()),
                "date": str(metadata.get("date") or ""),
                "tags": combined_tags,
                "category": category,
                "ctf": ctf,
                "filename": filename,
                "description": str(metadata.get("description") or ""),
            }
        )

    writeups.sort(key=lambda item: (item["date"], item["title"]), reverse=True)
    return writeups


def tag_label(tag: str) -> str:
    return TAG_LABELS.get(tag, tag)


def render_tag(tag: str) -> str:
    return f'<span class="tag">{html.escape(tag_label(tag))}</span>'


def render_writeup_card(writeup: dict[str, Any], href: str, filterable: bool = False) -> str:
    tags = writeup["tags"]
    tags_display = "".join(render_tag(tag) for tag in tags)
    data_tags = ""
    if filterable:
        data_tags = (
            f' data-category="{html.escape(writeup["category"], quote=True)}"'
            f' data-ctf="{html.escape(writeup["ctf"], quote=True)}"'
            f' data-tags="{html.escape(" ".join(tags), quote=True)}"'
        )

    return f"""
  <a href="{html.escape(href, quote=True)}" class="writeup-card"{data_tags}>
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">{html.escape(writeup["date"])}</span>
        <h3 class="card-title">{html.escape(writeup["title"])}</h3>
      </div>
      <div class="card-tags">
        {tags_display}
      </div>
    </div>
  </a>
"""


def write_file_if_changed(path: Path, content: str) -> None:
    if path.exists() and path.read_text(encoding="utf-8") == content:
        print(f"No changes needed for {path}")
        return

    path.write_text(content, encoding="utf-8")
    print(f"Updated {path}")


def generate_writeups_index(writeups: list[dict[str, Any]]) -> None:
    categories = sorted({writeup["category"] for writeup in writeups if writeup["category"]}, key=str.lower)
    ctfs = sorted({writeup["ctf"] for writeup in writeups if writeup["ctf"]}, key=str.lower)

    content = """---
hide:
  - toc
---

# CTF Writeups

<div class="filter-container writeup-filters" data-animate>
  <label class="filter-field" for="writeup-ctf-filter">
    <span class="filter-label">CTF</span>
    <select id="writeup-ctf-filter" class="filter-select" aria-label="Filter writeups by CTF">
      <option value="all">All CTFs</option>
"""

    for ctf in ctfs:
        content += f'      <option value="{html.escape(ctf, quote=True)}">{html.escape(tag_label(ctf))}</option>\n'

    content += """    </select>
  </label>
  <label class="filter-field" for="writeup-category-filter">
    <span class="filter-label">Category</span>
    <select id="writeup-category-filter" class="filter-select" aria-label="Filter writeups by category">
      <option value="all">All categories</option>
"""

    for category in categories:
        content += (
            f'      <option value="{html.escape(category, quote=True)}">'
            f"{html.escape(tag_label(category))}</option>\n"
        )

    content += f"""    </select>
  </label>
  <button class="filter-reset" type="button" hidden>Reset</button>
  <div class="filter-count" aria-live="polite">{len(writeups)} writeups</div>
</div>

<div class="writeup-grid filterable">
"""

    for writeup in writeups:
        href = writeup["filename"].removesuffix(".md") + "/"
        content += render_writeup_card(writeup, href, filterable=True)

    content += "\n</div>\n\n<p class=\"filter-empty\" hidden>No writeups match those filters.</p>\n"
    write_file_if_changed(INDEX_FILE, content)


def generate_latest_writeups_section(writeups: list[dict[str, Any]]) -> str:
    content = f"""{GENERATED_START}
<div class="section-header" data-animate>
  <span class="section-label">// latest writeups</span>
  <a href="write-ups/" class="section-link">View all →</a>
</div>

<div class="writeup-grid">
"""

    for writeup in writeups[:3]:
        href = "write-ups/" + writeup["filename"].removesuffix(".md") + "/"
        content += render_writeup_card(writeup, href)

    content += f"""
</div>
{GENERATED_END}
"""
    return content


def update_homepage(writeups: list[dict[str, Any]]) -> None:
    content = HOMEPAGE_FILE.read_text(encoding="utf-8")
    latest_section = generate_latest_writeups_section(writeups)

    marker_pattern = re.compile(
        rf"{re.escape(GENERATED_START)}.*?{re.escape(GENERATED_END)}\s*",
        re.DOTALL,
    )
    if marker_pattern.search(content):
        updated = marker_pattern.sub(latest_section, content)
        write_file_if_changed(HOMEPAGE_FILE, updated)
        return

    legacy_pattern = re.compile(
        r'<div class="section-header"[^>]*>\s*'
        r'<span class="section-label">// latest writeups</span>.*?'
        r'<div class="writeup-grid">.*?</div>\s*\Z',
        re.DOTALL,
    )
    if not legacy_pattern.search(content):
        raise RuntimeError("Could not find the latest writeups section in docs/index.md")

    updated = legacy_pattern.sub(latest_section, content)
    write_file_if_changed(HOMEPAGE_FILE, updated)


def main() -> None:
    writeups = get_all_writeups()
    generate_writeups_index(writeups)
    update_homepage(writeups)


if __name__ == "__main__":
    main()
