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
CTF_HISTORY_FILE = Path("docs/ctf-history.md")

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


def parse_ctf_history_rows(content: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("| :"):
            continue

        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 3 or cells[0].lower() == "competition":
            continue

        rank_match = re.search(r"\d+", cells[1])
        if not rank_match:
            continue

        year_match = re.search(r"\b(20\d{2})\b", cells[0])
        rows.append(
            {
                "competition": cells[0],
                "rank": int(rank_match.group(0)),
                "year": int(year_match.group(1)) if year_match else None,
            }
        )

    return rows


def get_ctf_stats() -> dict[str, str]:
    rows = parse_ctf_history_rows(CTF_HISTORY_FILE.read_text(encoding="utf-8"))
    years = sorted({row["year"] for row in rows if row["year"] is not None})
    first_place_count = sum(1 for row in rows if row["rank"] == 1)
    top_ten_count = sum(1 for row in rows if row["rank"] <= 10)

    if len(years) >= 2:
        year_range = f"{years[0]}-{years[-1]}"
    elif years:
        year_range = str(years[0])
    else:
        year_range = "tracked results"

    return {
        "competitions": str(len(rows)),
        "first_place": str(first_place_count),
        "top_ten": str(top_ten_count),
        "year_range": year_range,
    }


def generate_homepage_ctf_stats(stats: dict[str, str]) -> str:
    return f"""  <div class="hero__stats">
    <div class="hero__stat">
      <div class="hero__stat-num" data-count="{stats["competitions"]}">{stats["competitions"]}</div>
      <div class="hero__stat-label">CTF Competitions</div>
    </div>
    <div class="hero__stat">
      <div class="hero__stat-num" data-count="{stats["first_place"]}">{stats["first_place"]}</div>
      <div class="hero__stat-label">1st Place Finishes</div>
    </div>
    <div class="hero__stat">
      <div class="hero__stat-num" data-count="{stats["top_ten"]}">{stats["top_ten"]}</div>
      <div class="hero__stat-label">Top-10 Finishes</div>
    </div>
  </div>"""


def generate_ctf_history_stats(stats: dict[str, str]) -> str:
    return f"""<div class="ctf-stats-grid">
  <div class="stat-box" data-animate data-animate-delay="1">
    <div class="stat-number" data-count="{stats["competitions"]}">{stats["competitions"]}</div>
    <div class="stat-title">Competitions</div>
    <div class="stat-desc">Tracked from {stats["year_range"]}</div>
  </div>
  <div class="stat-box" data-animate data-animate-delay="2">
    <div class="stat-number" data-count="{stats["first_place"]}">{stats["first_place"]}</div>
    <div class="stat-title">1st Place Finishes</div>
    <div class="stat-desc">Across school, national, and global events</div>
  </div>
  <div class="stat-box" data-animate data-animate-delay="3">
    <div class="stat-number" data-count="{stats["top_ten"]}">{stats["top_ten"]}</div>
    <div class="stat-title">Top-10 Finishes</div>
    <div class="stat-desc">Including multiple large international CTFs</div>
  </div>
</div>"""


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


def update_homepage(writeups: list[dict[str, Any]], ctf_stats: dict[str, str]) -> None:
    content = HOMEPAGE_FILE.read_text(encoding="utf-8")
    stats_section = generate_homepage_ctf_stats(ctf_stats)
    latest_section = generate_latest_writeups_section(writeups)

    stats_pattern = re.compile(
        rf'  <div class="hero__stats">.*?</div>\s*(?={re.escape(GENERATED_START)})',
        re.DOTALL,
    )
    if not stats_pattern.search(content):
        raise RuntimeError("Could not find the homepage CTF stats section in docs/index.md")
    content = stats_pattern.sub(f"{stats_section}\n</div>\n\n", content, count=1)

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


def update_ctf_history(ctf_stats: dict[str, str]) -> None:
    content = CTF_HISTORY_FILE.read_text(encoding="utf-8")
    stats_section = generate_ctf_history_stats(ctf_stats)
    stats_pattern = re.compile(
        r'<div class="ctf-stats-grid">.*?</div>\s*(?=\| Competition)',
        re.DOTALL,
    )

    if not stats_pattern.search(content):
        raise RuntimeError("Could not find the CTF history stats section in docs/ctf-history.md")

    updated = stats_pattern.sub(f"{stats_section}\n\n", content, count=1)
    write_file_if_changed(CTF_HISTORY_FILE, updated)


def main() -> None:
    writeups = get_all_writeups()
    ctf_stats = get_ctf_stats()
    generate_writeups_index(writeups)
    update_homepage(writeups, ctf_stats)
    update_ctf_history(ctf_stats)


if __name__ == "__main__":
    main()
