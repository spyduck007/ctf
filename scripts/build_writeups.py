import os
import glob
import yaml
import re

DOCS_DIR = "docs/write-ups"
INDEX_FILE = os.path.join(DOCS_DIR, "index.md")
HOMEPAGE_FILE = "docs/index.md"


def parse_frontmatter(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    # Extract frontmatter
    match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return None

    try:
        metadata = yaml.safe_load(match.group(1))
        return metadata
    except yaml.YAMLError:
        return None


def get_all_writeups():
    writeups = []
    files = glob.glob(os.path.join(DOCS_DIR, "*.md"))

    for file_path in files:
        filename = os.path.basename(file_path)
        if filename in ["index.md", "_template.md"]:
            continue

        metadata = parse_frontmatter(file_path)
        if not metadata:
            continue

        # Normalize tags
        tags = metadata.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # Add categories to tags if present
        categories = metadata.get("categories", [])
        if isinstance(categories, str):
            categories = [categories]

        combined_tags = list(set(tags + categories))

        writeups.append(
            {
                "title": metadata.get("title", filename.replace(".md", "")),
                "date": metadata.get("date", ""),
                "tags": combined_tags,
                "filename": filename,
                "description": metadata.get("description", ""),
            }
        )

    # Sort writeups by date (newest first)
    writeups.sort(key=lambda x: str(x["date"]), reverse=True)
    return writeups


def generate_writeups_index(writeups):
    all_tags = set()
    for w in writeups:
        all_tags.update(w["tags"])

    content = """---
hide:
  - toc
---

# CTF Writeups

<div class="filter-container">
  <button class="filter-btn active" onclick="filterSelection('all')">All</button>
"""

    # Add filter buttons
    sorted_tags = sorted(list(all_tags))
    for tag in sorted_tags:
        content += f'  <button class="filter-btn" onclick="filterSelection(\'{tag}\')">{tag}</button>\n'

    content += """</div>

<div class="writeup-grid filterable">
"""

    # Add writeup cards
    for w in writeups:
        tags_str = " ".join(w["tags"])
        tags_display = "".join([f'<span class="tag">{t}</span>' for t in w["tags"]])
        link_url = w["filename"].replace(".md", "/")

        content += f"""
  <a href="{link_url}" class="writeup-card" data-tags="{tags_str}">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">{w["date"]}</span>
        <h3 class="card-title">{w["title"]}</h3>
      </div>
      <div class="card-tags">
        {tags_display}
      </div>
    </div>
  </a>
"""

    content += """</div>

<script>
function filterSelection(c) {
  var x, i;
  x = document.getElementsByClassName("writeup-card");
  var btns = document.getElementsByClassName("filter-btn");
  
  // Update active button state
  for (i = 0; i < btns.length; i++) {
    if (btns[i].innerText.toLowerCase() === c.toLowerCase() || (c === 'all' && btns[i].innerText === 'All')) {
      btns[i].classList.add("active");
    } else {
      btns[i].classList.remove("active");
    }
  }

  if (c == "all") c = "";
  for (i = 0; i < x.length; i++) {
    w3RemoveClass(x[i], "show");
    if (x[i].getAttribute("data-tags").indexOf(c) > -1) w3AddClass(x[i], "show");
  }
}

function w3AddClass(element, name) {
  var i, arr1, arr2;
  arr1 = element.className.split(" ");
  arr2 = name.split(" ");
  for (i = 0; i < arr2.length; i++) {
    if (arr1.indexOf(arr2[i]) == -1) {element.className += " " + arr2[i];}
  }
}

function w3RemoveClass(element, name) {
  var i, arr1, arr2;
  arr1 = element.className.split(" ");
  arr2 = name.split(" ");
  for (i = 0; i < arr2.length; i++) {
    while (arr1.indexOf(arr2[i]) > -1) {
      arr1.splice(arr1.indexOf(arr2[i]), 1);     
    }
  }
  element.className = arr1.join(" ");
}

// Initialize
filterSelection("all")
</script>
"""

    with open(INDEX_FILE, "w") as f:
        f.write(content)

    print(f"Successfully generated {INDEX_FILE}")


def update_homepage(writeups):
    with open(HOMEPAGE_FILE, "r") as f:
        content = f.read()

    # Split content at "## Latest Updates"
    parts = content.split("## Latest Updates")
    if len(parts) < 2:
        print("Could not find '## Latest Updates' section in homepage.")
        return

    pre_content = parts[0]

    # Generate new grid for top 3 items
    new_section = '## Latest Updates\n\n<div class="writeup-grid">\n'

    for w in writeups[:3]:  # Top 3
        tags_display = "".join([f'<span class="tag">{t}</span>' for t in w["tags"]])
        # Link needs to be relative to root, so prepend write-ups/
        link_url = f"write-ups/{w['filename'].replace('.md', '/')}"

        new_section += f"""
  <a href="{link_url}" class="writeup-card">
    <div class="card-content">
      <div class="card-header">
        <span class="card-date">{w["date"]}</span>
        <h3 class="card-title">{w["title"]}</h3>
      </div>
      <div class="card-tags">
        {tags_display}
      </div>
    </div>
  </a>
"""
    new_section += "</div>\n"

    final_content = pre_content + new_section

    with open(HOMEPAGE_FILE, "w") as f:
        f.write(final_content)

    print(f"Successfully updated {HOMEPAGE_FILE}")


def main():
    writeups = get_all_writeups()
    generate_writeups_index(writeups)
    update_homepage(writeups)


if __name__ == "__main__":
    main()
