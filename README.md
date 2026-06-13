# My CTF Site

This site is built with [MkDocs](https://www.mkdocs.org/) and the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme.

## Setup

1.  **Install Python** (if not already installed).
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Running Locally

To preview the site locally:

```bash
mkdocs serve
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

## Adding Content

### New Writeup

1.  Go to `docs/write-ups/`.
2.  Create a new Markdown file (e.g., `my-challenge.md`).
3.  Copy the content from `_template.md` and fill it in.
4.  It will automatically appear on the site!

### Regenerate Writeup Listings

The writeup index and homepage latest updates are generated from writeup front matter:

```bash
python scripts/build_writeups.py
```

Run this before building or serving the site.

## Deployment to GitHub Pages

This site is ready to be deployed to GitHub Pages.

1.  **Push your changes** to GitHub.
2.  **Run the deploy command**:
    ```bash
    mkdocs gh-deploy
    ```
    This will build the site and push it to the `gh-pages` branch.

## Configuration

- **`mkdocs.yml`**: Main configuration file (site name, theme, plugins).
- **`scripts/build_writeups.py`**: Regenerates the writeup index and homepage latest updates.
