# Ansh Agrawal Portfolio Site

Personal cybersecurity, CTF, projects, and teaching portfolio for Ansh Agrawal.

The site is built with [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/), with custom styling and JavaScript under `docs/`.

## Setup

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Local Development

Build the generated writeup listings and serve the site:

```bash
./build.sh
```

Or run the steps manually:

```bash
python scripts/build_writeups.py
mkdocs serve
```

Open <http://127.0.0.1:8000> in your browser.

## Site Structure

- `mkdocs.yml`: site configuration, navigation, theme options, CSS, and JavaScript.
- `docs/index.md`: homepage.
- `docs/about.md`: personal/about page.
- `docs/projects.md`: project cards.
- `docs/ctf-history.md`: CTF results and stats.
- `docs/mentoring.md`: teaching and presentation materials.
- `docs/write-ups/`: individual CTF writeups.
- `docs/stylesheets/extra.css`: custom site styling.
- `docs/javascripts/`: filters, animations, contact modal, and MathJax setup.
- `scripts/build_writeups.py`: regenerates the writeup index and homepage latest-writeup cards from writeup front matter.

## Adding Writeups

1. Create a Markdown file in `docs/write-ups/`.
2. Use `docs/write-ups/_template.md` as the starting point.
3. Fill in the required front matter.
4. Run:

```bash
python scripts/build_writeups.py
```

The script updates `docs/write-ups/index.md` and the latest writeup cards on `docs/index.md`.

## Building

Run a production build:

```bash
python scripts/build_writeups.py
mkdocs build
```

The generated site is written to `site/`.

## Deployment

The site is configured for <https://anshagrawal.xyz/>. Deploy with:

```bash
mkdocs gh-deploy
```

This builds the site and pushes the output to the `gh-pages` branch.
