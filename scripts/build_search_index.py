#!/usr/bin/env python3
import frontmatter, json, pathlib, re

CONTENT_DIR = pathlib.Path('content/blog')  # restrict index to blog posts only
OUTPUT = pathlib.Path('static/index.json')

items = []
for md in CONTENT_DIR.rglob('*.md'):
    if md.name == '_index.md':
        continue
    post = frontmatter.load(md)
    title = post.get('title') or md.stem.replace('-', ' ').title()
    summary = post.get('summary') or ''
    raw = post.content
    text = re.sub(r'```[\s\S]*?```', ' ', raw)
    text = re.sub(r'!\[[^\]]*\]\([^)]*\)', ' ', text)
    text = re.sub(r'\[[^\]]*\]\([^)]*\)', ' ', text)
    text = re.sub(r'\s+', ' ', text)[:400]
    rel = md.relative_to(CONTENT_DIR)
    slug = post.get('slug') or md.stem
    permalink = f"/blog/{slug}/"
    items.append({
        'title': title,
        'summary': summary,
        'content': text,
        'permalink': permalink
    })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(items, ensure_ascii=False))
print(f"Wrote {len(items)} records to {OUTPUT}")
