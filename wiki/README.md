# Wiki source (not published)

Markdown in this directory is the **source of truth** for the GitHub Wiki. It is **not** synced as a page (`README.md` is excluded).

## Publish to GitHub Wiki

**First time only:** enable Wiki on the repo, then create an empty **Home** page in the GitHub Wiki UI (Settings → Wiki). Without this, the wiki git remote may not exist.

```bash
# From repo root — requires gh auth (gh auth login)
./scripts/sync-wiki.sh
```

## What the script does

1. Resolves `GITHUB_REPOSITORY` (default: `batu3384/frostwall-beam`)
2. Clones or updates `.wiki.git` via `gh auth token`
3. `rsync --delete` from `wiki/` → wiki clone (excludes `.git`, `README.md`)
4. Commits and pushes to `master` (falls back to `main` if that is the wiki default)

## Local preview

Any Markdown viewer works. GitHub Wiki uses `_Sidebar.md` for navigation and link targets **without** `.md` suffix (e.g. `[Home](Home)`).

## Edit workflow

1. Edit files under `wiki/`
2. Run `./scripts/sync-wiki.sh`
3. Verify: `https://github.com/batu3384/frostwall-beam/wiki`
