# Documentation and wiki source

This directory is the single source of truth for project documentation and for the published GitHub Wiki. `README.md` itself is excluded from publication.

## Publish to the GitHub Wiki

First-time setup: enable the repository Wiki and create an empty **Home** page in the GitHub UI so the wiki git remote exists.

```bash
# From the repository root; requires gh auth login
./scripts/sync-wiki.sh
```

The script:

1. resolves `GITHUB_REPOSITORY` (default: `batu3384/frostwall-beam`);
2. clones or updates the ignored `.wiki.git` working copy;
3. authenticates through a temporary `GIT_ASKPASS` helper so the token is not stored in the wiki remote URL;
4. copies `docs/wiki/` into the wiki clone, excluding `.git` and this `README.md`;
5. commits and pushes the wiki branch (`master`, or `main` when that is the wiki default).

## Editing workflow

1. Edit files in `docs/wiki/`.
2. Run `./scripts/sync-wiki.sh`.
3. Verify the published pages at the repository Wiki.

Wiki navigation is defined in `_Sidebar.md`. Wiki-internal links intentionally omit the `.md` suffix, for example `[Architecture](Architecture)`.
