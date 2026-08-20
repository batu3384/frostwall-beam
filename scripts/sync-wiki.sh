#!/usr/bin/env bash
# Sync wiki/ markdown to GitHub Wiki (.wiki.git clone).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIKI_SRC="${ROOT}/wiki"
WIKI_CLONE="${ROOT}/.wiki.git"
REPO="${GITHUB_REPOSITORY:-batu3384/frostwall-beam}"

if [[ ! -d "${WIKI_SRC}" ]]; then
  echo "error: ${WIKI_SRC} not found" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI required (https://cli.github.com/)" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh not authenticated — run: gh auth login" >&2
  exit 1
fi

TOKEN="$(gh auth token)"
WIKI_URL="https://x-access-token:${TOKEN}@github.com/${REPO}.wiki.git"

if [[ ! -d "${WIKI_CLONE}/.git" ]]; then
  echo "Cloning wiki into ${WIKI_CLONE} ..."
  if ! git clone "${WIKI_URL}" "${WIKI_CLONE}" 2>&1; then
    echo "" >&2
    echo "error: wiki git remote not found." >&2
    echo "First-time setup: open https://github.com/${REPO}/wiki" >&2
    echo "  → Create the Home page (any content), then re-run this script." >&2
    exit 1
  fi
else
  echo "Updating wiki clone ..."
  git -C "${WIKI_CLONE}" remote set-url origin "${WIKI_URL}"
  git -C "${WIKI_CLONE}" fetch origin
fi

# GitHub Wiki default branch is usually master
WIKI_BRANCH="master"
if ! git -C "${WIKI_CLONE}" show-ref --verify --quiet "refs/heads/${WIKI_BRANCH}"; then
  if git -C "${WIKI_CLONE}" show-ref --verify --quiet refs/heads/main; then
    WIKI_BRANCH="main"
  elif git -C "${WIKI_CLONE}" rev-parse --verify origin/master >/dev/null 2>&1; then
    git -C "${WIKI_CLONE}" checkout -B master origin/master
  elif git -C "${WIKI_CLONE}" rev-parse --verify origin/main >/dev/null 2>&1; then
    WIKI_BRANCH="main"
    git -C "${WIKI_CLONE}" checkout -B main origin/main
  else
    echo "Initializing empty wiki on branch master ..."
    git -C "${WIKI_CLONE}" checkout --orphan master 2>/dev/null || git -C "${WIKI_CLONE}" checkout -B master
    git -C "${WIKI_CLONE}" rm -rf . 2>/dev/null || true
  fi
else
  git -C "${WIKI_CLONE}" checkout "${WIKI_BRANCH}"
  git -C "${WIKI_CLONE}" pull --rebase origin "${WIKI_BRANCH}" 2>/dev/null || true
fi

echo "Rsync wiki/ → .wiki.git ..."
rsync -av --delete \
  --exclude='.git' \
  --exclude='README.md' \
  "${WIKI_SRC}/" "${WIKI_CLONE}/"

git -C "${WIKI_CLONE}" add -A

if git -C "${WIKI_CLONE}" diff --staged --quiet; then
  echo "Wiki unchanged — nothing to push."
  exit 0
fi

git -C "${WIKI_CLONE}" commit -m "Sync wiki from ${REPO}@$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

echo "Pushing to origin ${WIKI_BRANCH} ..."
git -C "${WIKI_CLONE}" push origin "${WIKI_BRANCH}"

echo "Done: https://github.com/${REPO}/wiki"
