# pki-tools repo notes

## Dependency management (uv)

- This repo uses `uv`, not pip/poetry — `pyproject.toml` + `uv.lock`.
- The `pip` Dependabot ecosystem block in `.github/dependabot.yml` also
  parses `pyproject.toml`'s PEP-621 `[project.dependencies]`, but has no
  concept of `uv.lock`, so it will bump those deps without re-locking. It's
  restricted to `allow: dependency-name: uv` (just the bootstrap pin in
  `requirements.txt`) on purpose — don't widen that without also handling
  `uv.lock` sync. This caused uv.lock to silently go stale after PR #281
  until fixed in #286/#287.
- CI's `lint` job runs `uv lock --check`. Any `pyproject.toml` dependency
  edit needs `uv lock` run and the resulting `uv.lock` diff committed
  alongside, or CI fails.
- `.github/COPILOT_INSTRUCTIONS.md` documents the dev workflow but can
  drift from what CI actually does (it claimed CI checked `uv.lock` sync
  before that was actually true) — verify its claims against the real
  workflow YAML rather than trusting it as ground truth.

## GitHub housekeeping

- The dependency graph can leave orphaned Dependabot security alerts
  pointing at `poetry.lock`, which was deleted in #270 (poetry → uv
  migration, 2026-06-24). These don't self-clear even months later and new
  ones keep appearing for new advisories — dismiss manually
  (`gh api repos/fulder/pki-tools/dependabot/alerts/<n> -X PATCH -f
  state=dismissed -f dismissed_reason=inaccurate -f dismissed_comment=...`)
  rather than expecting them to resolve on their own.

## Releases

- `.github/workflows/publish.yml` triggers on **any tag push** and
  immediately runs `uv build && uv publish` to PyPI — there's no separate
  approval gate. Creating a GitHub Release (which pushes the tag) *is* the
  publish action; confirm with the user before doing it.
- Patch releases with no public-API change use
  `gh release create vX.Y.Z --generate-notes` (auto-generated "What's
  Changed" list, e.g. v2.0.1). Releases with a real feature get a curated
  `### Highlights` / `### Changes` / `### Requirements` format instead
  (see v2.2.0) — use `### Requirements` when a runtime dependency's version
  floor changes.
- Version is derived from git tags via hatch-vcs (`dynamic = ["version"]`
  in `pyproject.toml`) — there's no static version field to bump.
