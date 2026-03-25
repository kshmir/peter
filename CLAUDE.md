# Peter — Project Instructions

## Versioning

- **`0.0.x`** (e.g. `v0.0.3`) — Minor/patch builds. Bug fixes, small tweaks. Increment the last number.
- **`0.x.0`** (e.g. `v0.3.0`) — Major releases. New features, significant changes. Increment the middle number.
- Tag format: `v0.x.y` — pushing a tag triggers the CI/CD pipeline to build + upload to Play Store internal track.

## Release

- `git tag v0.0.x && git push origin v0.0.x` — minor build
- `git tag v0.x.0 && git push origin v0.x.0` — major release
- Pipeline: GitHub Actions → build AAB → sign → upload to Play Store (internal/draft) → create GitHub Release
