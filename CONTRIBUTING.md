# Contributing

Thanks for improving Frostwall Beam. This project is security-sensitive: keep changes focused, preserve validation and error handling, and do not weaken pairing, encryption, path confinement, or receiver approval.

## Repository workflow

The upstream repository intentionally keeps only the `main` branch.

- External contributors: fork the repository, work in your fork, and open a pull request.
- Maintainers: prefer small, reviewable commits directly on `main` or pull requests from a fork.
- Do not push feature or bot branches to the upstream repository.
- Never commit secrets, certificates, pairing invites, or real user files.

## Before submitting

Run all verification commands from the repository root:

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm build
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

A network-dependent subset of Rust tests is intentionally marked `#[ignore]` because CI cannot guarantee multicast or public relay access. Do not unignore a test unless it is deterministic in CI.

## Change guidelines

- Keep each change scoped; avoid unrelated formatting or refactors.
- Match the existing Rust, TypeScript, and React style.
- Update Turkish and English strings together in `src/i18n.tsx`.
- Update documentation when behavior, setup, security assumptions, or operator workflows change.
- Add or adjust tests for protocol, parser, filesystem, session lifecycle, and security-sensitive changes.
- Preserve backward compatibility for persisted settings and documented invite formats when practical.

## Commit and pull request expectations

- Use concise commit messages that explain user-visible or security-relevant impact.
- Describe the threat model impact for security changes.
- Include the verification commands you ran and their results.
- For UI changes, include screenshots or a short screen recording when possible.

## Security issues

Do not report vulnerabilities in public issues or pull requests. Use the private process in [SECURITY.md](SECURITY.md).
