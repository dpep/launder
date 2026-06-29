# launder development conventions

`launder` makes diagnostic output safe to paste: pipe in a stack trace or log
spew and it returns the same text with identifying paths, usernames, secrets,
and contacts replaced by readable placeholders — while preserving everything a
reader needs (relative paths, extensions, line numbers, system paths,
diagnostic IDs). Read [README.md](README.md) for the product vision.

## First principles (do not drift from these)

- **Paste-safe diagnostics, not a PII platform.** That framing is the whole
  design — small, fast, structural-only. Everything detected is structural
  (patterns, structural validation, entropy, system lookup). No ML, no NER, no person-name
  or street-address detection. Free-text detection is a later, pluggable hook,
  never core.
- **No persistence. No mapping file on disk, ever.** Consistency is per-run
  only; the registry lives in memory and is discarded at exit. A persisted map
  is a re-identification key — never write one. No network, no telemetry, no
  config-file requirement.
- **Never emit a raw secret in any mode**, including JSON/ndjson. This rule
  overrides `--with-originals` and everything else. A dedicated test guards it.
- **Zero-config does the right thing.** Bare `… | launder` must produce clean,
  pasteable output with no flags. Flags are for precision, never for value.
- **Deterministic within a run.** First-seen order drives numbering; same input
  → same output on a given machine. Stable ordering everywhere — no HashMap
  iteration leaking into output. (The local-identity watchlist means output can
  differ across machines — that's intended; shareability, not portability, is
  the goal.)
- **Asymmetric bias by type.** Paths/IPs bias toward *under*-scrubbing (keep
  system paths, extensions, private IPs, diagnostic IDs). Secrets bias toward
  *over*-detection (a missed credential is the worst outcome).
- **Streaming, line-oriented.** Process a line at a time so it works on
  `tail -f`; constant memory in text and ndjson modes. Only `-j` buffers.

## Language and toolchain

Rust, single statically-linkable binary, no runtime deps. `regex` for matching,
`serde`/`serde_json` for structured output, `clap` for the CLI, `anyhow` for
errors. Compile regex sets once via `std::sync::LazyLock`. The environment and
hostname are read directly — no crate.

This machine's Rust came via Homebrew's keg-only `rustup`, so `cargo` may not be
on `PATH`. Either add it once —

```sh
echo 'export PATH="/opt/homebrew/opt/rustup/bin:$PATH"' >> ~/.bash_profile
```

— or invoke directly: `/opt/homebrew/opt/rustup/bin/cargo`.

## Repo layout

Single crate (published as `launder`, binary `launder`); modules mirror the
pipeline.

```text
launder/
  Cargo.toml
  src/
    main.rs        ← wire: cli → reader → engine → emitter
    cli.rs         ← clap (derive) surface
    config.rs      ← resolved run config + --only/--except type filter
    input.rs       ← streaming line reader over stdin/files
    engine.rs      ← per-line detect → resolve → assign → emit
    registry.rs    ← per-run placeholder registry + numbering
    detect/
      mod.rs       ← Candidate/Kind/Action types, precedence/overlap resolution
      paths.rs     ← pillar 1: home/user/tmpdir collapse
      secrets.rs   ← pillar 2: prefixes, jwt, keys, url-creds, keyed entropy
      net.rs       ← email, ip (private-keep), host, mac
      ids.rs       ← UUID/SHA recognizers used to PRESERVE diagnostic IDs
    system.rs      ← local-identity signal: $USER/$HOME/hostname watchlist
    emit.rs        ← structured-output writers + the secret rule
    report.rs      ← --report summary
  tests/
    cases.rs       ← table-driven gold acceptance tests
```

Keep it a single crate until there's a concrete reason to split. Simpler wins.

## Building, testing, linting

```sh
cargo build                 # dev build → target/debug/launder
cargo build --release       # optimized → target/release/launder
cargo test                  # unit + acceptance tests
cargo clippy --all-targets  # lint — keep it clean
cargo fmt                   # format — run before committing
```

Before committing: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`.

## Testing conventions

- The gold cases in `tests/cases.rs` are the contract: each asserts the exact
  laundered output for an `(input, flags)` pair, and determinism is part of the
  assertion. Add a row when you add behavior.
- Prefer driving the library (`Engine::process_line`) in tests over shelling out
  to the binary — faster, deterministic, no permission prompts.
- Use generic, non-identifying test data (`dpep`, `alice`, `ops@dpep.io`) — this
  is a public repo, and the sample `dpep` is fine as a stand-in.
- The "no raw secret in any mode" invariant has a dedicated test. Never weaken
  it.

## Landing changes

Solo project — commit or merge directly to `main` and push; skip the PR
ceremony. Keep changes small, focused, and logically connected; change behavior
or structure, not both at once. Make sure CI is green
(`cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`)
before pushing.

## Versioning / releasing

Bump the version when a change reaches users — i.e. it alters the built binary
(behavior, a flag, a detector, even `--help`/output wording). Stay below 1.0 —
only minor or patch bumps, never major:

- **patch** (`0.1.x`) — fixes, output/`--help` wording, internal cleanups
- **minor** (`0.x.0`) — new user-facing capability (a flag, a detector)

Repo-only docs (README, CLAUDE.md) don't bump — they don't change what `brew`
builds.

A bump is three edits, landed together:

1. `Cargo.toml` `version`
2. `Cargo.lock` — run `cargo build` so the `launder` entry updates
3. the Homebrew formula `version` in
   `~/code/lib/homebrew-tools/Formula/launder.rb` (push the tap too)

## Scope boundaries (out of scope for v1)

Noted so they're not designed out, but do not build them without a decision:
pluggable free-text (name/address) detection via an external interface;
key-aware JSON mode (redact by JSON key path); a `--fake` realistic-replacement
mode. Core stays structural.
