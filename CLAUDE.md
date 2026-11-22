# launder development conventions

`launder` makes diagnostic output safe to paste: pipe in a stack trace or log
spew and it returns the same text with identifying paths, usernames, secrets,
and contacts replaced by readable placeholders — while preserving everything a
reader needs (relative paths, extensions, line numbers, system paths,
diagnostic IDs). Read [README.md](README.md) for the product vision.

## First principles (do not drift from these)

- **Paste-safe diagnostics, not a PII platform.** That framing is the whole
  design — small, fast, structural-only. Everything detected is structural
  (patterns, structural validation, key words, system lookup). No ML, no NER, no
  person-name or street-address detection. Free-text detection is a later,
  pluggable hook, never core.
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
`memchr` for literal-term search, `serde`/`serde_json` for structured output,
`clap` + `clap_complete` for the CLI and completions, `anyhow` for errors.
Compile regex sets once via `std::sync::LazyLock`. The environment is read
directly and the hostname from the `hostname` command — no crate.

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
    main.rs        ← shim: calls cli::run
    lib.rs         ← module list (tests drive the library)
    cli.rs         ← clap (derive) surface, --help, run loop: reader → engine → emitter
    config.rs      ← resolved run config + --only/--except type filter
    input.rs       ← streaming line reader over stdin/files
    engine.rs      ← per-line detect → resolve → assign → emit
    registry.rs    ← per-run placeholder registry + numbering
    detect/
      mod.rs       ← Candidate/Kind/Action/Label types, precedence/overlap resolution
      paths.rs     ← home/user/tmpdir collapse
      secrets.rs   ← prefixes, jwt, private keys, logins, keyed values
      net.rs       ← email, ip (private-keep), host, mac
      ids.rs       ← UUID/SHA recognizers used to PRESERVE diagnostic IDs
      literal.rs   ← case-insensitive term matcher: watchlist, --watch, --keep
    watchlist.rs   ← local-identity signal: $USER/$HOME/hostname
    emit.rs        ← text / --dry-run / JSON writers + the secret rule
    report.rs      ← --report summary
  tests/
    cases.rs       ← table-driven gold acceptance tests
    cli.rs         ← binary-level tests: streaming, exit codes, help
```

Keep it a single crate until there's a concrete reason to split. Simpler wins.

## Building, testing, linting

```sh
cargo build                 # dev build → target/debug/launder
cargo build --release       # optimized → target/release/launder
cargo test                  # unit, acceptance, and binary tests
cargo clippy --all-targets  # lint — keep it clean
cargo fmt                   # format — run before committing
```

Before committing: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`.

## Testing conventions

- The gold cases in `tests/cases.rs` are the contract: each asserts the exact
  laundered output for an `(input, flags)` pair, and determinism is part of the
  assertion. Add a row when you add behavior.
- Prefer driving the library (`Engine::process_line`) in tests over shelling out
  to the binary — faster, deterministic, no permission prompts. Behavior only
  the real process shows (streaming timing, exit codes, help, completions)
  lives in `tests/cli.rs`.
- Use generic, non-identifying test data (`dpep`, `alice`, `ops@dpep.io`) — this
  is a public repo, and the sample `dpep` is fine as a stand-in.
- The "no raw secret in any mode" invariant has a dedicated test
  (`secrets_never_expose_original_even_with_flag`). Never weaken it.
- README examples are real output. When behavior changes, re-run them with a
  fake identity (`HOME=/Users/dpep USER=dpep`) and paste what comes back.

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

Release with `release` (`~/.claude/bin/release`) from the repo root:
`release patch --steps` shows the checklist, `--dry-run` previews it, and
`release patch` runs it. It bumps `Cargo.toml` and `Cargo.lock`, tags,
publishes, and updates the tap formula
(`~/code/lib/homebrew-tools/Formula/launder.rb`, which pins the tag's tarball
and sha256). Don't do the steps by hand.

## Scope boundaries (out of scope for v1)

Noted so they're not designed out, but do not build them without a decision:
pluggable free-text (name/address) detection via an external interface;
key-aware JSON mode (redact by JSON key path); a `--fake` realistic-replacement
mode. Core stays structural.
