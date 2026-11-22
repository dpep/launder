# launder roadmap

What shipped, what's known to be missing, and what's out of scope. Small on
purpose: launder is a filter, and most ideas for it are better as a decision
not to build (see [DECISIONS](DECISIONS.md)).

## Shipped

### 0.1.0 – 0.1.5 — the core filter

- [x] Streaming line pipeline: detect → resolve → number → emit
- [x] Home, temp-dir, and username scrubbing with first-seen numbering
- [x] Known-prefix tokens, JWTs, private keys, URL passwords, keyed values
- [x] Emails, public IPs, internal hosts, MACs
- [x] `$USER`, `$HOME`, hostname as a watchlist, not a pinned identity
- [x] `-j`, `-J`, `-r`, `--only`/`--except`, `--all-ips`
- [x] Homebrew tap

### Unreleased — the 2026-11 polish pass

- [x] `--watch` / `$LAUNDER_WATCH`, `--keep`, `--check`, `--completions`
- [x] Secrets always on (D1); shape gate for keyed values (D2)
- [x] Repeated secrets scrubbed after first sight (D3)
- [x] Many leak fixes and new token formats (see [CHANGELOG](../CHANGELOG.md))
- [x] Output streams through pipes (D11)
- [x] Output modes reshaped: `-n` preview, `-J` rows per line (D13)

## Known misses

Checked against `main` on 2026-11-22. Each is deferred, not rejected.

- [ ] **Template references under a key stay raw.** `token={{secret}}` and
      `token=${secret}` pass through: the identifier gate (D2) reads them as
      references, which they usually are. Only a miss if a tool expands them
      into look-alike values.
- [ ] **Camel-hump tokens under a key stay raw.** `token=SomeTokenAbcdef` is
      indistinguishable from an identifier like `TokenProvider`.
- [ ] **`file://` URLs don't collapse the home.**
      `file:///Users/alice/x.txt` becomes `file:///Users/<USER_N>/x.txt`:
      the owner is scrubbed, but the path isn't collapsed to `~`/`<HOME_N>`.
- [ ] **`--completions zsh FILE` ignores FILE.** It prints the script and exits
      0 instead of rejecting the extra argument.
- [ ] **`$SHELL` with a version suffix isn't recognised.** `SHELL=…/zsh-5.9`
      makes bare `--completions` ask for the shell by name.
- [ ] **JSON summary has no subtype breakdown.** `-r` splits secrets by
      subtype; `summary.by_type` in `-j`/`-J` doesn't.

## Candidates

- [ ] **`--watch` term file** (`--watch-file`, or a path in `LAUNDER_WATCH`)
      for teams with a long list of names. It would push the term count past
      the Aho-Corasick crossover (D10), so switch the matcher with it.

## Out of scope

Noted so they aren't designed out. Don't build these without a decision:

- Pluggable free-text detection (person names, street addresses) through an
  external interface. Core stays structural.
- Key-aware JSON mode: redact by JSON key path.
- `--fake`: realistic replacements instead of placeholders.
