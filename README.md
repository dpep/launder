launder — make logs pastesafe
=============================

**Paste-safe diagnostics, not a PII platform.** Pipe in a stack trace or log spew and `launder` hands back the same text with identifying paths, usernames, secrets, and contacts swapped for readable placeholders — while keeping everything a reader needs to actually help you: relative paths, file extensions, line numbers, system paths, and diagnostic IDs.

```sh
$ myapp 2>&1 | launder | pbcopy        # zero config: clean trace on the clipboard
```

```sh
$ launder crash.log
  /Users/dpep/code/proj/src/db.rs:42   →   ~/code/proj/src/db.rs:42
  Authorization: Bearer eyJhbGciOi...  →   Authorization: Bearer <JWT_1>
  ghp_AbCdEf0123...                    →   <TOKEN_1>
  alerts@dpep.io                       →   <EMAIL_1>
  203.0.113.7                          →   <IP_1>
```

Positionals are files; with none, `launder` reads stdin. It's streaming and line-oriented, so it works on `tail -f`. The default action is "read a stream, print it laundered" — every other behavior is a flag.

## Zero-config does the right thing

A bare `… | launder` produces clean, pasteable output with no flags. Flags are for precision, never for basic value.

The bias is asymmetric, on purpose:

- **Paths and IPs lean toward *under*-scrubbing.** System paths (`/usr`, `/etc`, …), file extensions, line numbers, private/loopback IPs, and diagnostic IDs (UUIDs, git SHAs) are kept — over-scrubbing destroys the trace's usefulness. A home path collapses to `~` but its relative tail survives intact: `/Users/dpep/code/proj/src/db.rs:42` → `~/code/proj/src/db.rs:42`.
- **Secrets lean toward *over*-detection.** A missed credential is the worst possible outcome of pasting a log, so known-prefix tokens (GitHub, AWS, Stripe, Slack, …), JWTs, private-key blocks, `Authorization:` headers, and URL passwords are always redacted, plus any high-entropy value sitting under a suspicious key (`password=`, `api_key=`).

## What it keeps vs. replaces

Replaced with readable, numbered placeholders — `<EMAIL_1>`, `<TOKEN_2>`, `<USER_1>`, … — numbered from 1 per type in first-seen order, so a repeated value reuses its placeholder and "user X did A then B" stays linkable. Kept untouched: system paths, extensions, line numbers, UUIDs, git SHAs, request IDs, and private IPs.

## Knows your machine, doesn't assume it's yours

launder reads your `$USER`, `$HOME`, and hostname (offline) and uses them as a **watchlist** — extra known-identifying tokens to scrub on sight, so your username gets caught even where no home path reveals it, and your machine name gets redacted. It's pure signal: it never *pins* your identity or imposes ordering. So a trace generated on your laptop and one you pulled from a remote box both launder cleanly — on a remote log the subject is whoever appears (they become `~`), and your local names simply stay inert because they don't show up. No flag, no config.

## No persistence, ever

Consistency is per-run only. The mapping from value to placeholder lives in memory and is discarded at exit — **no file is written, ever.** A persisted map would be a re-identification key, and that's the one thing a tool like this must never leave behind. Two separate runs need not agree on numbering; that's intended. No network, no telemetry, no config file.

## Install

```sh
brew install dpep/tools/launder    # builds from source; no runtime deps
```

Or build it yourself — `launder` needs Rust only at build time:

```sh
cargo install --path .             # or: make install
```

## Usage

```sh
launder [FILE...]            # files, or stdin if none
launder -o/--output FILE     # write laundered text to FILE (default: stdout)
launder --no-keep-system     # scrub OS paths too (kept by default)
launder --all-ips            # scrub private/loopback IPs too (kept by default)
launder --only TYPES         # comma list: path,secret,email,ip,host,mac,user
launder --except TYPES       # run everything except these types
launder -r/--report          # summary of what changed (counts by type) → stderr
launder -n/--dry-run         # detect + report, pass input through UNCHANGED
launder -j/--json            # buffered: one object {laundered, findings, summary}
launder -J/--ndjson          # streaming: one JSON finding per line
launder --with-originals     # include original values in JSON (never for secrets)
launder -h/--help · -V/--version
```

`-j` and `-J` replace the default text output with structured output; `--report` adds a stderr summary without touching stdout. **One rule overrides everything:** a raw secret never appears in any output mode — `--with-originals` is honored for paths, emails, and the like, but never for a secret.

## How it works

A short streaming pipeline, one line in flight:

**read line → detect spans → resolve overlaps → assign placeholders → emit.**

1. **Detect** runs structural matchers only — known prefixes, structural validation (IP octet ranges, JWT segment shape, UUID/SHA recognition), entropy under a key, and a local-identity signal ($USER / $HOME / hostname, used as a watchlist). No ML, no NER, no network.
2. **Resolve** reduces overlapping matches to a non-overlapping set by precedence (a credentialed URL is caught as one credential, not split into host + path).
3. **Assign** maps each distinct value to a stable placeholder for the life of the run.
4. **Emit** substitutes spans, honoring the secret rule.

See [CLAUDE.md](CLAUDE.md) for development conventions.

## License

MIT © Daniel Pepper
