# Decisions

ADR-lite, borrowed from `rq`. Each entry records what was decided, why, and
**what would reverse it** — so a rejected idea comes back with new evidence
rather than fresh confidence.

Performance entries state the number they were measured at. Most of these were
settled in the 2026-11 polish pass between 0.1.5 and the next release.

---

## D1 — Secrets are always on

**Decided**, 2026-11-21.

No flag turns secret detection off or exposes a secret's text. `--only` and
`--except` don't accept `secret` (naming it is an error), `--keep` can't spare
one, and no output mode prints one raw: `-n` shows only the subtype, and
`--with-originals` leaves `original` off. A test,
`secrets_never_expose_original_even_with_flag`, guards it.

A missed credential is the worst thing launder can do, and every off-switch is
a way to miss one by accident. In 0.1.5, `--only path` silently disabled
secrets; someone narrowing the output to paths had no reason to expect that.

*Reverses if:* never for raw output. A secrets opt-out would need a real use
where scrubbing a secret breaks the paste, and even then it would be a separate,
loudly named flag, not a type in `--only`.

## D2 — Keyed values are gated by shape, not entropy; password words aren't gated

**Decided**, 2026-11-21.

A value under a token, secret, or key word (`api_key=`, `client_secret:`) is
scrubbed unless it looks like an identifier: words in one case, camel humps, a
date, a path, a `$VAR` or `{{template}}` reference. `client_id=OrderService`
stays; most values shaped like that are names.

This replaced a Shannon-entropy gate, which got both sides wrong:
`hunter2hunter2` scored too low and leaked, while entropy says nothing about
whether a value reads as a name.

A password word (`password`, `passwd`, `passphrase`) skips the gate. Its value
is scrubbed whatever it is, unless it is an obvious placeholder (empty,
`true`/`false`/`null`, a `***` mask, a `[FILTERED]` marker). So
`password=${DB_PASSWORD}` and `password: string` are redacted. That
over-detection is accepted: under a password key, a value that reads like a
word is still most likely a password.

*Reverses if:* real logs show password-key false positives costing readers
something they need (not just a config template looking redacted), or an
identifier-shaped value turns out to be a common real secret format.

## D3 — Repeated secrets: exact, 8+ characters, generated-looking only

**Decided**, 2026-11-21.

Once a secret is found, later copies of the same text are scrubbed with the
same placeholder (`Engine::enroll_secret`). Three limits apply: the match is
exact (case and whole token), the value is at least `MIN_REPEAT_LEN` (8)
characters, and it must look generated (`detect::secrets::looks_generated`).

Without the last limit, a keyed false positive spreads: `password: disabled` is
scrubbed at its key (D2), and enrolling it would then take every later
`disabled` in the log. The length floor does the same job for short values
like `password=test`.

*Reverses if:* a real leak shows a word-shaped password repeating unscrubbed
where the context made it obvious — and only with a way to tell it from a word
that wouldn't mangle prose.

## D4 — A login is scrubbed where it logs in, not everywhere

**Decided**, 2026-11-21.

A username from URL userinfo, `curl -u`, or `.netrc` becomes `<USER_N>` at that
site only. It is not enrolled as a bare username to match across the log.

Enrolling it mangled hosts: a postgres user `northwind` turned
`northwind-labs.com` into `<USER_2>-labs.com` and `northwind.slack.com` into
`<USER_2>.slack.com`. Logins are often service or company names, not people.
Home-directory owners and `$USER` are still enrolled; those are people.

*Reverses if:* logins in real logs turn out to be mostly personal names that
recur elsewhere unscrubbed, and bare matching can learn to skip host labels.

## D5 — Home collapse is prefix-only

**Decided**, 2026-11-21.

A home path scrubs only its personal prefix (`/Users/dpep` → `~`); the rest of
the path is ordinary text for the other detectors. The first home seen becomes
`~`, later ones `<HOME_N>`. CI runner homes (`/home/runner`, `/Users/runner`)
and `/Users/Shared` are system paths and kept.

A home span used to cover the whole path, so anything kept inside it won the
overlap and cancelled the collapse: the hash in Rust's cargo registry path
(`index.crates.io-6f17d22bba15001f`) leaked the username in nearly every Rust
backtrace. A token in a home path did the same. The runner home names a CI
machine, not a person, and `~` there would hide where the build ran.

`~` goes to the first home *in the input*, not your own `$HOME`, so a log from
another machine launders cleanly.

*Reverses if:* a reader needs the whole path treated as one unit (it is
already readable), or another non-personal home is common enough to join the
list.

## D6 — A kept ID strictly inside a wider scrub yields to it

**Decided**, 2026-11-21.

UUIDs and hex digests are kept as diagnostic IDs. When one sits strictly inside
a wider scrub span — an email or host — the scrub wins: `ops@cafebabe.io` is an
address, not a digest. A keep exactly as wide as the span still wins.

*Reverses if:* a real ID is regularly embedded in something that looks like a
contact and the reader needs it. None seen.

## D7 — Which dotted quads are IPs

**Decided**, 2026-11-21.

Private, loopback, and multicast addresses are kept (`10.0.0.4`, `127.0.0.1`,
`ff02::1`); they identify no one outside the network. A dotted quad that is a
version is kept: a product token (`Chrome/119.0.0.0`) or one after the word
`version` (`version 1.2.3.4`, `app_version`, `RestoreVersion`). A quad joined
to more numbers (an OID like `1.3.6.1.4.1.2021`) isn't an address.

`libfoo 2.17.0.1` and `appversion 1.1.1.1` stay `<IP_N>`. Nothing structural
tells `libfoo 2.17.0.1` from `host 2.17.0.1`, and accepting `version` inside a
word would let `conversion 8.8.4.4` through. Over-scrubbing a version is a
paper cut; under-scrubbing a public IP is a leak.

*Reverses if:* versions mistaken for IPs show up often enough in real traces to
hurt readability, with a shape that excludes addresses.

## D8 — A URL password with a raw `/` leaks its prefix

**Accepted**, 2026-11-21.

`https://alice:pa/ss@host` scrubs from the `/`, leaving `pa` raw. RFC 3986
requires `/` in userinfo to be percent-encoded, so this URL is malformed.
Reading past `/` to find the `@` would swallow npm-style paths like
`registry.npmjs.org/@scope/pkg`.

*Reverses if:* a common tool is found emitting unencoded `/` in URL passwords.

## D9 — Not detectors: shapes with too many false positives

**Rejected**, 2026-11-21.

- `mysql -pX`: `-p` means port, path, or profile in most tools.
  `mysql --password X` and `docker login -p X` (a fixed context) are caught.
- Bare 32- or 40-character hex: that's a git SHA or digest far more often than
  a key.
- Bare base64 without context: an AWS secret key is caught only on a line with
  its `AKIA`/`ASIA` access key ID.
- Free-floating high entropy: random-looking strings are everywhere in logs
  (build IDs, hashes, base64 payloads).

Each would scrub things readers need on most logs to catch a secret on a few.
Keyed values (D2) and known prefixes catch the common cases with context.

*Reverses if:* a specific tool's output shows one of these shapes leaking a
real credential, with a context word or prefix that narrows it.

## D10 — Literal search: `memchr::memmem`, not Aho-Corasick

**Decided**, 2026-11-21.

Bare usernames, the machine's hostnames, `$HOME`, and `--watch`/`--keep` terms
each get a prebuilt `memchr::memmem::Finder`. Switching from `str::find` cut
CPU on the 200 MB perf corpus (loaded machine, median of 5) from 6.0 s to 4.7 s
on a clean log and 3.2 s to 2.3 s on a JSON log. `memchr` was already built as
a `regex` dependency.

Aho-Corasick only wins once there are about 16 terms, measured in the same
pass. Terms come from a handful of `--watch` flags and the environment, well
under that.

*Reverses if:* `--watch` reads a file of terms (see the roadmap), which puts
the count past the crossover.

## D11 — Streaming: flush when the next read would block

**Decided**, 2026-11-21.

Output goes through a `BufWriter`, flushed whenever the input buffer holds no
complete line — the moment the next read may wait (`LineReader::would_block`).

A `BufWriter` flushed only at end of input silently broke
`tail -f app.log | launder`: nothing printed until 8 KB piled up. Flushing per
line would cost a write syscall per line on file input; flushing on would-block
costs nothing there, since a file's buffer always holds the next line.

*Reverses if:* a source turns up where the buffer holds a partial line for a
long time and output stalls — then flush on a timer too.

## D12 — An unterminated private key suppresses the rest of the input

**Decided**, 2026-11-21.

After a `BEGIN … PRIVATE KEY` line with no `END`, everything to the end of
input is suppressed, across file boundaries, and stderr says where the key
started (`FILE:LINE`).

There is no reliable way to tell where a truncated key's body stops, and
emitting a guess risks emitting key material. Losing the tail of a log is
recoverable; leaking a key isn't. The warning makes the loss visible; it used
to be silent.

*Reverses if:* key bodies prove reliably delimitable (fixed base64 line width,
say) in the logs people actually paste.

## D13 — Output modes: four, and no `-q`, `-v`, or `--profile`

**Decided**, 2026-11-21.

| Flag | Purpose |
|---|---|
| `-n` | Preview each replacement, with originals (never a secret's) |
| `-j` | One JSON document at end of input |
| `-J` | The same rows streamed as NDJSON, then a summary line |
| `-r` | Summary on stderr; stdout untouched |

`-n` used to pass input through unchanged, which showed nothing without `-r`.
`-J` streams rows per line, not per finding, so it is `-j` made incremental.

Quiet, verbose, and profiling flags were considered and not added. A filter
that prints its input has nothing to quiet; `-r` and `-n` already say what
changed; and profiling belongs in a benchmark script, not the shipped surface.

*Reverses if:* users need diagnostics launder can't express through `-n`/`-r`
(why something *wasn't* scrubbed, say).
