launder — share logs safely
===========================

Pipe in a stack trace or log spew and `launder` hands back the same text with identifying paths, usernames, secrets, and contacts swapped for readable placeholders. Everything a reader needs to help you stays: relative paths, extensions, line numbers, system paths, diagnostic IDs.

```sh
myapp 2>&1 | launder | pbcopy        # clean trace on the clipboard
```

Given this `crash.log`, written by user `dpep`:

```text
thread 'main' panicked at /Users/dpep/code/proj/src/db.rs:42:7
  connecting to postgres://dpep:hunter2@db.acme-corp.com:5432/app
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkcGVwIn0.c2lnbmF0dXJlX2hlcmVfMTIz
  GITHUB_TOKEN=ghp_AbCdEf0123456789AbCdEf0123456789AbCd
  notify ops@dpep.io from 203.0.113.7 (via 10.0.0.4)
  cache at /var/folders/xy/abc123/T/proj-cache, request 3f2b8c1e-9d4a-4b6e-8f1a-2c3d4e5f6a7b
  /Users/alice/shared/notes.txt owned by alice, Chrome/119.0.0.0
```

`launder crash.log` prints:

```text
thread 'main' panicked at ~/code/proj/src/db.rs:42:7
  connecting to postgres://<USER_1>:<PASSWORD_1>@db.acme-corp.com:5432/app
  Authorization: Bearer <JWT_1>
  GITHUB_TOKEN=<TOKEN_1>
  notify <EMAIL_1> from <IP_1> (via 10.0.0.4)
  cache at <TMPDIR>/proj-cache, request 3f2b8c1e-9d4a-4b6e-8f1a-2c3d4e5f6a7b
  <HOME_2>/shared/notes.txt owned by <USER_2>, Chrome/119.0.0.0
```

No flags, no config. It streams a line at a time, so `tail -f app.log | launder` works too.

## What gets replaced

| Placeholder | Replaces |
|---|---|
| `~`, `<HOME_N>` | A home-directory prefix (`/Users/dpep`, `/home/alice`); the path after it is kept. The first home seen becomes `~`. |
| `<USER_N>` | A username: a home's owner (same `N` as its `<HOME_N>`), your `$USER`, a login |
| `<TMPDIR>` | The per-user temp dir (`/var/folders/…/T`) |
| `<EMAIL_N>` | An email address |
| `<IP_N>` | A public IPv4 or IPv6 address |
| `<HOST_N>` | An internal hostname (`*.internal`, `*.local`, `*.corp`), your machine's name, a `--watch` domain |
| `<MAC_N>` | A MAC address |
| `<TERM_N>` | A `--watch` term that isn't a domain |
| `<TOKEN_N>` | A token with a known prefix (`ghp_`, `sk_live_`, `AKIA`, Slack webhooks, …) or in a login slot (`docker login -p`) |
| `<JWT_N>` | A JSON Web Token |
| `<SECRET_N>` | The value under a token, secret, or key word (`api_key=`, `client_secret:`), unless it looks like an identifier |
| `<PASSWORD_N>` | The value under a password word, or the password in a URL or `curl -u` |
| `<PRIVATE_KEY>` | A whole PEM private-key block |

Numbers count per type in first-seen order, so a repeated value keeps its placeholder and "user X did A, then B" stays readable. Usernames and hostnames match in any case. Numbering lives only for one run: two runs number independently, and nothing is written to disk.

A login (URL userinfo, `curl -u`, `.netrc`) is scrubbed where it logs in, not everywhere the word appears.

## What it keeps

The bias is lopsided on purpose. Over-scrubbing a trace makes it useless, so paths and addresses lean toward keeping:

- system paths (`/usr`, `/etc`, `/var/log`) and CI runner homes (`/home/runner`)
- file extensions, relative paths, line and column numbers
- UUIDs, git SHAs, request IDs
- private and loopback IPs (`10.0.0.4`, `127.0.0.1`) unless you pass `--all-ips`
- version numbers that look like IPs (`Chrome/119.0.0.0`)
- public hostnames (`api.github.com`, `db.acme-corp.com`)

A leaked credential is the worst outcome, so secrets lean the other way: if it's under a credential word, it goes.

## What it won't catch

launder is structural: it matches shapes, prefixes, and key words. It does not understand prose. It misses:

- **Names and street addresses.** `Jane Doe, 1 Main St` passes through.
- **Your company's public hostnames.** `api.acme-corp.com` looks like any other public host. `--watch acme-corp.com` fixes that (see below).
- **Bare tokens.** A random string with no known prefix and no credential word next to it (`session q7Xr2mLp9vZ4tK8sW1nB expired`) stays.
- **Identifier-shaped values.** A single word or camel-case value, even under a key (`secret=HunterTwo`, `client_id=OrderService`), stays; most of those are names, not secrets.
- **A password repeated in free text.** `password: Spring2026!` is scrubbed; the same string later on a line with no password word is not.
- **Customer and account IDs.** `cus_48213`, `acct 99812231` stay.

Read what you paste. launder makes that quick; it doesn't make it optional.

## Checking its work

Preview each replacement with `-n` (this shows originals, so don't paste it):

```text
$ launder -n crash.log
1:27     path    /Users/dpep → ~
2:28     user    dpep → <USER_1>
2:33     secret  [url_credential] → <PASSWORD_1>
3:25     secret  [jwt] → <JWT_1>
4:16     secret  [github] → <TOKEN_1>
5:10     email   ops@dpep.io → <EMAIL_1>
5:27     ip      203.0.113.7 → <IP_1>
6:12     path    /var/folders/xy/abc123/T → <TMPDIR>
7:3      path    /Users/alice → <HOME_2>
7:42     user    alice → <USER_2>
```

Add a summary on stderr with `-r`; stdout is untouched:

```text
$ launder -r crash.log > clean.log
launder: 10 replacements
  email   1
  ip      1
  path    3
  secret  3  (github 1, jwt 1, url_credential 1)
  user    2
```

For tooling, `-j` writes one JSON document at end of input, and `-J` streams the same rows as NDJSON: one per input line, then a summary line. `--with-originals` adds each finding's original text:

```text
$ echo 'key=ghp_AbCdEf0123456789AbCdEf0123456789AbCd mail ops@dpep.io' | launder -J --with-originals
{"line":1,"text":"key=<TOKEN_1> mail <EMAIL_1>","findings":[{"type":"secret","subtype":"github","col":5,"len":40,"replacement":"<TOKEN_1>"},{"type":"email","col":51,"len":11,"replacement":"<EMAIL_1>","original":"ops@dpep.io"}]}
{"summary":{"total":2,"by_type":{"email":1,"secret":1}}}
```

`col` and `len` count characters (not bytes) in the input line; `col` starts at 1.

One rule beats every flag: **a raw secret never appears in any output.** `-n` shows only its subtype, and `--with-originals` leaves `original` off. A dedicated test (`secrets_never_expose_original_even_with_flag` in [tests/cases.rs](tests/cases.rs)) guards it. The exception you choose yourself: `--only` and `--except` can turn the `secret` type off.

In a hook or CI, `--check` exits 1 if anything was scrubbed:

```sh
git diff | launder --check -r > /dev/null
```

## Company terms

launder can't know `acme-corp.com` is yours. Tell it with `--watch`:

```text
$ launder --watch acme-corp.com,hooli acme.log
GET https://<HOST_1>/v2/orders failed (deploy by <TERM_1> bot)
retrying via <HOST_2>; see https://github.com/acme/app/issues/12
```

A domain takes its subdomains, in any case (`build.ACME-CORP.COM` → `<HOST_2>`). Any other term becomes `<TERM_N>`. Watched terms are scrubbed whatever `--only` and `--except` say.

To make them stick, set `LAUNDER_WATCH` in your shell rc. It takes the same comma- or space-separated list:

```sh
export LAUNDER_WATCH="acme-corp.com hooli"
```

The opposite is `--keep`: never scrub a term, such as a public host you want readers to see. A wider match that contains it is still scrubbed (`ops@acme-corp.com` under `--keep acme-corp.com`), and a secret is always scrubbed.

## Usage

```text
launder [OPTIONS] [FILES]...
```

Files are read in order; `-` or no files reads stdin. Bare `launder` at a terminal prints help.

| Flag | |
|---|---|
| `-n, --dry-run` | Show each replacement instead of the text (not for pasting: shows originals) |
| `-j, --json` | JSON: {lines: [{line, text, findings}], summary}, written at EOF |
| `-J, --ndjson` | Like -j, streamed: one row per line, then a summary line |
| `--with-originals` | Add each finding's original text to -j/-J output (never a secret's) |
| `-o, --output <FILE>` | Write output to FILE instead of stdout |
| `-r, --report` | Also print a summary of what changed to stderr |
| `--check` | Exit 1 if anything was scrubbed, 0 if clean (for hooks and CI) |
| `--completions [<SHELL>]` | Print a completion script for bash, zsh, fish, ... (default: $SHELL) |
| `--watch <TERM>` | Also scrub TERM, any case; a domain takes its subdomains (also $LAUNDER_WATCH) |
| `--keep <TERM>` | Never scrub TERM, e.g. a public host. Secrets are scrubbed regardless |
| `--only <TYPES>` | Scrub only these types: path,secret,email,ip,host,mac,user |
| `--except <TYPES>` | Scrub every type except these (same names as --only) |
| `--all-ips` | Also scrub private and loopback IPs (kept by default) |

`-n` doesn't combine with `-j`/`-J`, and `--with-originals` needs one of them. `--watch` and `--keep` repeat.

Exit codes: `0` success (with `--check`, nothing needed scrubbing), `1` `--check` found something, `2` error.

A few behaviors worth knowing:

- Invalid UTF-8 becomes `U+FFFD` and the run continues.
- A private key with no `END` line suppresses everything after it, and a warning on stderr says where it started.
- `-o` refuses to overwrite one of its inputs, including a redirected stdin.

## Install

```sh
brew install dpep/tools/launder
```

Or build from source (Rust is needed only to build):

```sh
cargo install --path .
```

Shell completions:

```sh
launder --completions bash > ~/.local/share/bash-completion/completions/launder
launder --completions zsh > "${fpath[1]}/_launder"
launder --completions fish > ~/.config/fish/completions/launder.fish
```

## How it works

One line in flight: **detect → resolve → number → emit.**

1. **Detect** runs structural matchers only: known token prefixes, credential key words, shape checks (IP octets, JWT segments, UUIDs and SHAs to keep), and your `$USER`, `$HOME`, and hostname as a watchlist. No ML, no network.
2. **Resolve** picks one match per span by precedence, so a credentialed URL is caught as a login and password, not split into host and path.
3. **Number** gives each distinct value its placeholder for the rest of the run.
4. **Emit** substitutes the spans, holding to the secret rule.

Your own identity is a watchlist, not an assumption: on a log pulled from another machine, whoever's home appears first becomes `~`, and your local names simply never match.

See [CLAUDE.md](CLAUDE.md) for development conventions.
