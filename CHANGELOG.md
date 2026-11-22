# Changelog

Notable changes to `launder`. The CLI surface — flags, output text, JSON shape,
exit codes — is the public API.

Entries from 0.1.0 to 0.1.5 are reconstructed from tags and commit messages, so
they summarise what shipped rather than every commit.

## Unreleased

### Changed (breaking)
- **JSON has a new shape.** `-j` writes
  `{"lines":[{"line","text","findings"}],"summary"}` instead of
  `{"laundered","findings","summary"}`. `-J` streams one row per input line
  (`{"line","text","findings"}`, including lines with no findings), then a
  `{"summary":…}` line; it used to stream one finding per line. Update any
  script that parses either.
- **Finding types and spans.** Home-directory and temp-dir findings report
  `type: "path"` (in JSON and `-r`) instead of `home` and `tmpdir`, and cover
  only the personal prefix (`/Users/dpep` → `~`), not the whole path. The
  `keyed_entropy` subtype is now `keyed`.
- **`-n` previews each replacement** (`LINE:COL  type  original → placeholder`)
  instead of passing the input through unchanged. It shows originals (never a
  secret's), so don't paste it. It no longer combines with `-j`/`-J`.
- **`--only` and `--except` reject `secret`.** Secrets are always scrubbed;
  naming the type is an error (exit 2). Drop `secret` from those lists.
  `--only path` used to turn secret detection off without saying so.
- A password — under a password key, in a URL, or from `curl -u` — renders as
  `<PASSWORD_N>` instead of `<SECRET_N>`.
- Multicast IPs (`224.0.0.0/4`, `ff00::/8`) are kept by default, like private
  and loopback ones. `--all-ips` scrubs them.
- `~` goes to the first home directory seen in the input, not the first
  identity.
- A login name (URL userinfo, `curl -u`, `.netrc`) is scrubbed as `<USER_N>`
  where it logs in. It used to pass through.

### Removed
- `--no-keep-system`. It did nothing (system paths are always kept); passing it
  is now an unknown-flag error, so delete it from scripts. The hidden
  `--keep-system` and `--keep-private-ips` went with it.

### Added
- `--watch TERM` scrubs your own names: a domain takes its subdomains
  (`<HOST_N>`), any other term becomes `<TERM_N>`, in any case. Set
  `LAUNDER_WATCH` in your shell rc to make terms stick.
- `--keep TERM` never scrubs a term, such as a public host you want readers to
  see. A secret is scrubbed regardless.
- `--check` exits 1 if anything was scrubbed, for hooks and CI.
- `--completions [SHELL]` prints a bash, zsh, or fish completion script.
- A secret is scrubbed wherever it repeats after it's found, with the same
  placeholder. Only values of 8+ characters that look generated spread this
  way; `password: disabled` doesn't take every later `disabled` with it.
- New token formats: Hugging Face, PyPI, DigitalOcean, Shopify, Mailgun,
  Twilio, Docker Hub PATs, and Slack and Discord webhook URLs.
- New credential shapes: `--password X`-style flags, `docker login -p`,
  `curl -u user:pass`, `.netrc` lines, `<password>` XML elements, GitHub
  Actions `::add-mask::`, an unkeyed AWS secret key on its access key's line,
  Django's `SECRET_KEY`, Apple app-specific passwords, and more key words
  (`passphrase`, `credentials`, `signature`, `session_id`, …).
- `-r` breaks the secret count down by subtype.
- `-` among the file arguments reads stdin.
- Bare `launder` at a terminal prints help instead of waiting for input.

### Fixed
- Output streams through pipes. `tail -f app.log | launder | grep …` printed
  nothing until 8 KB or end of input.
- A password key's value is redacted whatever it looks like:
  `DB_PASSWORD=hunter2hunter2` passed an entropy check and leaked. Token,
  secret, and key values are judged by shape instead of entropy, so a name like
  `OrderService` stays.
- A UUID or hex digest under a credential key (npm `_authToken`,
  `X-Amz-Signature`) is redacted, not kept as a diagnostic ID.
- Keyed values that leaked part of themselves: quoted values now run to the
  closing quote, `"authorization":"Bearer …"` and JSON cookie values are
  caught, a percent-encoded separator (`%3D`) counts, and values opening with
  `/`, `.`, `$`, `%` or `{` aren't mistaken for paths or references.
- A token inside a wider secret no longer leaves the rest of it raw; a URL
  password with an unencoded `@` no longer leaks its tail.
- A home path holding a hex digest (Rust's cargo registry) or a token collapses
  to `~` instead of leaking the username.
- `/private/var/folders/…` becomes `<TMPDIR>`, and a `pytest-of-<user>` owner
  is scrubbed.
- Usernames revealed by paths are learned even with `--except path`.
- Misreads: `git@host:org/repo` is not an email, `x.internal.acme-corp.com` is
  one host, `Chrome/119.0.0.0` and OIDs aren't IPs, `%40` emails and emails
  with a hex run (`ops@cafebabe.io`) are scrubbed.
- Text after a private key's `END` line is scanned instead of passed raw. An
  unterminated key still suppresses the rest of the input, but now says where
  it started on stderr.
- Invalid UTF-8 becomes `U+FFFD` instead of aborting the run.
- `-o` refuses to overwrite one of its inputs; it used to truncate it before
  reading.
- Error messages show `$HOME` as `~`.
- Lines with many findings are linear, not quadratic: a 3 MB line of 100k keyed
  values took ~13 s of CPU, now ~0.3 s.

## 0.1.5 — 2026-09-16

### Added
- PGP private key blocks are redacted.

## 0.1.4 — 2026-09-15

### Fixed
- Dashed `sk-` keys and Stripe test keys are caught; kebab-case names are not
  read as `sk-` keys.
- Escaped JSON keys and Rails SQL bind values are redacted.
- `author:` and shell `PWD=` / `OLDPWD=` are no longer treated as credentials.
- The rest of a line holding a private key is scanned.

## 0.1.3 — 2026-09-15

### Fixed
- Secrets directly after ANSI color codes are caught.
- Quoted, prefixed, and env-style credential keys are caught.
- URL passwords with an empty user (`redis://:pass@host`) are redacted.
- `Cookie` and `Set-Cookie` values are redacted.
- The IPv6 rule no longer rewrites Ruby constants (`Foo::Bar`).

## 0.1.2 — 2026-06-28

### Changed
- README and `--help` wording.

## 0.1.1 — 2026-06-28

### Changed
- `$USER`, `$HOME`, and the hostname are used by default as a watchlist; the
  `--system` flag and the `/etc/passwd` scan are gone.

## 0.1.0 — 2026-06-28

First release.
