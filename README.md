# SafePaste

A local secret guard for the Linux clipboard.

Repository scanners catch secrets at commit time. Nothing catches them at *paste*
time — and pasting into a browser, an LLM chat, Slack or a ticket is the last
unguarded hop a credential takes before it leaves your machine. SafePaste sits at
the clipboard rather than inside any one application, so it behaves the same in
VS Code, a terminal, Chrome, Slack or ChatGPT.

Everything runs locally: no network calls at runtime, no clipboard content in
logs, no clipboard history on disk.

## The default is fail-safe

In the default `redact` mode, the clipboard is replaced **before** you are asked
anything:

```
copy a secret
      ↓   (the clipboard already holds the redacted text)
┌────────────────────────────────────────────┐
│ ⚠ 2 secrets removed from the clipboard     │
│   ✓ AWS access token   ✓ GitHub PAT        │
│   12,481 characters were kept intact.      │
│   [ Restore original ]  [ OK ]             │
│   ☐ Never flag this value again            │
└────────────────────────────────────────────┘
```

Ignore the dialog, dismiss it by accident, or kill the daemon mid-decision, and
you are still safe — the swap has already happened. Asking first and replacing
second would leave the raw secret on the clipboard during precisely the window in
which you are distracted.

Only the value is replaced, never the surrounding text:

```
AWS_SECRET_ACCESS_KEY=wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u
DATABASE_URL=postgres://svc_user:h1ghlyS3cretPw@db.internal:5432/prod
```
becomes
```
AWS_SECRET_ACCESS_KEY=[REDACTED]
DATABASE_URL=postgres://svc_user:[REDACTED]@db.internal:5432/prod
```

Other modes are available from Preferences: `ask` (leave the original, ask first),
`notify` (notification only, clipboard untouched) and `off`.

## Install

```sh
./packaging/build-deb.sh
sudo apt install ./dist/safepaste_0.1.0_all.deb
```

The package enables a **systemd user unit**, so protection starts at your next
login. To start it in the session you already have open:

```sh
systemctl --user start safepaste.service
```

Then bind the on-demand shortcut (as yourself, not root — it writes your
gsettings):

```sh
python3 -m safepaste.hotkey install     # Ctrl+Alt+V
```

Without root, `./install.sh` installs under `~/.local` instead. Either way you
need two packages from the archive:

```sh
sudo apt install python3-xlib python3-regex
```

## Usage

- **Tray icon** — current state at a glance, plus mode switching, *Pause 15
  minutes*, *Sanitise clipboard now*, Preferences and Quit.
- **Ctrl+Alt+V** — sanitise whatever is on the clipboard right now, on demand.
- **Preferences** — protection mode, how long *Restore original* stays available,
  the replacement text, and which categories of secret to look for.

The command-line tool works headless and needs no daemon:

```console
$ printf 'AWS_SECRET_ACCESS_KEY=wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u\n' | safepaste scan -
1:23  generic-api-key  Generic API key  (40 chars, entropy 5.12)

$ echo "$SOMETHING" | safepaste redact - > clean.txt
safepaste: redacted 1 secret(s) (40 chars replaced, 23 kept) [Generic API key]

$ safepaste rules --stats
total rules: 231
  API keys 77 / Access tokens 135 / Passwords 10 / Private keys 2 /
  Connection strings 4 / JWTs 2 / High entropy strings 1
active by default: 230  opt-in: 1  vetoed: 0

$ printf 'hunter2' | safepaste hash          # for hand-writing an exclusion
f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7
```

`scan` exits 1 when it finds something and 0 when clean, so it composes in
pipelines. `--json` output carries rule ids, offsets and entropy — never the
secret value.

## How it works on Wayland

The interesting part, because the obvious approach does not work. Everything
below was measured on Ubuntu 24.04 / GNOME Shell 46 / Wayland, and
`scripts/probe-clipboard.py` re-checks it on any machine.

**A background Wayland client cannot watch the clipboard.** Mutter implements
neither `zwlr_data_control_manager_v1` nor `ext_data_control_manager_v1`, so
`wl-paste --watch` refuses to start ("requires a compositor that supports the
wlroots data-control protocol"). Mutter also gates clipboard reads on keyboard
focus, so an unfocused GTK4 client reading the clipboard gets an *empty* one —
not an error, just nothing. A daemon has no Wayland vantage point at all.

**So monitoring goes through the XWayland selection bridge.** Mutter mirrors the
clipboard into the X11 `CLIPBOARD` selection byte-for-byte in both directions, and
XFIXES delivers a `SetSelectionOwnerNotify` for every change — including changes
made by Wayland-native applications. That is event-driven, with no polling.

Two details cost real debugging time and are worth knowing if you touch
`safepaste/clipboard/monitor.py`, because both fail *silently*:

- python-xlib binds `select_selection_input` onto the `Display`, not the `Window`,
  unlike most Xlib wrappers.
- `extension_add_subevent` registers a dynamically-generated **copy** of the event
  class, so `isinstance(ev, xfixes.SetSelectionOwnerNotify)` is always `False` and
  quietly discards every event. Match the `(type, sub_code)` tuple instead.

Also note the X11 selection owner is permanently Mutter's XWayland proxy window
and never changes, so a polling fallback has to hash content — watching the owner
id will never fire.

**Writes go out through `wl-copy`**, the authoritative direction; Mutter mirrors
them back to X11.

### Known limitations, stated plainly

- **Rich formatting is dropped when redacting.** `wl-copy` serves one MIME type
  per invocation, so replacing a selection that carried `text/html` leaves plain
  text only. Safety wins, and the dialog says so. Serving several flavours needs a
  resident selection source of our own.
- **Nothing happens while the screen is locked.** wl-clipboard has no
  clipboard-management protocol available, so it falls back to creating a surface
  and waiting for keyboard focus — which the lock screen never yields. `wl-copy`
  and `wl-paste` then block in `poll()` indefinitely (confirmed by strace; lock
  your screen and run `wl-paste` to see it). SafePaste watches
  `org.gnome.ScreenSaver` and skips clipboard work while locked, which is also the
  behaviourally correct answer, since nothing can paste then anyway. GNOME
  additionally unloads shell extensions while locked, so the tray icon disappears
  and re-registers on unlock.
- **Per-application policy is not implemented.** "Always redact into a browser,
  never into my password manager" needs to know which window has focus, and
  `org.gnome.Shell.Introspect` returns `Access denied` to unsandboxed callers —
  both `GetWindows` and `GetRunningApplications`. There is no other public API for
  it, so this genuinely requires an optional GNOME Shell extension, which does not
  exist yet. The daemon's D-Bus interface (`dev.safepaste.Daemon`, with
  `Inspect` / `Redact` / `SafePaste`) is deliberately shaped as the seam for one:
  an extension can grab a real Ctrl+V in-compositor, see the focused app id, and
  call in here for detection.
- **Ctrl+V itself is not intercepted.** GNOME 46 has no `GlobalShortcuts` portal,
  so the shortcut goes through gnome-settings-daemon's custom-keybindings — a
  compositor-level grab, which is what makes it work everywhere. Grabbing `Ctrl+V`
  there would route every paste on the system through a process spawn, and a
  daemon that died would leave the machine unable to paste at all. `Ctrl+Shift+V`
  was avoided because it is already GNOME Terminal's paste, and a compositor grab
  silently outranks an application accelerator. `safepaste/hotkey.py` reports such
  conflicts before taking a binding.

### Environment inheritance

The systemd **user** unit needs `WAYLAND_DISPLAY`, `DISPLAY` and
`DBUS_SESSION_BUS_ADDRESS`. Under GNOME these are already in the user manager's
environment: gnome-session pushes them in with `systemctl --user
import-environment` (and via `dbus-update-activation-environment`) before
`graphical-session.target` is reached, which is why the unit orders itself
`After=graphical-session.target`. If you run the daemon from a unit of your own,
outside a GNOME session, you must export those three yourself.

## Privacy

- **No network at runtime.** Rules are vendored at build time from a pinned
  Gitleaks tag; the installed package never fetches anything.
- **No clipboard content in logs.** Log records carry rule ids, offsets, counts and
  timings only, and a test asserts the secret literal never reaches a log record.
- **No clipboard history on disk.** There is no history feature.
- **Exclusions are SHA-256 digests.** "Never flag this value again" stores a hash,
  never the value. `~/.config/safepaste/` is `0700` and `config.toml` is `0600`.
- **The honest caveat:** *Restore original* works by holding the pre-redaction
  value in process memory for the retention window (60 seconds by default). This
  machine has swap enabled, so that memory can reach disk. The window is short and
  the buffer is dropped afterwards, but Python cannot guarantee the bytes are
  scrubbed from the heap. Set `restore_timeout_secs = 0` in
  `~/.config/safepaste/config.toml` to disable the undo entirely if that trade is
  not worth it to you.

## Detection

Built on the [Gitleaks](https://github.com/gitleaks/gitleaks) rule set, vendored
at a **pinned tag** (see `safepaste/detector/data/gitleaks.provenance.json` for
the tag, digest and rule counts) plus SafePaste's own detectors for gaps that
matter more on a clipboard than in a repository: database URLs with inline
credentials, `Authorization:` headers as pasted from devtools, kubeconfig client
keys and tokens, `.netrc` passwords, AWS session tokens, and plain password
assignments.

The pipeline order *is* the false-positive strategy: literal-keyword prefilter →
regex → Shannon entropy → allowlists → your exclusions. So
`const token = "hello-world";` is rejected twice over, by the allowlist and by
entropy.

Two things surprise people:

- **`AKIAIOSFODNN7EXAMPLE` is deliberately not flagged.** Upstream allowlists
  documentation placeholders — `aws-access-token` carries the allowlist regex
  `.+EXAMPLE$`, and `generic-api-key` carries a ~1500-entry stopword list that
  includes `example`. That is correct scanner behaviour, but it makes the canonical
  AWS doc keys a misleading thing to test with. Use a realistic invented key.
- **Go RE2 is not Python `re`.** 25 of the 221 upstream patterns fail to compile
  under the standard library (mid-pattern `(?i)`, `\z`), which is why the `regex`
  module is a hard dependency rather than a convenience. It also supplies the
  per-call `timeout=` that bounds RE2-shaped patterns running on a backtracking
  engine.
- **Even `regex` needs a nudge, and the failure is silent.** RE2's `\z`
  (end of text) is spelled `\Z` in Python, and Ubuntu 24.04's
  `python3-regex 0.1.20221031` rejects `\z` outright, while a pip-installed
  modern `regex` accepts it. Four upstream rules use it. `translate_re2()`
  rewrites the anchor at load time; without it the installed package quietly ran
  four detectors short on the distro it targets, with nothing but a log line to
  say so. `RuleSet.compile_failures` and a test now make that condition loud —
  worth knowing if you ever bump the pinned tag and a new RE2-ism appears.

### Custom rules

Drop Gitleaks-format TOML into `~/.config/safepaste/rules/*.toml` — the same
schema, parsed by the same code, so there is nothing new to learn. Reusing an
existing rule id **replaces** it, which is how you retune a vendored rule without
editing the vendored copy. Two SafePaste-only keys are honoured:

- `enabled = false` — an absolute veto, for silencing one vendored rule you
  disagree with. Wins even when its category is switched on.
- `default_off = true` — ships inactive but switchable, for anything too noisy to
  have on by default. This is how the high-entropy detector stays opt-in.

## Development

```sh
python3 -m venv --system-site-packages .venv   # for the distro's PyGObject/GTK4
.venv/bin/pip install regex python-xlib pytest
.venv/bin/python -m pytest -q                  # 86 tests
```

`--system-site-packages` is required: GTK4 and libadwaita come from the distro's
PyGObject and cannot be pip-installed.

Two diagnostics are worth knowing about:

```sh
.venv/bin/python scripts/probe-clipboard.py    # can we see clipboard changes here?
.venv/bin/python scripts/verify-live.py        # full loop against the real clipboard
```

`probe-clipboard.py` is the one to run first if monitoring ever appears broken —
it re-derives every assumption above on the machine in front of you, and both
scripts save and restore your clipboard. `verify-live.py` refuses to run while the
screen is locked rather than appearing to hang.

To refresh the rule set:

```sh
.venv/bin/python scripts/fetch-rules.py --tag vX.Y.Z   # validates every rule
.venv/bin/python scripts/fetch-rules.py --check        # offline digest + compile check
```
