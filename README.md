# tuneup

A tune-up stick: menu-driven Windows maintenance that runs from removable media,
plus a sanitized diagnostic collector so a failure can be reasoned about away
from the customer's machine.

Built for PowerShell 5.1 on Windows 10/11. ASCII-only sources, no external
modules, no internet dependency beyond Windows Update itself.

---

## The one architectural rule

**Verbose logs stay on the machine being worked on. Only a sanitized report is
written to the stick.**

| What                        | Where it goes                    | Leaves the machine? |
|-----------------------------|----------------------------------|---------------------|
| Verbose run log             | `C:\ProgramData\GSTuneUp\`       | No                  |
| Resume state across reboots | `C:\ProgramData\GSTuneUp\`       | No                  |
| Sanitized report            | `<stick>\tuneup\reports\`        | Yes                 |

This is structural rather than a habit to remember at 6pm on a busy Saturday.
The only code path that writes to the stick runs the sanitizer first, verifies
the result, and **refuses to write at all** if any identifier survived.

### What the sanitizer removes

Two passes. Literals gathered from the live machine (hostname, every local
profile name, BIOS/board/system/disk serials, SMBIOS UUID, MachineGuid) go
first, longest-first so a short name cannot chew a hole in a longer one.
Literals under 4 characters are skipped entirely. Then a regex sweep for
MAC, IPv4, email, `C:\Users\<name>` paths, product keys, and GUIDs.

Volume labels are never collected - a label is free text and is very often the
owner's name. Event log **message bodies** are never collected, only IDs,
providers and counts, because the bodies are full of paths.

Product models, chipset families and KB numbers are kept. Those are generic
product facts, not customer data, and they are most of what makes the report
worth reading.

Run `tests\Test-Sanitizer.ps1` to verify on any machine. It prints pass/fail
only and never echoes a value it found.

---

## Use

Launch `RUN.cmd` from the stick. It self-elevates and bypasses execution policy,
which is what you need on a machine whose policy is Restricted and whose drive
letter is not the one you had last time.

```
1  Collect diagnostic report        read-only, safe on anything
2  Repair component store           DISM ladder, then SFC
3  Windows Update                   software only, no drivers
4  Reclaim cache space              temp, WU cache, WER, CBS logs
5  Full tune-up                     2 then 3 then 4, then report
6  Dry run of the full tune-up      prints the plan, writes nothing
7  Purge logs and state from THIS machine

Modules (type the key):
   bloatware   Bloatware inventory and removal
   browser     Browser hijack and redirect detection
```

From the menu a module **always runs read-only first**, prints what it found,
and then asks. You have to type `YES` in full before anything changes.

Non-interactive:

```powershell
.\Invoke-TuneUp.ps1 -Action Report
.\Invoke-TuneUp.ps1 -Action Full -WhatIf
.\Invoke-TuneUp.ps1 -Action Repair -SourcePath D:\sources\install.wim

.\Invoke-TuneUp.ps1 -Module bloatware                        # inventory only
.\Invoke-TuneUp.ps1 -Module bloatware -Apply                 # remove Consumer tier
.\Invoke-TuneUp.ps1 -Module bloatware -Apply -IncludeOptional -Provisioned
.\Invoke-TuneUp.ps1 -Module browser                          # detect only
.\Invoke-TuneUp.ps1 -Module browser -Apply -WhatIf           # show the fix plan
```

Default action is `Report`, which changes nothing. That is deliberately what you
get when you forget an argument.

`Full` records each completed stage, so after a reboot you re-run option 5 and
it skips what already finished rather than starting the 40-minute ladder again.

**Option 7 when the job is done.** The logs are the customer's data and there is
no reason to leave them behind.

---

## Why DISM before SFC

SFC repairs system files *using* the component store. If the store is corrupt,
SFC either fails or repairs from a bad source, and you have burned half an hour
learning nothing. The ladder is:

1. `DISM /CheckHealth` - reads a flag, takes seconds
2. `DISM /ScanHealth` - real scan, slow; skipped if CheckHealth already flagged
3. `DISM /RestoreHealth` - only if corruption was found
4. `sfc /scannow`, and a second pass if unrepaired files remain

`0x800f081f` from RestoreHealth means no usable repair source - blocked network,
dead WSUS pointer, or a genuinely gutted store. Supply `-SourcePath` pointing at
a matching `install.wim`/`.esd`.

If SFC still reports unrepairable files, the next rung is an in-place repair
install. That is above the scripted line and the tool says so rather than
attempting it.

---

## Modules — the update surface

A module is one `.ps1` in `modules\` with a `MANIFEST` block at the top. Drop
the file on the stick and it appears in the menu. Nothing else needs editing —
that is the whole mechanism for adding capability later.

```powershell
<#MANIFEST
{
  "Key": "bloatware",
  "Title": "Bloatware inventory and removal",
  "Entry": "Invoke-BloatwareModule",
  "Order": 10,
  "RequiresAdmin": true,
  "Description": "one line for the menu"
}
MANIFEST#>
```

Discovery reads that block with a regex and **does not execute the file**, so
listing the menu never runs module code and two modules can never collide on
function names. Only the selected module is dot-sourced, into the calling
function's scope. Every module must be read-only unless `-Apply` is passed,
must honour `-WhatIf`, and returns an object that gets folded into the
sanitized report.

Bump `VERSION` when you change anything. `Deploy-ToUsb.ps1` prints
`old -> new` so an update in the field says what it replaced instead of
silently overwriting.

### bloatware

Classifies every installed package into five tiers and removes only the safest:

| Tier | Meaning | Removed? |
|---|---|---|
| Consumer | Games, promo tiles, social apps. No system function. | With `-Apply` |
| Optional | Wanted by some, or holds user data, or load-bearing on some builds. | Needs `-IncludeOptional` too |
| Protected | Runtimes, store infrastructure, security UI, OEM utilities, antivirus. | Never |
| SystemComponent | System-signed or `NonRemovable` per Windows itself. | Never |
| Unclassified | Not in the catalog. | Never |

Classification is by explicit pattern, never heuristic, because "looks like
bloat" is exactly how you remove the utility that owns a laptop's fan curve.
**OEM utilities are Protected on purpose** — Lenovo Vantage, Dell Power
Manager and friends own battery charge thresholds, thermal profiles and Fn-key
handling. Antivirus is Protected because the customer may be paying for it.

The SystemComponent tier comes from Windows' own `SignatureKind`, not from the
catalog, and it overrides the catalog in the fail-safe direction. That keeps
working on builds shipping components this catalog has never seen.

Desktop (non-Store) trialware is **reported with its uninstall string and
never uninstalled** — those strings are inconsistent and several hang without
a console. Same rule as partitioning: print the command, let the tech decide.

`-Provisioned` also removes the provisioned copy, without which every new user
profile gets the junk back.

### browser

Detection is broad, repair is deliberately narrow.

**Fixed** (backed up first, and only with `-Apply`):
- Browser shortcuts with a URL appended to their arguments — the classic
  hijack. Legitimate switches like `--profile-directory="Default"` survive.
- `AutoConfigURL` / `ProxyServer` in Internet Settings — **skipped entirely if
  the machine is domain-joined**, where those are probably real management.

**Reported, never auto-fixed:** browser policy keys (including
`ExtensionInstallForcelist`, the strongest single hijack signal), installed
extensions, hosts file entries, scheduled tasks that launch a browser at a
URL, and static DNS servers.

Extensions are never removed automatically — telling a hijacker from a
password manager the customer depends on needs a human, and guessing wrong
costs them their saved logins. **Browser profiles are never deleted or
reset**; that is where bookmarks and passwords live.

Only the **host** of a redirect URL is ever recorded, never the full URL,
because hijack URLs routinely carry a machine-tied id in the query string.

## Deliberate limits

These are finished decisions, not gaps:

- **Never claims "healthy" from a check that did not run.** "Corruption found",
  "confirmed healthy" and "could not establish" are three distinct states.
  Unelevated runs mark SMART and component store as `RequiresElevation`, so a
  blank cannot be misread as a clean bill of health.
- **Event signatures match provider, not just event ID.** IDs are only unique
  within a provider; counting by ID alone reports Kernel-Processor-Power ID 55
  as NTFS corruption and sends you after a filesystem that was never broken.
- **No driver updates by default.** WU driver packages are a reliable way to
  turn a working machine into a broken one. `-IncludeDrivers` exists; it is off.
- **No Recycle Bin, no Downloads, no browser profiles.** Only caches Windows
  rebuilds itself. Emptying the bin is the customer's call, not a script's.
- **No `/ResetBase`.** Component cleanup is opt-in via
  `-IncludeComponentCleanup` and never resets the base, which would make every
  installed update permanently uninstallable.
- **Never formats, partitions or repartitions anything.** `Deploy-ToUsb.ps1`
  copies files and creates a directory. That is all it will ever do.

---

## Deploying to a stick

```powershell
.\Deploy-ToUsb.ps1                        # lists removable volumes, changes nothing
.\Deploy-ToUsb.ps1 -Destination D: -WhatIf  # prints the copy plan
.\Deploy-ToUsb.ps1 -Destination D:          # copies, then verifies
```

Refuses the live system drive outright, and refuses a fixed disk without
`-Force`. Reports are never copied *to* a stick - `reports\` on the stick is an
output directory, populated in the field.

---

## Layout

```
RUN.cmd                          launcher: elevation + execution policy
Invoke-TuneUp.ps1                entry point, menu, report writing
Deploy-ToUsb.ps1                 copy toolkit to removable media
VERSION                          bumped on change; deploy reports old -> new
lib\Common.ps1                   logging, native invocation, state, reboot checks
lib\Sanitize.ps1                 redaction and verification
lib\Modules.ps1                  module discovery and dispatch
tasks\Collect-Report.ps1         read-only diagnostic collection
tasks\Repair-ComponentStore.ps1  DISM ladder + SFC
tasks\Invoke-WindowsUpdate.ps1   WU via COM agent
tasks\Clear-TempFiles.ps1        cache reclamation
modules\Remove-Bloatware.ps1     tiered app classification and removal
modules\Repair-BrowserHijack.ps1 redirect detection, narrow repair
tests\Run-AllTests.ps1           runs every suite
tests\Test-Sanitizer.ps1         redaction
tests\Test-Modules.ps1           discovery + bloatware classification
tests\Test-BrowserHijack.ps1     shortcut detection and repair
```

---

## Testing status

Run everything with `tests\Run-AllTests.ps1`. Verified on Windows 11 24H2
(26100), PowerShell 5.1 — 83 assertions across three suites, all passing:

- **Sanitizer (21):** live hostname/account/profile-path redaction, synthetic
  MAC/IPv4/email/user-path/product-key/GUID, nested object graphs, and a
  verifier that must flag unsanitized text. Plus an independent leak check of
  a generated report against this machine's real serials.
- **Modules (41):** discovery, manifest validation, unique keys, and 28
  classification cases covering runtimes, OEM utilities, antivirus, consumer
  junk and unknowns — plus a live sweep asserting no System-signed package on
  this machine is removal-eligible.
- **Browser (21):** argument splitting, synthetic hijacked shortcut detected
  and repaired, legitimate switches preserved, query string never recorded,
  backup written before the fix, clean and non-browser shortcuts untouched.

Also verified by hand: `Report` collection and write, `-WhatIf` dry run of the
full ladder (plan printed, no report written, log still written), unelevated
degradation, and execution from the stick.

**Not yet exercised end-to-end:** the elevated write paths — actual
`RestoreHealth`, `sfc /scannow`, update installation, cache deletion, real
`Remove-AppxPackage`, and the proxy-registry fix. Their dry-run and refusal
paths are tested; the halves that change a machine are not. Those need a bench
run before you trust them on a customer's hardware.

Detection on a clean machine proves the detectors run, not that they detect.
The shortcut path is covered by synthetic fixtures; the proxy, policy,
scheduled-task and hosts detectors have not been fired against a genuinely
hijacked machine yet.
