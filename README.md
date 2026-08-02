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
MAC, IPv4, email, `C:\Users\<name>` paths, product keys, GUIDs, and account
SIDs (`S-1-5-21-...`, `S-1-12-1-...`). Well-known SIDs like `S-1-5-18` are
deliberately kept — they are identical on every Windows machine, so they
identify nobody and are worth having for diagnosis.

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
   startup     Startup item inventory and control
   browser     Browser hijack and redirect detection
   driver      Driver problem and rollback assistant
   stress      Load and stability testing
   network     Network diagnosis and repair
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
.\Invoke-TuneUp.ps1 -Module startup                          # inventory only
.\Invoke-TuneUp.ps1 -Module startup -Apply                   # disable Optional tier
.\Invoke-TuneUp.ps1 -Module startup -Apply -Restore          # undo all of the above
.\Invoke-TuneUp.ps1 -Module browser                          # detect only
.\Invoke-TuneUp.ps1 -Module browser -Apply -WhatIf           # show the fix plan
.\Invoke-TuneUp.ps1 -Module driver                           # diagnose only
.\Invoke-TuneUp.ps1 -Module driver -Apply                    # only creates a restore point
.\Invoke-TuneUp.ps1 -Module stress                           # preflight, no load
.\Invoke-TuneUp.ps1 -Module stress -Apply -Minutes 10        # sustained load with telemetry
.\Invoke-TuneUp.ps1 -Module stress -Apply -MaxTempC 90       # lower the abort threshold
.\Invoke-TuneUp.ps1 -Module network                          # walk the ladder, change nothing
.\Invoke-TuneUp.ps1 -Module network -Apply                   # safe repairs only
.\Invoke-TuneUp.ps1 -Module network -Apply -Disruptive       # + winsock / stack reset (reboot)
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

### startup

**Disables, never deletes.** It writes to the same `StartupApproved` keys Task
Manager uses, so the original `Run` value and its command line stay intact and
the customer can re-enable anything themselves from Task Manager > Startup.
Deleting a `Run` entry throws away the command line, and reconstructing one
from memory on a machine you no longer have is not a repair.

Covers `HKLM`/`HKCU` `Run` (both bitnesses) and both Startup folders, showing
current enabled/disabled state. Same tiering as bloatware — Protected,
Optional, Unclassified — with an important asymmetry:

> Protected patterns may be **broad**: over-matching just means declining to
> disable something. Optional patterns must be **specific**: over-matching
> means disabling something the machine needed.

Touchpad, audio, graphics, Fn-key, OEM and security entries are Protected.
Only the Optional tier is ever switched off, and `-Restore` re-enables
everything the tool disabled from a backup written at the time.

Boot impact comes from Windows' own diagnostics log (
`Microsoft-Windows-Diagnostics-Performance/Operational`, events 100/101/103) —
real measured seconds, not a guess. That log **needs elevation**; unelevated
runs report `RequiresElevation` rather than implying boot is fine.

Logon-triggered scheduled tasks are **reported, never disabled** — that is
where updaters hide, but also where OEM and Windows machinery lives. The
module prints the `Disable-ScheduledTask` command instead. They are classified
on task path *and* name, so `Background monitor` under `\Lenovo\Power Manager\`
reads as Protected rather than inviting someone to switch off the battery
manager.

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

### network

The value is the **ladder**, not the reset commands. "No internet" is a
symptom with six candidate layers under it, and running the whole reset stack
because someone said the wifi is broken is how you turn a bad DNS entry into a
machine that has lost its static address.

```
1 link      adapter up, cable or radio associated
2 address   an IP that is not APIPA
3 gateway   the router answers
4 internet  a public IP answers - routing works
5 dns       names resolve
6 http      traffic completes, and is not a captive portal
```

**A rung that fails while something above it passes has not failed — its probe
is blocked.** Most routers and firewalls drop ICMP, so a silent gateway with
working internet is normal; those are marked `filtd` and explained, not
reported as the fault. The failing layer is the lowest failure *above* the
highest pass. (This was a real bug caught on the module's first live run — it
blamed a healthy router.)

APIPA (`169.254.x`) is called out specifically: the adapter and stack are fine
and nothing answered DHCP. The HTTP rung checks the response *body*, so a
captive portal answering 200 with a login page reads as a portal rather than
as working internet.

Repairs are tiered by blast radius:

| Tier | Actions | Cost |
|---|---|---|
| Safe (`-Apply`) | flush DNS, clear ARP/NetBIOS, DHCP release+renew | brief drop |
| Disruptive (`-Disruptive`) | `netsh winsock reset`, `netsh int ip reset` | **reboot, and the stack reset wipes static IP config** |

Disruptive is opt-in and writes the full IP configuration to a local file
first. A machine with a static address is usually static for a reason — a
printer, a line-of-business host, a site with no DHCP — and handing it back on
DHCP is a fault you introduced. DHCP release/renew is skipped automatically on
a static machine, since it only muddies the picture.

Proxy, hosts entries, disabled firewall profiles and domain membership are
reported as context, never changed. Firewall rules are never touched.

Addresses and MACs are classified, never recorded — the report says `APIPA`,
`static`, `gateway reachable`, which is the diagnostic content and survives
redaction intact.

### driver

**This module does not roll back drivers**, and that is a finished decision.

Windows has no supported scripted rollback — Device Manager's "Roll Back
Driver" calls SetupAPI with the retained previous package, and there is no
`pnputil` verb or cmdlet for it. Everything a script *can* do is blunter:
delete a driver package outright and hope the next best driver binds. The
blast radius is the worst in the toolkit — delete the wrong storage package
and the machine will not boot (`0x7B`); delete the display package and you
have a black screen with no way back.

So it diagnoses, identifies candidates, and **prints the exact commands** in
safest-first order (Device Manager rollback → System Restore → `pnputil
/delete-driver`). Same rule as partition layout in `bootrepair`: the judgement
is not automatable and the downside is someone's machine.

What it reports:

- **Devices with an actual fault**, with the problem code decoded into *which
  layer to go look at* — code 43 means the device stopped itself and is often
  failing hardware; code 28 means no driver; code 31 means the driver failed
  to load. `Status <> OK` is deliberately **not** treated as a fault: Windows
  reports `Unknown` for hidden and unqueryable devices, which on a healthy
  machine is dozens of entries. The count filtered is always printed, so a
  shorter list never looks like a cleaner machine.
- **Third-party driver packages**, flagged `BootCritical` / `HighRisk` /
  `Standard`. Boot-critical comes from Windows' own `BootCritical` flag first,
  with a device-class list as a belt-and-braces overlay.
- **System Restore state** — and if it cannot tell whether protection is off
  or simply empty, it says so rather than guessing.

`-Apply` does exactly one thing: creates a System Restore point. That is
additive and is the safety net you want before doing any of this by hand. If
Windows throttles it (one per 24h by default) the module says the point was
**not** created rather than implying a net exists.

Device instance IDs go to the console only, never the report — they routinely
embed hardware serials (`USB\VID_xxxx&PID_xxxx\<serial>`).

### stress

Not a benchmark. The point is reproducing *"it shuts off when it gets warm"*
or *"it crawls after ten minutes"* on the bench, with the telemetry that says
which layer failed — thermal, firmware throttle, or power.

**The interlock that matters: it refuses to run when a disk is not reporting
healthy.** Stressing a machine with a dying drive risks the data you should be
recovering first. Image it, get the data off, then test hardware. `-Force`
overrides it and the tool states plainly what is being overridden.

Applies load across every logical core and samples temperature and
`% Processor Performance` — the latter is the useful one, because sustained
running *below* base clock is the signature of throttling. Afterwards it
counts `Kernel-Processor-Power` ID 37 events, which is the firmware saying in
its own words that it limited the CPU.

Aborts automatically above `-MaxTempC` (default 95). Where a machine exposes
no ACPI thermal zone — common on laptops — it says so and warns that the
thermal abort will not work, rather than running blind and implying safety.
Duration defaults to 2 minutes and is hard-capped at 30.

Load workers are stopped in a `finally` block, so Ctrl-C, an abort or an error
all shut them down. Leaving CPU-pegging jobs behind on a customer's machine is
not an acceptable failure mode.

**No disk write tests, ever.** A throughput benchmark that writes to a
customer's volume is not worth the risk. Memory test (`mdsched.exe`) and
surface scans (`chkdsk /scan`, `/r`) need a reboot or hours, so the module
prints the commands instead of running them.

Third-party tools go in `tools\` on the stick — see `tools\README.md`. The
module lists what it finds and does not launch anything. **No vendor binaries
are in git**: most disallow redistribution, they are large and freely
re-downloadable, and a repo is the wrong place for them.

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
modules\Manage-StartupItems.ps1  startup inventory, reversible disable
modules\Repair-BrowserHijack.ps1 redirect detection, narrow repair
modules\Repair-DriverRollback.ps1 device faults, rollback guidance
modules\Test-SystemStress.ps1    load testing with thermal telemetry
modules\Repair-Network.ps1       connectivity ladder, tiered repairs
tools\                           third-party utilities (gitignored)
tests\Run-AllTests.ps1           runs every suite
tests\Test-Sanitizer.ps1         redaction
tests\Test-Modules.ps1           discovery + bloatware classification
tests\Test-BrowserHijack.ps1     shortcut detection and repair
tests\Test-Startup.ps1           StartupApproved encoding + classification
tests\Test-Driver.ps1            problem codes + boot-critical risk tiers
tests\Test-Stress.ps1            temp conversion, caps, safety interlocks
tests\Test-Network.ps1           address classification, ladder logic
```

---

## Testing status

Run everything with `tests\Run-AllTests.ps1`. Verified on Windows 11 24H2
(26100), PowerShell 5.1 — 238 assertions across seven suites, all passing:

- **Sanitizer (29):** live hostname/account/profile-path redaction, synthetic
  MAC/IPv4/email/user-path/product-key/GUID/SID, nested object graphs, a
  verifier that must flag unsanitized text, a check that well-known SIDs are
  *not* redacted, and list-shape round trips at the 0 and 1 boundaries. Plus
  an independent leak check of a generated report against this machine's real
  serials.
- **Modules (53):** discovery, manifest validation, unique keys, and 28
  classification cases covering runtimes, OEM utilities, antivirus, consumer
  junk and unknowns — plus a live sweep asserting no System-signed package on
  this machine is removal-eligible.
- **Browser (21):** argument splitting, synthetic hijacked shortcut detected
  and repaired, legitimate switches preserved, query string never recorded,
  backup written before the fix, clean and non-browser shortcuts untouched.
- **Startup (41):** `StartupApproved` byte encoding both directions including
  the 0x06/0x07 variant and the missing-value case, 24 classification cases,
  and an enable/disable round trip against a throwaway registry key so a
  failing test can never leave a real startup item switched off.

Also verified by hand: `Report` collection and write, `-WhatIf` dry run of the
full ladder (plan printed, no report written, log still written), unelevated
degradation, and execution from the stick.

- **Driver (40):** problem-code decoding, boot-critical class list, risk tiers
  including Windows' own flag beating the class list, an invariant that no
  boot-critical or high-risk class reads as Standard, and confirmation that
  `Status <> OK` devices with no fault code are excluded.
- **Stress (26):** deci-Kelvin conversion at four reference points, duration
  caps, preflight proven read-only by elapsed time, disk-health interlock
  shape, sensor status honesty, and tool discovery listing executables only.
- **Network (28):** address classification including both RFC1918 boundaries
  (`172.15` and `172.32` must read as public), APIPA and static verdicts, and
  ladder logic — gateway-down-plus-dns-down reports gateway, a genuine DNS
  fault reports DNS, a captive portal reports http, and an ICMP-filtered
  gateway under working internet reports *no fault at all*. Plus a check that
  the snapshot carries no IPv4 or MAC address.

`BENCH-CHECKLIST.md` is a single ordered pass that closes the list below.
It is grouped by blast radius — Tier A is safe on a working machine, Tier C is
scratch-unit only — and each step names the path it closes, so anything
skipped stays honestly marked untested rather than quietly assumed working.

### Tier A: passed on the bench, 2026-08-02

Elevated, Windows 11 24H2. **Now exercised end-to-end:**

- `DISM /CheckHealth` and `/ScanHealth` (2m43s), then `sfc /scannow` — verdict
  `Clean`. The `-WhatIf` pass in the same run correctly reported
  `Inconclusive` rather than claiming healthy from a check that never ran.
- Cache deletion — 1.28 GB reclaimed across temp, CBS logs and the WU cache,
  with `wuauserv` and `bits` confirmed running afterwards.
- `Checkpoint-Computer` — correctly reported the restore point was **not**
  created rather than claiming success.
- Network safe repairs — flush DNS, ARP clear, NetBIOS reload, DHCP
  release+renew, all exit 0, ladder still green afterwards.
- Elevated collection — `SmartStatus` = `Read` with live values,
  `ComponentStore` = `Healthy`. Independent leak check clean: hostname,
  username, profile path, BIOS serial, both disk serials, SID, IPv4 and MAC
  all absent from the report.

Three bugs found and fixed (v1.5.1):

1. Cache clean reclaimed 1.28 GB but reported `88.3% -> 88.3%` — volume free
   space lags behind deletions. It now counts bytes actually removed, with
   per-target removed/locked counts, so "nothing reclaimed" can be told apart
   from "everything was in use".
2. The restore-point failure listed candidate causes. The real one was
   **System Protection switched off** — now named specifically, with the
   enable command printed rather than run.
3. A drive reporting `0` C was recorded as 0 rather than "not reported".

**Still not exercised:** `DISM /RestoreHealth` (never fired — the store was
healthy), Windows Update install and the cross-reboot resume, real
`Remove-AppxPackage`, the proxy-registry fix, a live startup disable/restore
cycle, an `-Apply` load run, and the disruptive network resets. Tiers B and C
of `BENCH-CHECKLIST.md` cover these; until they run, treat them as untested.

Detection on a clean machine proves the detectors run, not that they detect.
The shortcut path is covered by synthetic fixtures; the proxy, policy,
scheduled-task and hosts detectors have not been fired against a genuinely
hijacked machine yet.
