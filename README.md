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
   evidence    Hardware evidence around an external stress test
   network     Network diagnosis and repair
   clocks      Clock and power-state review
   crashes     Crash report review
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
.\Invoke-TuneUp.ps1 -Module evidence                         # baseline before stressing
.\Invoke-TuneUp.ps1 -Module evidence -Phase Watch -Minutes 15 # sample while OCCT runs
.\Invoke-TuneUp.ps1 -Module evidence -Phase Compare          # diff against the baseline
.\Invoke-TuneUp.ps1 -Module network                          # walk the ladder, change nothing
.\Invoke-TuneUp.ps1 -Module network -Apply                   # safe repairs only
.\Invoke-TuneUp.ps1 -Module network -Apply -Disruptive       # DISABLED - saves config, prints commands
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
| Disruptive (`-Disruptive`) | `netsh winsock reset`, `netsh int ip reset` | **DISABLED — see below** |

> **The disruptive resets are switched off in this build.** They have never
> been executed end to end, they need a reboot, and the stack reset wipes
> static IP configuration — so a customer's machine is the wrong place for
> their first run.
>
> `-Disruptive` still does the useful half: it saves the full IP configuration
> to a local file and prints the exact commands, so a tech can run them by
> hand having seen what is at stake. Same rule as partitioning in
> `bootrepair` — print the commands, let the tech decide.
>
> Re-enable via `$script:DisruptiveEnabled` in `modules\Repair-Network.ps1`
> once Tier C of `BENCH-CHECKLIST.md` has passed on a scratch machine. A test
> asserts it is off, so it cannot come back silently.

A machine with a static address is usually static for a reason — a printer, a
line-of-business host, a site with no DHCP — and handing it back on DHCP is a
fault you introduced. DHCP release/renew is skipped automatically on a static
machine, since it only muddies the picture.

Proxy, hosts entries, disabled firewall profiles and domain membership are
reported as context, never changed. Firewall rules are never touched.

Addresses and MACs are classified, never recorded — the report says `APIPA`,
`static`, `gateway reachable`, which is the diagnostic content and survives
redaction intact.

### crashes

**Read-only, always — there is no `-Apply` and there should never be one.**
Crash artefacts are the only record of an intermittent fault; deleting them
destroys the evidence.

The point is the **faulting module**. "It crashes sometimes" isn't actionable;
"eleven crashes, all in `nvlddmkm.sys`" names the display driver, and
"bugcheck `0x7A` twice" names the disk.

Covers:

- **Kernel dumps** — `Minidump\`, `MEMORY.DMP`, `LiveKernelReports\`. The stop
  code is read straight out of the dump header (`DUMP_HEADER64`, offset
  `0x38`), so you get `0x116 VIDEO_TDR_ERROR -> GPU` **without WinDbg or a
  symbol download**. 22 stop codes are mapped to a component.
- **WER** app crashes and hangs, machine-wide and per-user. The folder *name*
  carries type and app and is readable unelevated; faulting module and
  exception code need elevation, and it says so rather than showing blanks.
- **Third-party crash stores** — Chrome/Edge/Brave Crashpad, Firefox,
  Thunderbird, Discord, Slack, VS Code, Steam, NVIDIA, Office, and Java
  `hs_err_pid*.log`.
- **Reliability Monitor's** own dataset for a chronological view.

> **A kernel dump is a copy of RAM.** It can contain documents, passwords and
> keys. This module records app names, module names, stop codes, counts and
> dates — never file contents, paths or dumps. It will not copy a dump
> anywhere, and neither should you.

### clocks

Two different faults look identical to a customer ("it got slow"), and this
tells them apart:

- **Underclocked** — most often the power plan's *maximum processor state*. A
  single number that makes a healthy laptop feel broken, and it is checked
  first because it is free to fix. Also RAM at JEDEC default because XMP/EXPO
  was never enabled.
- **Overclocked** — on a machine that crashes under load, undo this *before*
  spending an hour on drivers or RAM. An unstable memory overclock imitates
  failing RAM exactly.

Reads rated vs running CPU clock and `% Processor Performance`, the power
plan's min/max processor state on **both AC and battery**, per-DIMM rated vs
configured speed, and live per-core/GPU clocks if LibreHardwareMonitor happens
to be running (it is not started here — this module changes nothing).

Power settings are read by **GUID rather than friendly name**, so it works on
non-English Windows where `powercfg` output is localised.

Read-only. A capped CPU or an overclock is the owner's configuration, so it
prints the `powercfg` command and stops.

### elevation

"Nothing will run as administrator." That one complaint is produced by at least
eight different faults that are indistinguishable from the customer's chair, so
this walks them as a ladder and names the layer:

| # | Rung | What it settles |
|---|---|---|
| 1 | Token | Standard user, filtered admin, or already elevated |
| 2 | Membership | In Administrators — and does the *running token* know it |
| 3 | Service | AppInfo performs elevation. Disabled, nothing elevates, ever |
| 4 | Policy | The UAC values. One of them denies silently |
| 5 | Hijack | IFEO debuggers, SilentProcessExit, the `runas` verb |
| 6 | Restriction | SRP, AppLocker, Smart App Control, removable-execute denial |
| 7 | Tamper | Is the state *stable*, or is something rewriting it |
| 8 | Evidence | Provider-filtered event counts that corroborate 1–7 |

**`RequiresAdmin` is false and that is load-bearing.** This module exists for a
machine that cannot elevate; one that needed elevation to diagnose elevation
would be useless on every machine it was written for. Rungs that genuinely need
elevation report `RequiresElevation` rather than a blank that reads as a pass.

**Do not launch this one with `RUN.cmd`.** `RUN.cmd` self-elevates, so on the
machine this module is for it is the single launcher guaranteed to fail. Go
straight at the script — `-ExecutionPolicy Bypass` is per-process and needs no
rights of its own:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File D:\tuneup\Invoke-TuneUp.ps1 -Module elevation
```

Three findings worth knowing before you need them:

- **AppInfo disabled** is the most common non-malware cause, and it is a
  10-second fix — but fixing it *needs* elevation, which is what is broken.
  Safe Mode as the built-in Administrator, or an offline registry edit, is
  usually the way in.
- **`ConsentPromptBehaviorUser = 0`** denies every request from a standard
  account with no prompt and no error. It matches "it just doesn't do anything"
  more exactly than anything else on the list — and it is also a legitimate
  hardening choice, so check who owns it first.
- **An IFEO `Debugger` on `consent.exe`** makes Windows launch the debugger
  instead of consent. The prompt appears, you click Yes, nothing runs. It is a
  supported debugging feature, which is why it survives most cleaners.

**Rung 6 exists because a block on the *launch* imitates a block on the
*elevation*.** If Smart App Control or a removable-execute policy is refusing
the binary, UAC is innocent and every minute spent on UAC is wasted. When the
toolkit is running from the stick, the one-minute test that splits these is to
copy it to `C:\` and launch it there.

#### "A virus keeps turning UAC off"

That is a hypothesis this module **tests**, not one it assumes. UAC settings
reverting has an innocent twin — a domain or MDM policy refresh putting them
back every 90 minutes — and a single look at the registry cannot tell the two
apart. So domain join and MDM enrolment are reported right beside every tamper
finding, and rung 7 uses three independent signals:

- **Running state vs registry state.** `EnableLUA` only takes effect at boot.
  So if the registry says UAC is on while this session has no filtered token,
  the value was changed *after* the machine came up — UAC is off right now
  whatever Security Centre shows, and stays off until a reboot. That is a fact
  about time rather than an inference, and it is the strongest evidence
  available from a single sample.
- **Key write time vs last boot**, the same argument from the other side.
- **Authenticode on `consent.exe` and `appinfo.dll`.** A replaced one is a
  compromised install, not a misconfiguration.

A single reading cannot see a value that gets rewritten later, so there are
phases for that:

```powershell
.\Invoke-TuneUp.ps1 -Module elevation -Phase Watch -Minutes 5
.\Invoke-TuneUp.ps1 -Module elevation -Phase Baseline   # then reboot, then
.\Invoke-TuneUp.ps1 -Module elevation -Phase Compare
```

Watch is honest about its own weakness: a quiet window rules out a tight loop
rewriting the value every few seconds, and rules out nothing on a 90-minute
refresh cycle. It says so rather than reporting a pass.

**Order matters if it really is an infection.** Repairing UAC while the writer
is still running gets the repair reverted and teaches nothing: data off first,
scan offline, then repair, then re-check with `-Phase Compare`. A confirmed
rootkit or a replaced `consent.exe` is a rebuild conversation, not a registry
edit — that is where the Level 1 line is.

Read-only, with no `-Apply` half at all. UAC, SRP, AppLocker and WDAC are
security configuration and often somebody's policy; it prints the exact command
for each fix and stops.

### codeintegrity

**This module exists because the elevation module got it wrong on a customer
machine.** Rung 8 summed CodeIntegrity events 3033 and 3077 and called the
total "blocked binaries — Smart App Control or WDAC". On a Windows 10 Home
unit with no policy of any kind, that produced a confident cause naming a
feature that does not exist before Windows 11 22H2. The count was real; every
word of the conclusion was wrong.

That is the toolkit's own lesson one level up. It already knew an event ID
means nothing without its **provider**. The same argument keeps going: an ID
means nothing without its **semantics**, and without checking that the feature
being blamed **exists on the OS in front of you**.

The distinction the module is built around:

| Events | What it actually is |
|---|---|
| 3033 / 3034 | A load failed a **signing level** requirement — typically an injection into a process that won't accept it. The program is still running. Storms of hundreds are unremarkable. |
| 3076 / 3077 / 3082 | A **WDAC policy** audited or blocked something. *This* is a program being refused, and it can't happen without a policy present. |

So it answers three questions in order, and nothing else is worth reading until
they're settled: **is anything enforcing**, **what is actually in the log**, and
**which file is repeating**. It checks the OS build before naming Smart App
Control, reads `Win32_DeviceGuard` for real WDAC enforcement status, and counts
active policy files — so "no policy is present" is a stated finding rather than
an assumption.

Blocked paths are an inventory of the customer's installed software, so they go
to the **console only**. The report carries a count, a file extension and a
location bucket (`Windows\System32`, `Program Files`, `user temp`, …) — never a
path and never a file name.

Two bugs caught before it shipped, both the same shape as the one it was written
to fix:

- **Windows paths contain spaces.** A pattern stopping at whitespace truncated
  `\Program Files\Vendor\thing.dll` to `\Program`, which then had no extension,
  was discarded as a non-binary, and made the parser name the *process* instead
  of the file. Every event for one repeating DLL would land in its own bucket
  and the concentration check — the whole point of the module — would report
  noise. Anchored on the extension instead.
- **Events naming no file were bucketed anyway**, so 171 unrelated
  informational events on a healthy machine looked like one thing retrying in a
  loop. They're counted now, never grouped, and concentration is judged only
  against events that actually name a file.

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
safest-first order (Device Manager rollback — System Restore — `pnputil
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

### evidence

**The evidence half of a stress test. It generates no load.** OCCT, Cinebench,
FurMark and MemTest86+ apply load better than anything written here and are on
the stick already. What they don't do is tell you which component logged a
hardware error while they ran — that is this module's job.

Three phases around a tool this module does not run:

```
-Phase Baseline    snapshot SMART, sensors, battery and the error log first
-Phase Watch       sample temps, clocks and fans WHILE your tool runs
-Phase Compare     diff everything against the baseline
```

`Baseline` is the default — the read-only thing you get when you forget an
argument. The baseline is written to `C:\ProgramData\GSTuneUp`, never the
stick, so it survives closing the window while OCCT runs.

It contributes three things the load tools don't:

1. **WHEA correlation.** Snapshot the hardware error log, let an external tool
   provoke the fault, snapshot again, attribute anything *new* to a component.
   Errors that appear under load and not before is the strongest evidence
   available from inside Windows.
2. **The disk-health interlock** — warns hard when a drive is not reporting
   healthy, because the data comes off first. It cannot stop an external tool,
   which is exactly why it says so before you start one.
3. **The sanitized report**, so findings can leave the customer's machine.

**Load being external creates one new way to be wrong, and it is the important
one.** If the tech never actually started the stress tool, the diff comes back
empty and reads as a pass. So `Watch` measures whether load was *observed* and
states it plainly — no observation, no pass.

That check cannot be CPU utilisation alone. A GPU stress test leaves the CPU
near idle **by design**, so judging it on CPU percentage would report "nothing
was tested" while FurMark cooks the card. A rise in GPU temperature counts as
load too, and the verdict names *which kind* was seen: a GPU run explicitly
says the CPU was not exercised rather than implying the whole machine passed.

Every source is matched on provider **and** event ID. `Kernel-Power` alone
emits hundreds of routine power-state events; only ID 41 is an unexpected
shutdown.

**There is no in-process memory test, deliberately.** An earlier version
verified memory patterns in-process and was deleted: it can only touch pages
this process owns, and a "partial pass" on RAM is exactly the false confidence
this toolkit exists to prevent. A test asserts those functions have not come
back. Use MemTest86+ from a boot device.

Every run prints a **coverage matrix** — a stated position on every component,
so "entire device" never means silence about the parts that were skipped:

| Part | Coverage |
|---|---|
| CPU | FULL — all-core load, clocks sampled, WHEA diffed |
| Cooling | FULL with LibreHardwareMonitor, else PARTIAL (ACPI only) |
| Fans | FULL with LHM — checks RPM *ramps* under load; a fan at idle speed while the CPU cooks is seized |
| Storage | FULL with smartctl (attributes), else PARTIAL; plus a read-only surface read |
| Battery | FULL — design vs full-charge capacity and cycle count via `powercfg` |
| Memory | NONE — MemTest86+, several passes |
| GPU | OBSERVED — temps and driver resets only; load it with FurMark/OCCT |
| PSU | INFERRED — suspect it on a drop with no thermal or WHEA cause |
| Display | NONE — physical inspection |
| Network | NONE — run the `network` module |

Load is verified, not assumed: it samples actual CPU utilisation and reports
**LOAD NOT APPLIED** if the mean is under 70%. A pass on a machine that was
never loaded is worse than no result. Workers are checked for `Running` after
start and stopped in a `finally`, so Ctrl-C, abort and error all clean up.

**No disk write tests, ever**, and no reboots. `mdsched.exe` and
`chkdsk /r` are printed, not run.

### Provisioning the tools

```powershell
.\Install-Tools.ps1                 # inventory, changes nothing
.\Install-Tools.ps1 -Install        # winget install on THIS machine
.\Install-Tools.ps1 -CopyToStick    # copy binaries into tools\
```

Three, all genuinely open source rather than free-for-personal-use — which
matters on a paid bench, where OCCT and HWiNFO's personal licences do not
apply. Verify current terms yourself before relying on them.

| Tool | Licence | Why |
|---|---|---|
| smartmontools | GPL v2 | SMART attributes — reallocated/pending sectors, media errors |
| LibreHardwareMonitor | MPL 2.0 | Temps **and fan RPM** where ACPI exposes nothing |
| CrystalDiskInfo | MIT | Readable SMART GUI to show a customer |

**Run it on your own bench machine, not a customer's** — then `-CopyToStick`
so the field toolkit installs nothing on the target. LibreHardwareMonitor must
be *running* (and elevated) to publish its WMI namespace; installed but closed
is no use.

`tools\` is gitignored. No vendor binaries in the repo.

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

## The stick

Ventoy (GPLv3) owns the whole device — it repartitions and cannot be installed
alongside existing data, so the stick is always rebuilt from this repo rather
than edited in place. That is what `Deploy-ToUsb.ps1` is for.

```
D:\  exFAT, ~14.4 GB          Ventoy data partition
     iso\
         memtest86plus-8.10.iso    boots from Ventoy's menu
     tuneup\                        the toolkit; not an ISO, so invisible to the menu
         tools\                     smartmontools, LibreHardwareMonitor, CrystalDiskInfo
VTOYEFI  ~32 MB, hidden        Ventoy's own boot files
```

ISOs and ordinary files coexist on the same partition — Ventoy only lists
`.iso`/`.img` in its boot menu and ignores everything else. Installed MBR, not
GPT, so it boots legacy BIOS as well as UEFI; and with Secure Boot Support on,
so it boots machines with Secure Boot enabled without going into their
firmware to disable it.

exFAT rather than FAT32 means no 4 GB per-file limit, so full Windows install
ISOs fit.

**Memory testing now lives here.** Boot the stick, pick MemTest86+, give it
several passes. That is the component the `evidence` module deliberately refuses
to test from inside Windows.

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
modules\Get-HardwareEvidence.ps1 sensors, SMART and error diffing (no load)
modules\Repair-Network.ps1       connectivity ladder, tiered repairs
modules\Get-CrashReports.ps1     kernel dumps, WER, third-party crash stores
modules\Get-ClockStatus.ps1      rated vs running clocks, power-state caps
tools\                           third-party utilities (gitignored)
tests\Run-AllTests.ps1           runs every suite
tests\Test-Sanitizer.ps1         redaction
tests\Test-Modules.ps1           discovery + bloatware classification
tests\Test-BrowserHijack.ps1     shortcut detection and repair
tests\Test-Startup.ps1           StartupApproved encoding + classification
tests\Test-Driver.ps1            problem codes + boot-critical risk tiers
tests\Test-Evidence.ps1          temp conversion, load observation, interlocks
tests\Test-Network.ps1           address classification, ladder logic
tests\Test-Crashes.ps1           bugcheck decode, dump header, WER names, clocks
```

---

## Testing status

Run everything with `tests\Run-AllTests.ps1`. Verified on Windows 11 24H2
(26100), PowerShell 5.1 — 382 assertions across eight suites, all passing:

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
- **Evidence (79):** deci-Kelvin conversion at four reference points, watch-window
  caps, baseline proven read-only by elapsed time and round-tripped through
  disk, disk-health interlock shape, sensor status honesty, tool discovery
  listing executables only, proof the load-generating functions have not come
  back — and the load-observation matrix, including that a GPU run with an idle
  CPU counts as load but never licenses a CPU pass.
- **Network (28):** address classification including both RFC1918 boundaries
  (`172.15` and `172.32` must read as public), APIPA and static verdicts, and
  ladder logic — gateway-down-plus-dns-down reports gateway, a genuine DNS
  fault reports DNS, a captive portal reports http, and an ICMP-filtered
  gateway under working internet reports *no fault at all*. Plus a check that
  the snapshot carries no IPv4 or MAC address.
- **Elevation (62):** every verdict branch, including three asymmetries that are
  easy to get backwards — `ConsentPromptBehaviorUser = 0` is a fault for a
  standard user and *not* for an administrator; a filtered admin token is the
  **healthy** state and must never be reported as broken; and membership is
  tri-state, so unreadable must not score as "not a member". Plus snapshot
  comparison, the honest-zero event path (an empty result is readable with a
  count of zero, a bad provider is not), and a static check that account
  **names** never reach the returned report object while member SIDs do.

  Two of those tests are regressions from the first real run, both false
  positives on a healthy machine, and both worth reading:

  1. `.NET WindowsIdentity.Groups` **omits deny-only groups and the mandatory
     integrity label**. On a filtered administrator that is exactly the
     interesting state — `S-1-5-32-544` is in the token as deny-only and .NET
     reports it as simply absent — so a perfectly healthy machine was told its
     token was stale and its user should sign out. Token groups now come from
     `whoami /groups`, parsed by SID because the columns are localised, and
     `TokenElevationType = 3` independently vetoes the stale verdict.
  2. `batfile\runas` and `cmdfile\runas` store an **already-expanded absolute
     path** (`C:\WINDOWS\System32\cmd.exe /C "%1" %*`), not the `%SystemRoot%`
     form, and its casing varies between installs. Exact-matching reported a
     verb hijack on a clean machine. Only `exefile` gets an exact test now;
     the others are checked structurally.

  A diagnostic that cries hijack on a healthy machine is worse than no
  diagnostic — it sends a tech hunting malware that was never there.

  **Not yet bench-tested against a machine that genuinely cannot elevate.** The
  ladder has only been run against healthy hardware, where its correct answer is
  `NO BLOCKING CONDITION FOUND`. Every fault branch is unit-tested but none has
  been seen in the wild, so treat rung findings as untried until one is.

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

