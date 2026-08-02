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
```

Non-interactive:

```powershell
.\Invoke-TuneUp.ps1 -Action Report
.\Invoke-TuneUp.ps1 -Action Full -WhatIf
.\Invoke-TuneUp.ps1 -Action Repair -SourcePath D:\sources\install.wim
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
RUN.cmd                        launcher: elevation + execution policy
Invoke-TuneUp.ps1              entry point, menu, report writing
Deploy-ToUsb.ps1               copy toolkit to removable media
lib\Common.ps1                 logging, native invocation, state, reboot checks
lib\Sanitize.ps1               redaction and verification
tasks\Collect-Report.ps1       read-only diagnostic collection
tasks\Repair-ComponentStore.ps1  DISM ladder + SFC
tasks\Invoke-WindowsUpdate.ps1   WU via COM agent
tasks\Clear-TempFiles.ps1        cache reclamation
tests\Test-Sanitizer.ps1         redaction test suite
```

---

## Testing status

Verified on Windows 11 24H2 (26100), PowerShell 5.1:

- Sanitizer suite: 21/21 passing, including live hostname/account/profile-path
  redaction and an independent leak check of a generated report.
- `Report` collection, sanitization, write and verification: working.
- `-WhatIf` dry run of the full ladder: prints the plan, writes no report,
  still writes its log.
- Unelevated degradation: marks what it could not read, does not guess.

**Not yet exercised end-to-end:** the elevated write paths - actual
`RestoreHealth`, `sfc /scannow`, update installation, and cache deletion. Those
need a bench run on a real machine. Dry-run and refusal paths are tested; the
destructive halves are not.
