# Bench validation checklist

One pass through this closes the "not yet exercised end-to-end" list in
`README.md`. Every step names the untested path it closes, so anything you
skip stays honestly marked as untested rather than quietly assumed working.

**Run everything elevated, via `RUN.cmd`.** Elevation is the whole point —
the unelevated paths are already covered.

---

## Read this first

The steps are grouped by what they cost you if they go wrong, not by module.

| Tier | Safe on your daily driver? | What it does |
|---|---|---|
| **A** | Yes | Reads, plans, and trivially reversible changes |
| **B** | Your call | Changes the machine, but there is an undo |
| **C** | **No — scratch or customer unit only** | Needs a reboot, wipes config, or loads hardware |

Do A completely before B, and B before C. If a Tier A step fails, stop and
fix the tool rather than pressing on — everything after it is built on the
same plumbing.

**Before starting:** have the machine on mains, not battery. Note that Tier C
step 12 will disconnect the network and step 13 will make the machine
unresponsive for minutes.

---

## Tier A — safe on a working machine

### 1. Full suite, elevated

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File D:\tuneup\tests\Run-AllTests.ps1
```

Expect `ALL SUITES PASSED`, 238 assertions. Elevated runs exercise branches
the unelevated suite skips — the live System-signed sweep and the thermal and
driver-store reads.

**Closes:** nothing on its own. Proves the toolkit is sound before you trust
anything below.

### 2. Elevated report — the elevation-honesty claims

```bash
D:\tuneup\RUN.cmd -Action Report
```

**Pass criteria.** Every field that said `RequiresElevation` unelevated now
carries a real value:

- `Disks[].SmartStatus` = `Read`, with actual `Wear`, `TemperatureC`, `PowerOnHours`
- `ComponentStore.Verdict` = `Healthy` / `Repairable` / `NotRepairable`, **not** `Unknown`
- `Elevated` = `true`

**Then verify the report is still clean** — this is the one that matters:

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File D:\tuneup\tests\Test-Sanitizer.ps1
```

An elevated collection reaches data the unelevated one never saw, so it is a
genuinely new chance to leak. Check the newest JSON for your hostname,
username, disk serials and any `S-1-5-21-` string.

**Closes:** elevated collection path, elevated sanitizer coverage.

### 3. Dry run of the full ladder

```bash
D:\tuneup\RUN.cmd -Action Full -WhatIf
```

Expect the DISM/SFC/update/clean plan printed, **no report written**, and the
log still written to `C:\ProgramData\GSTuneUp`. Confirms `-WhatIf` still holds
when elevated — the earlier test was unelevated, where `Assert-Admin` short-
circuits some of it.

**Closes:** elevated `-WhatIf` path.

### 4. Component store — DISM ladder and SFC

```bash
D:\tuneup\RUN.cmd -Action Repair
```

Slow: 10–40 minutes. `CheckHealth` runs, `ScanHealth` runs if needed, `SFC`
runs. On a healthy machine expect `Verdict: Clean`.

**Watch for:** the honesty rule. If DISM returns no verdict it must say
"could not be established", never "healthy". If `RestoreHealth` fires and hits
`0x800f081f`, it must say `NeedsSource` rather than claiming success.

**Closes:** `sfc /scannow` parsing, DISM ladder, `Invoke-Native` exit codes
under a long-running process.

### 5. Restore point

```bash
D:\tuneup\RUN.cmd -Module driver -Apply
```

Expect either "Restore point created" or the throttle message. **Both are
passes** — what must not happen is a silent claim of success. Verify:

```bash
powershell -NoProfile -Command "Get-ComputerRestorePoint | Select-Object -Last 3 CreationTime, Description"
```

**Closes:** `Checkpoint-Computer`, elevated driver-store read, elevated
restore-status read.

### 6. Network — safe repairs

```bash
D:\tuneup\RUN.cmd -Module network -Apply
```

Brief network drop during release/renew. Expect flush DNS, ARP clear, NetBIOS
reload, then DHCP renew, all exit 0. Re-run without `-Apply` afterwards and
confirm the ladder still passes end to end.

**Closes:** `ipconfig /flushdns`, `/release`, `/renew`, `netsh delete arpcache`,
`nbtstat -R`.

### 7. Cache reclamation

```bash
D:\tuneup\RUN.cmd -Action Clean
```

Reclaims temp, WER, CBS logs (~330 MB here) and the WU download cache (~180
MB). Confirm the WU services come back up:

```bash
powershell -NoProfile -Command "Get-Service wuauserv, bits | Select-Object Name, Status"
```

Both must be `Running`. A cache clean that leaves WU stopped is a real bug.

**Closes:** cache deletion, the stop/delete/restart service dance.

---

## Tier B — reversible, but it changes your machine

### 8. Startup disable, then restore

The point is the **round trip**. On this machine the Optional tier is just
OneDrive, which makes it a clean test.

```bash
D:\tuneup\RUN.cmd -Module startup -Apply
```

Then check Task Manager → Startup. OneDrive should read **Disabled**, and the
`Run` value must still exist:

```bash
powershell -NoProfile -Command "Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Select-Object OneDrive"
```

That command still returning the path is the whole design — disabled, not
deleted. Now undo:

```bash
D:\tuneup\RUN.cmd -Module startup -Apply -Restore
```

Task Manager should show **Enabled** again.

**Closes:** live `StartupApproved` write, the restore path, the
disabled-not-deleted guarantee.

### 9. Bloatware removal — *decide before running*

This removes 9 apps from **your** machine: DevHome, Teams (personal),
Feedback Hub, Weather, Get Help, Solitaire, Clipchamp, News, Office Hub. All
reinstallable from the Store, but that is your afternoon if you want them
back.

Preview first:

```bash
D:\tuneup\RUN.cmd -Module bloatware -Apply -WhatIf
```

If you would rather not strip your own machine, **skip to the customer unit**
and leave this marked untested. That is a legitimate choice — say so rather
than assuming it works.

If you do run it, confirm afterwards that nothing outside the Consumer tier
went: Store, Terminal, Notepad, Photos and every OEM app must survive.

**Closes:** live `Remove-AppxPackage`.

### 10. Browser module

```bash
D:\tuneup\RUN.cmd -Module browser -Apply
```

This machine is clean, so expect zero fixes. That proves the apply path does
not crash; it does **not** prove the repair works. The shortcut repair is
covered by fixtures in `Test-BrowserHijack.ps1`; the **proxy registry fix has
no coverage at all** and stays untested until a genuinely hijacked machine
turns up.

**Closes:** nothing. Records that the apply path runs cleanly.

---

## Tier C — scratch or customer unit only

**Do not run these on the machine you depend on.**

### 11. Load test

Mains power, lid open, and watch it.

```bash
D:\tuneup\RUN.cmd -Module stress -Apply -Minutes 5
```

This machine exposes no ACPI thermal zone, so **the thermal abort will not
work** — the module says so, and you are the abort. Stop it yourself if it
gets hot.

**Pass criteria:** all logical cores pegged, samples every 5s, `% Processor
Performance` recorded, and — most important — **every worker job gone when it
ends**. Check:

```bash
powershell -NoProfile -Command "Get-Job | Format-Table Id, State, Command"
```

Empty. Then run it again and press **Ctrl-C halfway**, and check again.
Leftover jobs after an interrupt is the one failure mode that would be
genuinely bad on a customer's machine.

**Closes:** the `-Apply` load path and the `finally` cleanup.

### 12. Network — disruptive

Reboot required afterwards; the stack reset returns the machine to DHCP.

```bash
D:\tuneup\RUN.cmd -Module network -Apply -Disruptive
```

Confirm `C:\ProgramData\GSTuneUp\network-ipconfig-backup.txt` was written
**before** the resets and contains the real addresses. Reboot, then re-run the
ladder and confirm connectivity returns.

If the unit has a static address, this is also the test that it warned you
loudly and captured the config.

**Closes:** `netsh winsock reset`, `netsh int ip reset`, the IP config backup.

### 13. Windows Update

```bash
D:\tuneup\RUN.cmd -Action Update
```

One update is pending here (`KB5101650`). Expect EULA acceptance, download,
install, and a reboot-required flag. Reboot, then run `-Action Full` and
confirm it **skips completed stages** from the resume state instead of
restarting the ladder.

**Closes:** WU COM download/install, and the cross-reboot resume path.

### 14. Purge

Last, on any machine you touched:

```bash
D:\tuneup\RUN.cmd -Action Purge
```

`C:\ProgramData\GSTuneUp` should be gone — logs, resume state, browser
backups, IP config backup, startup backup. Verify it, because those contain
the customer's data and leaving them behind is the one failure that matters
after the job is done.

**Closes:** purge path. **Note the ordering conflict:** purging removes the
startup and network backups, so do step 14 only after you have finished
needing them.

---

## Record as you go

| # | Step | Result | Notes |
|---|------|--------|-------|
| 1 | Suite elevated | **PASS** 2026-08-02 | 235 assertions (3 unelevated-only branches skip, as designed) |
| 2 | Elevated report + leak check | **PASS** | All 8 leak probes false. `SmartStatus=Read`, `ComponentStore=Healthy` |
| 3 | Full `-WhatIf` | **PASS** | 5 reports before and after, log still written |
| 4 | DISM + SFC | **PASS** | ScanHealth 2m43s, SFC `Clean`. `RestoreHealth` never fired — store healthy |
| 5 | Restore point | **PASS (failed safe)** | System Protection is OFF on this machine; correctly refused to claim success |
| 6 | Network safe | **PASS** | All 5 repairs exit 0, ladder green after |
| 7 | Cache clean | **PASS after fix** | 1.28 GB reclaimed; reporting bug found and fixed |
| 8 | Startup round trip | | |
| 9 | Bloatware | | |
| 10 | Browser apply | | |
| 11 | Load test + Ctrl-C | | |
| 12 | Network disruptive | | |
| 13 | Windows Update + resume | | |
| 14 | Purge | | |

### Tier A findings, 2026-08-02

Three bugs, all fixed in v1.5.1 and re-verified elevated:

1. **Cache clean under-reported its own success.** Reclaimed 1.28 GB, reported
   `88.3% -> 88.3%`. Volume free-space counters lag behind deletions, so the
   figure it trusted was wrong. Now counts bytes actually removed, plus
   removed/locked per target — the re-run showed `UserTemp reclaimed 0 MB,
   0 removed, 8 locked`, which is the honest version of the same result.
2. **Restore point failure was diagnosed as a guess.** The real cause was
   System Protection being switched off; it now names that and prints
   `Enable-ComputerRestore`, without running it.
3. **A drive reporting 0 C was recorded as 0**, not as "not reported".

**Outstanding on this machine:** System Protection is off, so there is no
rollback safety net here. Worth turning on before running Tier C.

Anything that fails: capture the console output and the log from
`C:\ProgramData\GSTuneUp` **before** step 14. Anything skipped stays in the
README's untested list — an unrun step is not a passed step.
