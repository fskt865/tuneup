# tools\

Drop third-party diagnostic and stress utilities here. The `evidence` module
lists whatever it finds so you know what is on the stick, and then gets out of
the way — it does not launch them.

**Nothing in this folder is in git.** `.gitignore` excludes every binary here
for three reasons: most of these tools do not permit redistribution, they are
large and freely re-downloadable, and a repo is the wrong place for vendor
executables. Only this README is tracked.

`Deploy-ToUsb.ps1` copies whatever is present locally, so if you want a tool on
every stick, put it here on the machine you deploy from.

## Worth carrying

| Tool | Use | Notes |
|---|---|---|
| Everything | Filename search | Provisioned by `Install-Tools.ps1` — **launch `Everything\SEARCH.cmd`**, see below |
| Prime95 | CPU load, heat soak | `Small FFTs` for maximum heat |
| OCCT | CPU/GPU/PSU load | Has a free personal-use build |
| MemTest86+ | Memory | Bootable — already on the stick at `\iso\`, not here |
| CrystalDiskInfo | SMART, portable | Reads more attributes than `Get-StorageReliabilityCounter` |
| HWiNFO64 | Sensors | Best option when a machine exposes no ACPI thermal zone |
| FurMark | GPU load | Genuinely stresses a marginal GPU or PSU |

Check each tool's licence before putting it on a stick you use commercially —
several of these are free for personal use only.

## Everything: never launch the exe

`Everything.exe` builds an index of every filename on the machine it runs on,
and in portable mode it saves that index **next to itself — on this stick**. A
full file listing of a customer's disk is customer data, and it does not leave
on removable media.

`Install-Tools.ps1 -CopyToStick` writes two files beside the exe to prevent it:

- **`SEARCH.cmd`** — self-elevates and launches with `-nodb`, so the index
  exists only in RAM and dies with the process. Use this one.
- **`Everything.ini`** — read-only, so a search term can't be saved back into
  it; history, update checks and both servers off; `db_location` pointed at
  `C:\ProgramData\GSTuneUp` so even a stray direct launch writes to the
  customer's machine, not the stick, where menu option 7 (Purge) will remove it.

`Deploy-ToUsb.ps1` checks the stick for an index file on every deploy and
reports it in red. If you ever see that, the exe got launched directly — delete
the file before the stick goes back out.

Unlike the other three provisioned tools, Everything is closed-source freeware.
Read voidtools' terms before relying on it commercially.

## Before running any of them on a customer's machine

The `evidence` module's interlock applies just as much when you drive a tool by
hand: **do not stress a machine whose disk is not reporting healthy.** Image it
and get the data off first. Load testing a dying drive can turn a recoverable
job into an unrecoverable one, and that is the whole ballgame at Level 1.
