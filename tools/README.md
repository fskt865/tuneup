# tools\

Drop third-party diagnostic and stress utilities here. The `stress` module
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
| Prime95 | CPU load, heat soak | `Small FFTs` for maximum heat |
| OCCT | CPU/GPU/PSU load | Has a free personal-use build |
| MemTest86+ | Memory | Bootable — already on the stick at `\iso\`, not here |
| CrystalDiskInfo | SMART, portable | Reads more attributes than `Get-StorageReliabilityCounter` |
| HWiNFO64 | Sensors | Best option when a machine exposes no ACPI thermal zone |
| FurMark | GPU load | Genuinely stresses a marginal GPU or PSU |

Check each tool's licence before putting it on a stick you use commercially —
several of these are free for personal use only.

## Before running any of them on a customer's machine

The `stress` module's interlock applies just as much when you drive a tool by
hand: **do not stress a machine whose disk is not reporting healthy.** Image it
and get the data off first. Load testing a dying drive can turn a recoverable
job into an unrecoverable one, and that is the whole ballgame at Level 1.
