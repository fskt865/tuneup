@echo off
rem RUN-STICKLOG.cmd - launch the toolkit with the run log on the STICK.
rem
rem Same as RUN.cmd but adds -LogToStick, so the verbose log is written to
rem <stick>\tuneup\logs\ instead of C:\ProgramData\GSTuneUp on the machine
rem being worked on. Every line is redacted on the way out and the finished
rem file is verified before you leave; if anything identifying survives, the
rem log is deleted from the stick rather than travelling.
rem
rem Use this when writing to the unit is itself the problem - a suspect drive
rem you may end up imaging, or a machine that must be left untouched.
rem
rem NOT the default, on purpose. A repair that spans reboots wants its log on
rem the machine, because the stick may come back on a different letter or not
rem at all. For an ordinary tune-up, use RUN.cmd.
rem
rem What this does NOT move: resume state and the modules' undo backups
rem (hw-baseline.json, startup-backup.json, browser-backup, the ipconfig
rem capture). Those stay on the unit because they exist to put the machine
rem back the way it was found, and a backup in your pocket cannot do that.

rem Delegates to RUN.cmd rather than duplicating the elevation logic - that
rem code has a UAC binding trap in it that is not worth having two copies of.
"%~dp0RUN.cmd" -LogToStick
