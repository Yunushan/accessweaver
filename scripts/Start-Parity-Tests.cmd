@echo off
rem Double-click only inside the named disposable VMware test guest.
set "ACCESSWEAVER_TEST_BOOTSTRAP=%~dp0vmware-test-bootstrap.ps1"
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File '+[char]34+$env:ACCESSWEAVER_TEST_BOOTSTRAP+[char]34)"
