@echo off
setlocal
if exist "%~dp0accessweaver.exe" (
  "%~dp0accessweaver.exe" ui
) else (
  echo accessweaver.exe is missing. Download or build the Windows binary first.
  pause
)
