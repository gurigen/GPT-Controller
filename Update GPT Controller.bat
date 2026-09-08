@echo off
setlocal
cd /d "%~dp0"
where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo PowerShell 7 is required to stage this reviewed candidate.
  pause
  exit /b 1
)
echo Staging only. Existing PC tasks and permissions will not be changed.
pwsh.exe -NoLogo -NoProfile -File "%~dp0scripts\install-candidate.ps1" -CandidateSource "%~dp0."
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" (
  echo Update finished successfully.
  echo Candidate is staged only. Read HARDENING_README_JA.md before activation.
  exit /b 0
)
echo Update failed with exit code %RC%.
pause
exit /b %RC%
