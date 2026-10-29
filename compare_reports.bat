@echo off
setlocal
title folderscan compare
rem ============================================================
rem  Migration check : compares a report of folderscan v5.18 (old bat)
rem  with a report of the new folderscan of the same folder.
rem   - drop both scan_*.txt files on this bat, or start it and enter the paths
rem   - which file is old / new is detected automatically
rem   - result : compare_<new report name>.txt next to the new report
rem  folderscan.bat must have been started once (it builds the exe).
rem ============================================================
set "FS_BUILD=%LOCALAPPDATA%\folderscan\build"
if not defined LOCALAPPDATA set "FS_BUILD=%TEMP%\folderscan\build"
set "FS_EXE=%FS_BUILD%\folderscan.exe"
if exist "%FS_EXE%" goto HAVEEXE
echo [ERROR] folderscan.exe not found. Start folderscan.bat once first.
pause
goto END

:HAVEEXE
set "A=%~1"
set "B=%~2"
if defined B goto RUN
echo Report of the old bat (v5.18) :
set /p "A=> "
echo Report of the new folderscan :
set /p "B=> "
set "A=%A:"=%"
set "B=%B:"=%"

:RUN
"%FS_EXE%" --selftest >nul 2>&1
if errorlevel 1 goto VIAPS
"%FS_EXE%" --compare "%A%" "%B%"
goto SHOW

:VIAPS
powershell -NoProfile -ExecutionPolicy Bypass -Command "$a=[Reflection.Assembly]::LoadFile($env:FS_EXE); $m=$a.GetType('FolderScan.App.Program').GetMethod('Main'); [void]$m.Invoke($null, @(,[string[]]@('--compare',$env:A,$env:B)))"

:SHOW
for %%N in ("%B%") do set "RES=%%~dpNcompare_%%~nN.txt"
for %%N in ("%A%") do set "RES2=%%~dpNcompare_%%~nN.txt"
if exist "%RES%" start "" notepad "%RES%"
if not exist "%RES%" if exist "%RES2%" start "" notepad "%RES2%"
pause

:END
endlocal
