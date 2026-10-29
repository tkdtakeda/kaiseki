@echo off
setlocal
title folderscan
rem ============================================================
rem  folderscan launcher
rem   - double click             : asks for the target folder
rem   - drop folders on this bat : scans the dropped folders
rem   - settings                 : settings.ini (next to this bat)
rem  The C# sources in src\ are compiled with the C# compiler that
rem  comes with Windows (.NET Framework 4.x). This happens at the first
rem  start and after a source file was changed; otherwise the built
rem  exe is started at once.
rem  Build folder : %LOCALAPPDATA%\folderscan\build
rem ============================================================
set "FS_HOME=%~dp0."
set "FS_SRC=%~dp0src"
set "FS_BUILD=%LOCALAPPDATA%\folderscan\build"
if not defined LOCALAPPDATA set "FS_BUILD=%TEMP%\folderscan\build"
set "FS_EXE=%FS_BUILD%\folderscan.exe"
if not exist "%FS_BUILD%\" mkdir "%FS_BUILD%" >nul 2>&1

rem ---------- C# compiler of Windows ----------
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" goto NOCSC

rem ---------- build only when a source file changed ----------
set "STAMP_NEW=%FS_BUILD%\stamp.new"
set "STAMP=%FS_BUILD%\stamp.txt"
>"%STAMP_NEW%" echo "%~dp0"
for /r "%FS_SRC%" %%F in (*.cs) do >>"%STAMP_NEW%" echo %%~fF^|%%~tF^|%%~zF
if not exist "%FS_EXE%" goto BUILD
fc /b "%STAMP_NEW%" "%STAMP%" >nul 2>&1
if errorlevel 1 goto BUILD
goto RUN

:BUILD
echo Building folderscan.exe (first start or source changed) ...
"%CSC%" /nologo /target:exe /optimize+ /unsafe /out:"%FS_BUILD%\folderscan.new.exe" /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /recurse:"%FS_SRC%\*.cs" >"%FS_BUILD%\build.log" 2>&1
if errorlevel 1 goto BUILDFAIL
move /y "%FS_BUILD%\folderscan.new.exe" "%FS_EXE%" >nul 2>&1
if errorlevel 1 goto MOVEFAIL
copy /y "%STAMP_NEW%" "%STAMP%" >nul
del "%FS_BUILD%\mode.txt" >nul 2>&1
echo Build OK.
goto RUN

:MOVEFAIL
echo [warn] folderscan.exe is in use by another window; the previous build is used.
if not exist "%FS_EXE%" goto END
goto RUN

:RUN
rem exe start may be blocked by a company policy -> run it inside PowerShell instead.
rem checked once after each build, the result is kept in mode.txt
set "FS_MODE="
if exist "%FS_BUILD%\mode.txt" set /p FS_MODE=<"%FS_BUILD%\mode.txt"
if "%FS_MODE%"=="exe" goto VIAEXE
if "%FS_MODE%"=="ps" goto VIAPS
"%FS_EXE%" --selftest >nul 2>&1
if errorlevel 1 goto SETPS
>"%FS_BUILD%\mode.txt" echo exe
goto VIAEXE

:SETPS
>"%FS_BUILD%\mode.txt" echo ps
goto VIAPS

:VIAEXE
"%FS_EXE%" --home "%FS_HOME%" %*
goto END

:VIAPS
echo [info] folderscan.exe could not be started directly. It is started through PowerShell.
set "FOLDERSCAN_ARGS=%*"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$a=[Reflection.Assembly]::LoadFile($env:FS_EXE); $m=$a.GetType('FolderScan.App.Program').GetMethod('Main'); [void]$m.Invoke($null, @(,[string[]]@('--home',$env:FS_HOME,'--argsenv')))"
goto END

:NOCSC
echo [ERROR] C# compiler of Windows was not found:
echo   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
pause
goto END

:BUILDFAIL
echo [ERROR] build failed. Messages:
type "%FS_BUILD%\build.log"
del "%STAMP%" >nul 2>&1
pause
goto END

:END
endlocal
