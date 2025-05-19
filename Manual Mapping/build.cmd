@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP
@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP /DEF:main.def
@REM @REM cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /VERBOSE /DEBUG /MAP
@REM @REM cl /c /EHsc /GS- /Oy /Zi /FAs .\injection.cpp


@echo off
cls
del main.pdb main.map main.ilk injection.obj main.obj injection.asm main.lib main.exp main.exe vc140.pdb 2>nul
cls

@REM /wait
cl /EHsc /GS- /Oy /Zi .\main.cpp .\injection.cpp /link /OUT:main.exe /DEBUG /MAP /INCREMENTAL:NO

if errorlevel 1 (
    goto :eof
)

start /min "" notepad.exe
timeout /t 0 /nobreak >nul

for /f "tokens=2 delims=," %%i in ('tasklist /nh /fi "imagename eq notepad.exe" /fo csv') do @set "notepadPID=%%i"
if defined notepadPID (
    start /min "" "C:\tools\x32 & x64 dbg\release\x64\x64dbg.exe" -p %notepadPID%
) else (
    echo Error: Could not find notepad.exe's PID.
)

endlocal
goto :eof