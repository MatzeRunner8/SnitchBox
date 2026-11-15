@echo off
rem Baut SnitchBoxStart.exe mit dem C++-Compiler von Visual Studio (statische Laufzeit: braucht kein VC++-Paket).
rem Aufruf: build-launcher.cmd <vcvars64.bat> <Zielordner> <Zwischenordner> <Major> <Minor> <Patch> <Build>
setlocal
call "%~1" >nul || exit /b 1
set OUT=%~2
set OBJ=%~3
if not exist "%OBJ%" mkdir "%OBJ%"
cd /d "%~dp0" || exit /b 1
rc /nologo /dVER_MAJOR=%4 /dVER_MINOR=%5 /dVER_PATCH=%6 /dVER_BUILD=%7 /dVER_TEXT="\"%4.%5.%6.%7\"" /dVER_PRODUCT="\"%4.%5.%6 (Build %7)\"" /fo "%OBJ%\SnitchBoxStart.res" SnitchBoxStart.rc || exit /b 1
cl /nologo /O1 /MT /W4 /WX /GS /guard:cf /DUNICODE /D_UNICODE /Fo"%OBJ%\\" /Fe"%OUT%\SnitchBoxStart.exe" SnitchBoxStart.cpp "%OBJ%\SnitchBoxStart.res" ^
   /link /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT /GUARD:CF /MANIFEST:EMBED /MANIFESTUAC:NO ^
   /MANIFESTINPUT:SnitchBoxStart.manifest kernel32.lib user32.lib || exit /b 1
exit /b 0
