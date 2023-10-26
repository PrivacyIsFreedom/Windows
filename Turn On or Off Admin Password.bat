@echo off
title Admin Passwort Manager
color 30
echo.
echo.
:start
@echo off
echo Press A to disable admin password prompts.
echo.
echo Press B to enable admin password prompts.
echo.
set /p example=
if %example% == 0 goto start
if %example% == a goto A
if %example% == A goto A
if %example% == b goto B
if %example% == B goto B
:A
echo.
echo.
@echo on
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
set /p example=
if %example% == 0 goto start
if %example% == a goto A
if %example% == A goto A
if %example% == b goto B
if %example% == B goto B
:A
echo.
echo.
@echo on
:B
:A
echo.
echo.
@echo on
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
set /p example=
if %example% == 0 goto start
if %example% == a goto A
if %example% == A goto A
if %example% == b goto B
if %example% == B goto B