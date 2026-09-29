@echo off
title KeyForge Generator Hasel
cd /d "%~dp0"

if exist "%~dp0Aplikacja-EXE\zadanie-2.1-karol-wojdyla.exe" (
    start "" "%~dp0Aplikacja-EXE\zadanie-2.1-karol-wojdyla.exe"
    exit /b
)

echo Plik wykonywalny nie zostal jeszcze utworzony.
echo Trwa kompilacja i publikowanie aplikacji WPF (.NET 9)...
dotnet publish -c Release -o "%~dp0Aplikacja-EXE"

if exist "%~dp0Aplikacja-EXE\zadanie-2.1-karol-wojdyla.exe" (
    echo Uruchamianie aplikacji...
    start "" "%~dp0Aplikacja-EXE\zadanie-2.1-karol-wojdyla.exe"
    exit /b
)

echo.
echo Wystapil blad podczas budowania aplikacji.
echo Upewnij sie, ze zainstalowany jest pakiet .NET 9 SDK.
pause
