@echo off
REM Create necessary directories if they don't exist
if not exist ".\bin" mkdir ".\bin"
if not exist ".\build\cache" mkdir ".\build\cache"

REM Build the docker image
docker build -t nim-builder .

REM Run the container with proper volume mounts
docker run --rm -it ^
    -v "%CD%:/app" ^
    nim-builder nimble shellcode --accept