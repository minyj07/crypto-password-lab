@echo off
REM This script builds and starts the Docker container for the web server.

echo [INFO] Please make sure Docker Desktop is running.
echo [INFO] Starting the web server... This window must remain open to keep the server running.

REM Execute the Docker Compose command.
REM The --build flag rebuilds the image if it's missing or if there are changes.
docker-compose up --build

echo [INFO] The server has been shut down.
pause