@echo off
REM Fetch configuration for max_users
curl -s http://localhost:8000/config/max_users

REM Pause to keep the command prompt window open
pause
