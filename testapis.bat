@echo off
setlocal

REM Define the API endpoint and credentials
set LOGIN_URL=http://localhost:8000/login
set USERNAME=admin
set PASSWORD=admin

REM Perform login and capture the JWT token
echo Logging in...
curl -v -X POST %LOGIN_URL% -H "Content-Type: application/json" -d "{\"username\":\"%USERNAME%\",\"password\":\"%PASSWORD%\"}" -c cookies.txt > response.txt

REM Display the contents of response.txt and cookies.txt for debugging
echo.
echo Response.txt content:
type response.txt
echo.
echo Cookies.txt content:
type cookies.txt
echo.

endlocal
