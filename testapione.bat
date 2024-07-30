@echo off
setlocal

REM Define the API endpoints
set LOGIN_URL=http://localhost:8000/login
set RESTRICTED_URL=http://localhost:8000/restricted

REM Define credentials (adjust as needed)
set USERNAME=admin
set PASSWORD=admin

REM Perform login and capture the JWT token
echo Logging in...
curl -v -X POST %LOGIN_URL% -H "Content-Type: application/json" -d "{\"username\":\"%USERNAME%\",\"password\":\"%PASSWORD%\"}" -c cookies.txt > response.txt 2>&1

REM Check if response.txt is empty
if not exist response.txt (
    echo response.txt does not exist.
    goto :EOF
)

for %%F in (response.txt) do if %%~zF equ 0 (
    echo response.txt is empty.
    goto :EOF
)

echo Login response captured.

REM Display the contents of response.txt and cookies.txt for debugging
echo.
echo Response.txt content:
type response.txt
echo.
echo Cookies.txt content:
type cookies.txt
echo.

REM Extract the JWT token from cookies.txt
set "JWT_TOKEN="
for /f "tokens=6 delims= " %%i in ('findstr /i "jwt=" cookies.txt') do (
    set "JWT_TOKEN=%%i"
)

REM Remove any surrounding quotes or extra spaces from the token
set "JWT_TOKEN=%JWT_TOKEN:~0,-1%"

REM Display the JWT token (for debugging purposes)
echo JWT Token: %JWT_TOKEN%

REM Access the restricted endpoint with POST method
echo Accessing restricted endpoint with POST method...
curl -v -X GET %RESTRICTED_URL% -H "Cookie: jwt=%JWT_TOKEN%" > restricted_response.txt 2>&1

REM Check if restricted_response.txt is empty
if not exist restricted_response.txt (
    echo restricted_response.txt does not exist.
    goto :EOF
)

for %%F in (restricted_response.txt) do if %%~zF equ 0 (
    echo restricted_response.txt is empty.
    goto :EOF
)

echo Restricted endpoint response captured.

REM Display the results
echo.
echo Login response:
type response.txt
echo.
echo Restricted endpoint response:
type restricted_response.txt

endlocal
