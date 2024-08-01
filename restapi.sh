#!/bin/bash

# Step 1: Log in to get the JWT token
response=$(curl -s -X POST http://localhost:8000/login \
                 -H "Content-Type: application/json" \
                 -d '{"username": "admin", "password": "admin"}')

# Extract the JWT token from the response
token=$(echo "$response" | grep -oP '(?<=Set-Cookie: jwt=)[^;]+')

# Print the token (optional, for debugging)
echo "JWT Token: $token"

# Step 2: Access the restricted endpoint with the JWT token
curl -X GET http://localhost:8000/restricted \
     -H "Cookie: jwt=$token"
