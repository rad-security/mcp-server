#! /bin/bash

# Run the server
export RAD_SECURITY_API_URL="https://api.sbx.rad.security"
export RAD_SECURITY_ACCESS_KEY_ID="<>"
export RAD_SECURITY_SECRET_KEY="<>"
export RAD_SECURITY_ACCOUNT_ID="<>"

# Run the server
node dist/index.js
