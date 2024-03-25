# JWKS-Server2
A functional JWKS server with a RESTful API that can serve public keys with expiry and unique kid to verify JWTs, backed by a SQLite database. 
The server authenticates fake users requests, issues JWTs upon successful authentication, and handles the “expired” query parameter to issue JWTs signed with an expired key.
