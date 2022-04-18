# Guide for jwt

## General security warn

You and only you are responsible for security of your application.

## Key length for HMAC (HS) algorithms

Looking and one of the attacks on HMAC we should be careful with key length.

In test and examples it short for clarity but in production (or anything beside examples) it must be more secure.

See `jwt.GenerateRandom512Bit` func in [jwt.go](https://github.com/cristalhq/jwt/blob/main/jwt.go)

Source: https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/ 
