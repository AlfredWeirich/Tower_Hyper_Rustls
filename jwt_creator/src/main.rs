use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::fs::{read_to_string, write};

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    name: String,
    iat: u64,
    exp: u64,
    jti: String, // <- Added unique identifier
}

fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("Time error: {e}"))
}

fn create_jwt(claims: &Claims, private_key_path: &str) -> Result<String, String> {
    let private_key =
        read_to_string(private_key_path).map_err(|e| format!("Failed to read private key: {e}"))?;

    encode(
        &Header::new(Algorithm::RS256),
        claims,
        &EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|e| format!("Encoding key error: {e}"))?,
    )
    .map_err(|e| format!("JWT creation error: {e}"))
}

fn verify_jwt(token: &str, public_key_path: &str) -> Result<Claims, String> {
    let public_key =
        read_to_string(public_key_path).map_err(|e| format!("Failed to read public key: {e}"))?;

    decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(public_key.as_bytes())
            .map_err(|e| format!("Decoding key error: {e}"))?,
        &Validation::new(Algorithm::RS256),
    )
    .map(|data| data.claims)
    .map_err(|e| format!("JWT verification error: {e}"))
}

fn main() -> Result<(), String> {
    let now = current_timestamp()?;

    let claims1 = Claims {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: now,
        exp: now + 3600 * 24 * 30, // 30 days
        jti: uuid::Uuid::new_v4().to_string(),
    };

    let claims2 = Claims {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: now,
        exp: now + 3600, // 1h
        jti: uuid::Uuid::new_v4().to_string(),
    };

    // Create JWT
    let token1 = create_jwt(&claims1, "./jwt_creator/private_key.pem")?;
    println!("JWT 1: {token1}");
    write("./jwt_creator/token1.jwt", &token1)
        .map_err(|e| format!("Failed to write token1: {e}",))?;

    let token2 = create_jwt(&claims2, "./jwt_creator/private_key.pem")?;
    println!("JWT 2: {token2}");
    write("./jwt_creator/token2.jwt", &token2)
        .map_err(|e| format!("Failed to write token1: {e}"))?;

    // Verify JWT
    let decoded_claims = verify_jwt(&token1, "./jwt_creator/public_key.pem")?;
    println!("Decoded Claims 1: {decoded_claims:?}");
    let decoded_claims = verify_jwt(&token2, "./jwt_creator/public_key.pem")?;
    println!("Decoded Claims 2: {decoded_claims:?}");

    Ok(())
}
