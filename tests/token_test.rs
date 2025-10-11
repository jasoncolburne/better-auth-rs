use better_auth::Signable;
use better_auth::messages::AccessToken;

mod implementation;
use implementation::{Secp256r1, TokenEncoder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct MockAccessAttributes {
    #[serde(rename = "permissionsByRole")]
    permissions_by_role: serde_json::Value,
}

#[tokio::test]
async fn test_token_encode_decode() {
    let token_encoder = TokenEncoder::new();

    let temp_token_string = "0IAGTf0y29Ra-8cjCnXS8NlImAi4_KZfaxgr_5iAux1CLoOZ7d5tvFktxb8Xc6pU2pYQkMw0V75fwP537N9dToIyH4sIAAAAAAACA22PXY-iMBSG_wvX203rUBHuOgIDasQ1jC5uNobaKkU-TFtAZ-J_nzoXu8nOnsuT93k_3i3FZc9lzHijhb5ZnoUIiUl_mNkp0isAWHpgCzKMWSaghJvE309VxifT6_no3Nh1G1jfLMZ7ceCGDYJhvIoDqXySVCAcPdfc2VFYlHG-TabDa0leu1NE56Byc8OJv6lB0taqqFx5jGadHfUiTU9OHYrFXp17FmKIdpfMZk80ileGvHS0Eoc5_1P4jVIM1qW92Qb-7keC6-HlxZH-Yjm-Coxilm1Q2-AV3dPO4LLVuRZtE-WqeISHIZDEGWe125Z-BnVHxc9NuQZk3c-XziyS5-2ybt6OpyJ51Faq44xoQ47gCAMEAZykaORh17PR9wnG8PN2RsuvFyFv_yifPGR_UUp-lFwVwRfATSH8n3WutRS001xZ3rt14bI2xcwo9XxbtxV_PHNWi8byfhnznBlkkEJz6_f9fv8A44o2TvkBAAA";

    let mut temp_key = Secp256r1::new();
    temp_key.generate().expect("Failed to generate key");

    let temp_token = AccessToken::<MockAccessAttributes>::parse(temp_token_string, &token_encoder)
        .await
        .expect("Failed to parse token");

    let new_token = AccessToken::new(
        temp_token.server_identity.clone(),
        temp_token.device.clone(),
        temp_token.identity.clone(),
        temp_token.public_key.clone(),
        temp_token.rotation_hash.clone(),
        temp_token.issued_at.clone(),
        temp_token.expiry.clone(),
        temp_token.refresh_expiry.clone(),
        temp_token.attributes.clone(),
    );

    let mut signed_token = new_token;
    signed_token
        .sign(&temp_key)
        .await
        .expect("Failed to sign token");

    let token_string = signed_token
        .serialize_token(&token_encoder)
        .await
        .expect("Failed to serialize token");

    println!("Token string length: {}", token_string.len());
    println!("Token string: {}", token_string);

    let token = AccessToken::<MockAccessAttributes>::parse(&token_string, &token_encoder)
        .await
        .expect("Failed to parse signed token");

    assert_eq!(
        token.server_identity,
        "1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE"
    );
    assert_eq!(token.device, "EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a");
    assert_eq!(
        token.identity,
        "EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP"
    );
    assert_eq!(
        token.public_key,
        "1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu"
    );
    assert_eq!(
        token.rotation_hash,
        "EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO"
    );
    assert_eq!(token.issued_at, "2025-10-08T12:59:41.855000000Z");
    assert_eq!(token.expiry, "2025-10-08T13:14:41.855000000Z");
    assert_eq!(token.refresh_expiry, "2025-10-09T00:59:41.855000000Z");

    let expected_permissions: serde_json::Value = serde_json::json!({
        "admin": ["read", "write"]
    });
    assert_eq!(token.attributes.permissions_by_role, expected_permissions);
}
