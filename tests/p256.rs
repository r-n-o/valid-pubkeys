use p256::{
    EncodedPoint,
    PublicKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use p256::FieldElement;

/// Return true if y is even (LSB of big-endian field repr is 0)
fn is_even_y(y: &FieldElement) -> bool {
    let r = y.to_bytes();
    // Big-endian; parity determined by the least significant bit (LSB) of the last byte.
    (r.to_vec()[31] & 1) == 0
}

#[test]
fn compressed_x_is_zero_is_valid_and_matches_y2_eq_b() {
    // Build SEC1 compressed: 0x0200..00 (0x02 + 32 zero bytes)
    let mut pubkey_bytes = vec![0x02u8];
    pubkey_bytes.extend_from_slice(&[0u8; 32]);

    // Proves that RustCrypto accepts this!
    let pubkey = PublicKey::from_sec1_bytes(&pubkey_bytes).expect("valid point with x=0");

    // Round-trip back to compressed form and ensure it matches
    let compressed_point = pubkey.to_encoded_point(true);
    assert_eq!(compressed_point.as_bytes(), pubkey_bytes.as_slice(),);
    
    // Check that the x coordinate is 0 (32 0-bytes)
    let uncompressed_point = pubkey.to_encoded_point(false);
    let point_x = uncompressed_point.x().unwrap().to_vec();
    assert_eq!(point_x, &[0u8; 32]);
    
    // Check that the y coordinate is NOT zero
    let point_y = uncompressed_point.y().unwrap().to_vec();
    assert_ne!(point_y, &[0u8; 32]);

    // P-256 curve parameter `b` from SEC2 / FIPS 186-4:
    // b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    // See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    let b = FieldElement::from_slice(
        &hex::decode("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B").unwrap()
    ).unwrap();

    let y2 = FieldElement::from_slice(&point_y).unwrap().square();

    // Paranoia: verify y^2 == b (since x=0, that's what the curve equation y^2 = b)
    assert_eq!(y2, b);

    // Compressed prefix 0x02 denotes "even" y; check that too!
    assert!(is_even_y(&FieldElement::from_slice(&point_y).unwrap()));
}

#[test]
fn identity_encoding_is_not_a_usable_public_key() {
    // SEC1 uses a single 0x00 byte for the point at infinity (the public key for d=0).
    let infinity = [0x00u8];

    // EncodedPoint accepts it syntactically...
    let ep = EncodedPoint::from_bytes(&infinity).expect("identity SEC1 is syntactically valid");
    assert!(ep.is_identity());

    // ...but it's not a valid *public key* (no finite affine coordinates).
    let parsed_pubkey = PublicKey::from_sec1_bytes(&infinity);
    assert!(parsed_pubkey.is_err());
}

#[test]
fn aa_repeated_x_is_not_on_curve() {
    // x = 0xaa..aa repeated 32 bytes; compressed prefix 0x02 
    let mut sec1 = vec![0x02u8];
    sec1.extend_from_slice(&[0xAAu8; 32]);

    // Ensure it's not a valid public key
    let parsed_pubkey = PublicKey::from_sec1_bytes(&sec1);
    assert!(parsed_pubkey.is_err());
}
