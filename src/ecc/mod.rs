pub mod ecdsa;
mod field_element;
mod point;
pub mod secp256k1;

#[cfg(test)]
mod test {
    use primitive_types::U256;

    use crate::ecc::ecdsa::PublicKey;

    use super::ecdsa::{PrivateKey, Signature};

    #[test]
    fn exercise_1_ch4() {
        let private_key = PrivateKey::new(5000.into());
        let public_key = private_key.public_key();
        let sec_uncompressed = public_key.serialize_uncompressed();
        let sec_hex = hex::encode(sec_uncompressed);
        let expected = "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10";
        assert_eq!(sec_hex, expected);
        assert_eq!(public_key, PublicKey::parse(&sec_uncompressed).unwrap());
    }

    #[test]
    fn exercise_2_ch4() {
        let private_key = PrivateKey::new(5001.into());
        let public_key = private_key.public_key();
        let sec_compressed = public_key.serialize();
        let sec_hex = hex::encode(sec_compressed);
        let expected = "0257a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1";
        assert_eq!(sec_hex, expected);
        assert_eq!(
            public_key,
            PublicKey::parse_compressed(&sec_compressed).unwrap()
        );
    }

    #[test]
    fn exercise_3_ch4() {
        let r = U256::from_str_radix(
            "0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();

        let s = U256::from_str_radix(
            "0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        let signature = Signature::new(r.into(), s.into());
        let expected_der_signature = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let der_signature = signature.serialize_der();
        println!("{}", der_signature.len());
        assert_eq!(hex::encode(der_signature), expected_der_signature);
    }
}
