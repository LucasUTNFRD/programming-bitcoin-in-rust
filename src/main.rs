use num_bigint::BigUint;

mod ecc;

fn main() {
    // Generator point coordinates
    let gx = BigUint::parse_bytes(
        b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        16,
    )
    .unwrap();
    let gy = BigUint::parse_bytes(
        b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        16,
    )
    .unwrap();

    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();

    // Calculate left side: y² mod p
    let left = (gy.pow(2u32)) % &p;
    println!("{}", left);

    // Calculate right side: (x³ + 7) mod p
    let right = (gx.pow(3u32) + BigUint::from(7u32)) % &p;
    println!("{}", right);

    assert_eq!(
        left, right,
        "Generator point does not satisfy the curve equation y² = x³ + 7"
    );
}
