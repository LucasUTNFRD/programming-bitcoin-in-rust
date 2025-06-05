use field_element::{FieldElement, Pow};

mod field_element;

fn generate_Fp_ex_7(prime: u64) -> Vec<FieldElement> {
    // construct vec from 1..p-1 of all the elem to p-1
    (1..prime)
        .map(|n| FieldElement::new(n, prime).unwrap().pow(prime - 1))
        .collect()
}

fn main() {
    let primes = vec![7, 11, 17, 31];

    for p in primes {
        let subset = generate_Fp_ex_7(p);
        println!("{:?}", subset);
    }
}
