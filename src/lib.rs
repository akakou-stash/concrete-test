extern crate rand;

#[warn(unused_imports)]
use concrete::*;
use rand::Rng;

#[test]
fn gen_key() -> Result<(), CryptoAPIError> {
    // settings
    let base_log: usize = 6;
    let level: usize = 4;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_630);

    // bootstrapping key
    println!("gen bootstrap keys");
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, base_log, level);
    println!("save keys");

    sk_rlwe.save("rlwe_key.json").unwrap();
    sk_in.save("lwe_key.json").unwrap();
    bsk.save("bootstrapping_key.json");
    Ok(())
}

pub fn calc_mul() -> Result<(), CryptoAPIError> {
    // encoders
    let encoder_input = Encoder::new(-20., 20., 24, 2)?;

    // secret keys
    let sk_rlwe = RLWESecretKey::load("rlwe_key.json").unwrap();
    let sk_in = LWESecretKey::load("lwe_key.json").unwrap();
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // bootstrapping key
    println!("load keys");
    //let bsk = LWEBSK::new(&sk_in, &sk_rlwe, 5, 3);
    let bsk = LWEBSK::load("bootstrapping_key.json");

    println!("start calc");
    for _ in 1..1000 {
        // encode and encrypt
        //println!("encrypt");
        let p1: f64 = rand::thread_rng().gen_range(-20. ..20.);
        let p2: f64 = rand::thread_rng().gen_range(-20. ..20.);

        let c1 = LWE::encode_encrypt(&sk_in, p1, &encoder_input)?;
        let c2 = LWE::encode_encrypt(&sk_in, p2, &encoder_input)?;

        // bootstrap
        let c3 = c1.mul_from_bootstrap(&c2, &bsk)?;

        // decrypt
        let d = c3.decrypt_decode(&sk_out)?;
        let e = p1 * p2;

        let diff = e - d;

        // diff / 400 * 100 = diff / 4
        println!("{}", diff);
    }

    Ok(())
}

#[test]
fn test_calc_mul() {
    calc_mul().unwrap();
}
