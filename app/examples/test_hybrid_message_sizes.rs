use app::hybrid_combiner_flex;
use openmls::prelude::Ciphersuite;

fn main() {
    println!("Testing message size tracking for hybrid_combiner_flex...\n");

    // Keep runs short for quick feedback
    let client_count: u8 = 2;
    let epochs: i32 = 500;
    let ratios: Vec<u8> = vec![1, 2, 5, 10, 50, 100];
    // let ratios: Vec<u8> = vec![1, 10, 50, 100];
    // let ratios: Vec<u8> = vec![10];

    // Sample pairs (PQ, Standard) similar to benches
    let pairs: Vec<(Ciphersuite, Ciphersuite)> = vec![
                // (
                //     Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256,
                //     Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                // ),
                // (
                //     Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256,
                //     Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                // ),
                // (
                //     Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384,
                //     Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                // ),

                //  // (PQ ciphersuite, Traditional ciphersuite) pairs
                // (
                //     Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44,
                //     Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                //     //ECDSA-P256 is only EUF-CMA so we use a comparable DSA that's SUF-CMA instead
                //     //(i.e. Ed25519)
                //     //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                // ),
                // (
                //     Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
                //     Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                //     //See note above on EUF vs SUF CMA
                //     //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                // ),
                // (
                //     Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
                //     Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                //     //See note above on EUF vs SUF CMA
                //     //Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
                // ),
                (
                    // Most direct comparison with X-Wing
                    Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ),
                (
                    // Most direct comparison with X-Wing, plus PQ Auth
                    Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ),
    ];

    for (cs_pq, cs_st) in pairs {
        println!("\n=== Pair: PQ={:?} | ST={:?} ===", cs_pq, cs_st);
        for r in &ratios {
            println!("-- ratio 1:{} (ST per PQ), clients={}, epochs={} --", r, client_count, epochs);
            // This will print a summary at the end of each call
            hybrid_combiner_flex(client_count, *r, epochs, cs_pq, cs_st);
        }
    }

    println!("\nDone testing hybrid combiner message sizes.\n");
}
