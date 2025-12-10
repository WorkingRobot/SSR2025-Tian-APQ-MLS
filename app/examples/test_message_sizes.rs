use app::{solo_with_epochs, solo_with_epochs_with_stats};
use openmls::prelude::Ciphersuite;

fn main() {
    println!("Testing message size tracking for solo_with_epochs...\n");
    
    // Test with a small number of epochs for quick demonstration
    let client_count = 2;
    let epochs = 500;
    
    // All ciphersuites from CiphersuiteCategories (traditional, pq_conf, pq_conf_auth)
    let ciphersuites = vec![
        // traditional
        ("Traditional X25519+Ed25519", Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        ("Traditional P-256+ECDSA", Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
        ("Traditional X25519+CHACHA20+Ed25519", Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        ("Traditional X448+Ed448 (AES-GCM)", Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
        ("Traditional P-384+ECDSA", Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
        ("Traditional X448+Ed448 (ChaCha20)", Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),

        // pq_conf (PQ KEM + traditional signatures)
        ("PQ Conf MLKEM512+Ed25519 (AES128GCM)", Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519),
        ("PQ Conf MLKEM768+Ed25519 (ChaCha20)", Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519),
        ("PQ Conf MLKEM768+Ed25519 (AES256GCM)", Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_Ed25519),
        ("PQ Conf MLKEM1024+Ed25519 (AES256GCM)", Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519),
        ("PQ Conf MLKEM512+P256", Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256),
        ("PQ Conf MLKEM768+P256", Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256),
        ("PQ Conf MLKEM1024+P384", Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384),

        // pq_conf_auth (PQ KEM + PQ signatures)
        ("PQ Conf+Auth MLKEM512+MLDSA44", Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44),
        ("PQ Conf+Auth MLKEM768+MLDSA65 (AES256GCM)", Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65),
        ("PQ Conf+Auth MLKEM768+MLDSA65 (ChaCha20)", Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65),
        ("PQ Conf+Auth MLKEM1024+MLDSA87", Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87),

        // X-wing
        ("X-wing", Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
    ];
    
    println!("=== MESSAGE SIZE COMPARISON TABLE ===");
    println!("{:<40} {:>12} {:>12} {:>12} {:>12}", "Ciphersuite", "Avg Welcome", "Avg Commit", "Total Welcome", "Total Traffic");
    println!("{}", "-".repeat(90));
    
    for (name, cs) in ciphersuites {
        let stats = solo_with_epochs_with_stats(client_count, epochs, cs);
        println!("{:<40} {:>12.0} {:>12.0} {:>12} {:>12}",
            name,
            stats.get_avg_welcome_size(),
            stats.get_avg_commit_size(),
            stats.get_total_welcome_bytes(),
            stats.total_bytes
        );
    }
    
    println!("\n=== DETAILED STATISTICS FOR KEY CIPHERSUITES ===\n");
    println!("X-Wing (Chcha+Ed25519): "); 
    solo_with_epochs(client_count, epochs, Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519); 
    // println!("Traditional (X25519+Ed25519):");
    // solo_with_epochs(client_count, epochs, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    // println!("PQ-Conf (ML-KEM768+P256):");
    // solo_with_epochs(client_count, epochs, Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256);
    // println!("PQ-Conf+Auth (ML-KEM768+ML-DSA65):");
    // solo_with_epochs(client_count, epochs, Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65);
}
