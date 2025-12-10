use openmls::{
    ciphersuite,
    prelude::{tls_codec::*, *},
    schedule::{ExternalPsk, PreSharedKeyId},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use rand::Rng;
use std::collections::HashSet;

/// Statistics for tracking message sizes in solo operations
#[derive(Debug, Default)]
pub struct SoloMessageSizeStats {
    pub welcome_messages: Vec<usize>,
    pub commit_messages: Vec<usize>,
    pub epoch_count: usize,
    pub total_bytes: usize,
}

impl SoloMessageSizeStats {
    pub fn add_welcome(&mut self, size: usize) {
        self.welcome_messages.push(size);
        self.total_bytes += size;
    }
    
    pub fn add_commit(&mut self, size: usize) {
        self.commit_messages.push(size);
        self.total_bytes += size;
    }
    
    pub fn get_avg_welcome_size(&self) -> f64 {
        if self.welcome_messages.is_empty() {
            0.0
        } else {
            self.welcome_messages.iter().sum::<usize>() as f64 / self.welcome_messages.len() as f64
        }
    }
    
    pub fn get_avg_commit_size(&self) -> f64 {
        if self.commit_messages.is_empty() {
            0.0
        } else {
            self.commit_messages.iter().sum::<usize>() as f64 / self.commit_messages.len() as f64
        }
    }
    
    pub fn get_total_welcome_bytes(&self) -> usize {
        self.welcome_messages.iter().sum()
    }
    
    pub fn get_total_commit_bytes(&self) -> usize {
        self.commit_messages.iter().sum()
    }
    
    pub fn print_stats(&self, cs: Ciphersuite) {
        println!("\n=== SOLO MESSAGE SIZE STATISTICS ===");
        println!("Ciphersuite: {:?}", cs);
        println!("Epochs: {}", self.epoch_count);
        
        if !self.welcome_messages.is_empty() {
            let avg_welcome = self.get_avg_welcome_size();
            let total_welcome = self.get_total_welcome_bytes();
            println!("Welcome Messages: {} (avg: {:.1} bytes, total: {} bytes)", 
                    self.welcome_messages.len(), avg_welcome, total_welcome);
        }
        
        if !self.commit_messages.is_empty() {
            let avg_commit = self.get_avg_commit_size();
            let total_commit = self.get_total_commit_bytes();
            println!("Commit Messages: {} (avg: {:.1} bytes, total: {} bytes)", 
                    self.commit_messages.len(), avg_commit, total_commit);
        }
        
        println!("Total Traffic: {} bytes", self.total_bytes);
        println!("====================================\n");
    }
}

/// Statistics for tracking message sizes in the hybrid combiner
#[derive(Debug, Default)]
pub struct HybridMessageSizeStats {
    // PQ group
    pub pq_welcome_messages: Vec<usize>,
    pub pq_commit_messages: Vec<usize>,
    pub pq_proposal_messages: Vec<usize>,
    pub total_pq_bytes: usize,
    // Standard group
    pub st_welcome_messages: Vec<usize>,
    pub st_commit_messages: Vec<usize>,
    pub st_proposal_messages: Vec<usize>,
    pub total_st_bytes: usize,
    // PSK export sizes (context + exported size proxy)
    pub psk_export_sizes: Vec<usize>,
    // Meta
    pub epoch_count: usize,
    pub ratio: u8,
}

impl HybridMessageSizeStats {
    pub fn add_pq_welcome(&mut self, bytes: usize) {
        self.pq_welcome_messages.push(bytes);
        self.total_pq_bytes += bytes;
    }
    pub fn add_pq_commit(&mut self, bytes: usize) {
        self.pq_commit_messages.push(bytes);
        self.total_pq_bytes += bytes;
    }
    pub fn add_pq_proposal(&mut self, bytes: usize) {
        self.pq_proposal_messages.push(bytes);
        self.total_pq_bytes += bytes;
    }
    pub fn add_st_welcome(&mut self, bytes: usize) {
        self.st_welcome_messages.push(bytes);
        self.total_st_bytes += bytes;
    }
    pub fn add_st_commit(&mut self, bytes: usize) {
        self.st_commit_messages.push(bytes);
        self.total_st_bytes += bytes;
    }
    pub fn add_st_proposal(&mut self, bytes: usize) {
        self.st_proposal_messages.push(bytes);
        self.total_st_bytes += bytes;
    }
    pub fn add_psk_export(&mut self, bytes: usize) {
        self.psk_export_sizes.push(bytes);
    }
    pub fn print_stats(&self, cs_pq: Ciphersuite, cs_st: Ciphersuite) {
        println!("\n=== HYBRID MESSAGE SIZE STATS ===");
        println!("PQ: {:?} | ST: {:?}", cs_pq, cs_st);
        println!("epochs: {} | ratio 1:{} (ST per PQ)", self.epoch_count, self.ratio);
        if !self.pq_welcome_messages.is_empty() {
            let sum: usize = self.pq_welcome_messages.iter().sum();
            println!("PQ welcomes: {} (avg {} B)", self.pq_welcome_messages.len(), sum / self.pq_welcome_messages.len());
        }
        if !self.st_welcome_messages.is_empty() {
            let sum: usize = self.st_welcome_messages.iter().sum();
            println!("ST welcomes: {} (avg {} B)", self.st_welcome_messages.len(), sum / self.st_welcome_messages.len());
        }
        if !self.pq_commit_messages.is_empty() {
            let sum: usize = self.pq_commit_messages.iter().sum();
            println!("PQ commits: {} (avg {} B)", self.pq_commit_messages.len(), sum / self.pq_commit_messages.len());
        }
        if !self.st_commit_messages.is_empty() {
            let sum: usize = self.st_commit_messages.iter().sum();
            println!("ST commits: {} (avg {} B)", self.st_commit_messages.len(), sum / self.st_commit_messages.len());
        }
        if !self.st_proposal_messages.is_empty() {
            let sum: usize = self.st_proposal_messages.iter().sum();
            println!("ST proposals: {} (avg {} B)", self.st_proposal_messages.len(), sum / self.st_proposal_messages.len());
        }
        if !self.psk_export_sizes.is_empty() {
            let sum: usize = self.psk_export_sizes.iter().sum();
            println!("PSK exports: {} (avg {} B)", self.psk_export_sizes.len(), sum / self.psk_export_sizes.len());
        }
        println!("PQ total: {} B | ST total: {} B | Combined: {} B", self.total_pq_bytes, self.total_st_bytes, self.total_pq_bytes + self.total_st_bytes);
        println!("==================================\n");
    }
}

// *************************************************************************************************************
// *************************************************************************************************************
// ************************************************** HYBRID ***************************************************
// *************************************************************************************************************
// *************************************************************************************************************

pub fn hybrid_combiner(client_num: u8, ratio: u8) {
    // Define ciphersuites ...
    let cs_pq = Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519;
    let cs_st = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let epoch_total = 500;

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create two vectors to store client credentials, one for the PQ group and one for the standard group
    let mut clients_pq: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();
    let mut clients_st: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the client list
    let owner_pq: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_pq.signature_algorithm(), provider);

    let owner_st: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_st.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client_pq: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_pq.signature_algorithm(), provider);
        clients_pq.push(client_pq);

        let client_st: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_st.signature_algorithm(), provider);
        clients_st.push(client_st);
    }

    // Generate KeyPackages
    let mut client_key_packages_pq: Vec<KeyPackage> = Vec::new();
    let mut client_key_packages_st: Vec<KeyPackage> = Vec::new();

    for i in clients_pq {
        let key_package_pq = generate_key_package(cs_pq, provider, &i.1, i.0);
        client_key_packages_pq.push(key_package_pq);
    }

    for i in clients_st {
        let key_package_st = generate_key_package(cs_st, provider, &i.1, i.0);
        client_key_packages_st.push(key_package_st);
    }

    // Now Owner starts a new group ...
    let mut group_pq = MlsGroup::new(
        provider,
        &owner_pq.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_pq).build(),
        owner_pq.0,
    )
    .expect("An unexpected error occurred.");

    // Now Owner starts a new group ...
    let mut group_st = MlsGroup::new(
        provider,
        &owner_st.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_st).build(),
        owner_st.0,
    )
    .expect("An unexpected error occurred.");
    //
    //
    //
    // Initial Setup Complete
    //
    //
    //

    // Invite clients to pq group
    let (_mls_message_out, welcome_out, _group_info) = group_pq
        .add_members(provider, &owner_pq.1, &client_key_packages_pq.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds Clients to the pq group.
    group_pq
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // The message is fanned out

    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups_pq: Vec<MlsGroup> =
        welcome_message_fanout(&user_id_list, serialized_welcome, provider, &group_pq);

    // Now invite clients to the standard group
    let (_mls_message_out, welcome_out, _group_info) = group_st
        .add_members(provider, &owner_st.1, &client_key_packages_st.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds Clients to the st group.
    group_st
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // The message is fanned out
    let mut client_groups_st =
        welcome_message_fanout(&user_id_list, serialized_welcome, provider, &group_st);

    // Export PSK from pq group
    let mut w: Vec<u8> = Vec::new();
    group_pq
        .export_group_context()
        .tls_serialize(&mut w)
        .unwrap();

    let combiner_psk = group_pq
        .export_secret(provider.crypto(), "Combiner", &mut w, 32)
        .unwrap();

    let rng = openmls_rust_crypto::RustCrypto::default();

    let psk_id = PreSharedKeyId::new(
        cs_st,
        &rng,
        openmls::schedule::Psk::External(openmls::schedule::psk::ExternalPsk::new(
            combiner_psk.clone(),
        )),
    )
    .unwrap();

    psk_id.store(provider, &combiner_psk.as_slice()).unwrap();

    // Owner sets the combiner PSK as a proposal for the st group's joins, may need to happen before their welcome is generated
    let (mls_message_out, _proposal_ref) = group_st
        .propose_external_psk(provider, &owner_st.1, psk_id)
        .unwrap();

    let serialized_message = mls_message_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    message_fanout(
        &mut client_groups_st,
        serialized_message,
        provider, /* &group_st */
    );

    let (mls_message_out, _welcome_option, _group_info) = group_st
        .commit_to_pending_proposals(provider, &owner_st.1)
        .expect("Could not commit to pending proposals.");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_message = mls_message_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // Owner merges the commit to advance to new epoch
    group_st
        .merge_pending_commit(provider)
        .expect("Error merging staged commit.");

    message_fanout(
        &mut client_groups_st,
        serialized_message,
        provider, /* &group_st */
    );

    //
    //--------------------------------------------------------------------------
    // Group setup complete, current state is epoch 1, now to run followon epochs
    //---------------------------------------------------------------------------
    //

    let mut epoch = 1; //increments with each standard group epoch progression
    while epoch < epoch_total {
        // in each epoch, the group owner merges an empty commit to roll into the next epoch

        // let the standard session do its partial commits before having the pq session merge and export
        for _a in 0..ratio {
            // Make empty commit
            let queued_message = group_st
                .self_update(provider, &owner_st.1, LeafNodeParameters::default())
                .expect("error merging pending commit")
                .into_commit();

            let serialized_message = queued_message
                .tls_serialize_detached()
                .expect("Error serializing welcome");

            // Merge for owner
            group_st
                .merge_pending_commit(provider)
                .expect("Error for owner merging pending commit.");

            message_fanout(
                &mut client_groups_st,
                serialized_message,
                provider, /* &group_st */
            );

            // Increment epoch once it has changed
            epoch = epoch + 1;
        }

        // Here we have completed the series of partial commits and now must do our full commit
        // which is all of the above on the PQ side, doing a PSK export, and then one more commit to get the standard group up to speed
        // Make empty commit
        let queued_message = group_pq
            .self_update(
                provider,
                &owner_pq.1,
                LeafNodeParameters::builder()
                    .with_capabilities(Capabilities::new(None, Some(&[cs_pq]), None, None, None))
                    .build(),
            )
            .unwrap()
            .into_commit();

        // Merge
        group_pq
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");
        // Simulate creating merge message
        let serialized_message = queued_message
            .tls_serialize_detached()
            .expect("Error serializing update");

        message_fanout(
            &mut client_groups_pq,
            serialized_message,
            provider, /* &group_pq */
        );

        // Export PSK from pq group
        let mut w: Vec<u8> = Vec::new();
        group_pq
            .export_group_context()
            .tls_serialize(&mut w)
            .unwrap();

        let combiner_psk = group_pq
            .export_secret(provider.crypto(), "Combiner", &mut w, 32)
            .unwrap();

        let rng = openmls_rust_crypto::RustCrypto::default();

        let psk_id = PreSharedKeyId::new(
            cs_st,
            &rng,
            openmls::schedule::Psk::External(openmls::schedule::psk::ExternalPsk::new(
                combiner_psk.clone(),
            )),
        )
        .unwrap();

        psk_id.store(provider, &combiner_psk.as_slice()).unwrap();

        // Owner sets the combiner PSK as a proposal for the st group's joins, may need to happen before their welcome is generated
        let (mls_message_out, _proposal_ref) = group_st
            .propose_external_psk(provider, &owner_st.1, psk_id)
            .unwrap();

        let serialized_message = mls_message_out
            .tls_serialize_detached()
            .expect("Error serializing welcome");

        message_fanout(
            &mut client_groups_st,
            serialized_message,
            provider, /* &group_st */
        );

        let (mls_message_out, _welcome_option, _group_info) = group_st
            .commit_to_pending_proposals(provider, &owner_st.1)
            .expect("Could not commit to pending proposals.");

        // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
        let serialized_message = mls_message_out
            .tls_serialize_detached()
            .expect("Error serializing welcome");

        // Owner merges the commit to advance to new epoch
        group_st
            .merge_pending_commit(provider)
            .expect("Error merging staged commit.");

        message_fanout(
            &mut client_groups_st,
            serialized_message,
            provider, /* &group_st */
        );
    }
    //println!("Done!");
}

/// Flexible hybrid combiner that accepts any pair of ciphersuites
/// cs_pq: Post-quantum ciphersuite for the PQ group
/// cs_st: Traditional ciphersuite for the standard group
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn hybrid_combiner_flex(
    client_num: u8,
    ratio: u8,
    epochs: i32,
    cs_pq: Ciphersuite,
    cs_st: Ciphersuite,
) {
    // Message size tracking (similar to solo_with_epochs)
    let mut stats = HybridMessageSizeStats::default();
    stats.epoch_count = epochs as usize;
    stats.ratio = ratio;

    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let epoch_total = epochs;

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create two vectors to store client credentials, one for the PQ group and one for the standard group
    let mut clients_pq: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();
    let mut clients_st: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the client list
    let owner_pq: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_pq.signature_algorithm(), provider);

    let owner_st: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_st.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client_pq: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_pq.signature_algorithm(), provider);
        clients_pq.push(client_pq);

        let client_st: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_st.signature_algorithm(), provider);
        clients_st.push(client_st);
    }

    // Generate KeyPackages
    let mut client_key_packages_pq: Vec<KeyPackage> = Vec::new();
    let mut client_key_packages_st: Vec<KeyPackage> = Vec::new();

    for i in clients_pq {
        let key_package_pq = generate_key_package(cs_pq, provider, &i.1, i.0);
        client_key_packages_pq.push(key_package_pq);
    }

    for i in clients_st {
        let key_package_st = generate_key_package(cs_st, provider, &i.1, i.0);
        client_key_packages_st.push(key_package_st);
    }

    // Now Owner starts a new group ...
    let mut group_pq = MlsGroup::new(
        provider,
        &owner_pq.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_pq).build(),
        owner_pq.0,
    )
    .expect("An unexpected error occurred.");

    // Now Owner starts a new group ...
    let mut group_st = MlsGroup::new(
        provider,
        &owner_st.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_st).build(),
        owner_st.0,
    )
    .expect("An unexpected error occurred.");

    //
    // Initial Setup Complete
    //

    // Invite clients to pq group
    let (_mls_message_out, welcome_out, _group_info) = group_pq
        .add_members(provider, &owner_pq.1, &client_key_packages_pq.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds Clients to the pq group.
    group_pq
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    stats.add_pq_welcome(serialized_welcome.len());

    // The message is fanned out
    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups_pq: Vec<MlsGroup> =
        welcome_message_fanout(&user_id_list, serialized_welcome, provider, &group_pq);

    // Now invite clients to the standard group
    let (_mls_message_out, welcome_out, _group_info) = group_st
        .add_members(provider, &owner_st.1, &client_key_packages_st.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds Clients to the st group.
    group_st
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    stats.add_st_welcome(serialized_welcome.len());

    // The message is fanned out
    let mut client_groups_st =
        welcome_message_fanout(&user_id_list, serialized_welcome, provider, &group_st);

    // Export PSK from pq group
    let mut w: Vec<u8> = Vec::new();
    group_pq
        .export_group_context()
        .tls_serialize(&mut w)
        .unwrap();

    let combiner_psk = group_pq
        .export_secret(provider.crypto(), "Combiner", &mut w, 32)
        .unwrap();

    let rng = openmls_rust_crypto::RustCrypto::default();

    let psk_id = PreSharedKeyId::new(
        cs_st,
        &rng,
        openmls::schedule::Psk::External(openmls::schedule::psk::ExternalPsk::new(
            combiner_psk.clone(),
        )),
    )
    .unwrap();

    psk_id.store(provider, &combiner_psk.as_slice()).unwrap();

    // Owner sets the combiner PSK as a proposal for the st group's joins, may need to happen before their welcome is generated
    let (mls_message_out, _proposal_ref) = group_st
        .propose_external_psk(provider, &owner_st.1, psk_id)
        .unwrap();

    let serialized_message = mls_message_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    stats.add_st_proposal(serialized_message.len());

    message_fanout(&mut client_groups_st, serialized_message, provider);

    let (mls_message_out, _welcome_option, _group_info) = group_st
        .commit_to_pending_proposals(provider, &owner_st.1)
        .expect("Could not commit to pending proposals.");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_message = mls_message_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    stats.add_st_commit(serialized_message.len());

    // Owner merges the commit to advance to new epoch
    group_st
        .merge_pending_commit(provider)
        .expect("Error merging staged commit.");

    message_fanout(&mut client_groups_st, serialized_message, provider);

    //
    //--------------------------------------------------------------------------
    // Group setup complete, current state is epoch 1, now to run followon epochs
    //---------------------------------------------------------------------------
    //

    let mut epoch = 1; //increments with each standard group epoch progression
    while epoch < epoch_total {
        // in each epoch, the group owner merges an empty commit to roll into the next epoch

        // let the standard session do its partial commits before having the pq session merge and export
        for _a in 0..(ratio-1) {
            // Make empty commit
            let queued_message = group_st
                .self_update(provider, &owner_st.1, LeafNodeParameters::default())
                .expect("error merging pending commit")
                .into_commit();

            let serialized_message = queued_message
                .tls_serialize_detached()
                .expect("Error serializing welcome");
            stats.add_st_commit(serialized_message.len());
                    
            // Merge for owner
            group_st
                .merge_pending_commit(provider)
                .expect("Error for owner merging pending commit.");

            message_fanout(&mut client_groups_st, serialized_message, provider);

            // Increment epoch once it has changed
            epoch = epoch + 1;
        }

        // Here we have completed the series of partial commits and now must do our full commit
        // which is all of the above on the PQ side, doing a PSK export, and then one more commit to get the standard group up to speed
        // Make empty commit
        let queued_message = group_pq
            .self_update(
                provider,
                &owner_pq.1,
                LeafNodeParameters::builder()
                    .with_capabilities(Capabilities::new(
                        None,
                        Some(&[cs_pq, cs_st]),
                        None,
                        None,
                        None,
                    ))
                    .build(),
            )
            .unwrap()
            .into_commit();

        // Merge
        group_pq
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");

        // Simulate creating merge message
        let serialized_message = queued_message
            .tls_serialize_detached()
            .expect("Error serializing update");
    stats.add_pq_commit(serialized_message.len());

        message_fanout(&mut client_groups_pq, serialized_message, provider);

        // Export PSK from pq group
        let mut w: Vec<u8> = Vec::new();
        group_pq
            .export_group_context()
            .tls_serialize(&mut w)
            .unwrap();

        let combiner_psk = group_pq
            .export_secret(provider.crypto(), "Combiner", &mut w, 32)
            .unwrap();

        let rng = openmls_rust_crypto::RustCrypto::default();

        let psk_id = PreSharedKeyId::new(
            cs_st,
            &rng,
            openmls::schedule::Psk::External(openmls::schedule::psk::ExternalPsk::new(
                combiner_psk.clone(),
            )),
        )
        .unwrap();

        psk_id.store(provider, &combiner_psk.as_slice()).unwrap();

        // Owner sets the combiner PSK as a proposal for the st group's joins, may need to happen before their welcome is generated
        let (mls_message_out, _proposal_ref) = group_st
            .propose_external_psk(provider, &owner_st.1, psk_id)
            .unwrap();

        let serialized_message = mls_message_out
            .tls_serialize_detached()
            .expect("Error serializing psk");
    stats.add_st_proposal(serialized_message.len());

        message_fanout(&mut client_groups_st, serialized_message, provider);
        // Standard group incorporates PSK proposal 
        let (mls_message_out, _welcome_option, _group_info) = group_st
            .commit_to_pending_proposals(provider, &owner_st.1)
            .expect("Could not commit to pending proposals.");

        // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
        let serialized_message = mls_message_out
            .tls_serialize_detached()
            .expect("Error serializing welcome");
    stats.add_st_commit(serialized_message.len());

        // Owner merges the commit to advance to new epoch
        group_st
            .merge_pending_commit(provider)
            .expect("Error merging staged commit.");

        message_fanout(&mut client_groups_st, serialized_message, provider);
        
        // Increment epoch after the PSK commit completes (ST group advanced to new epoch)
        epoch = epoch + 1;
    }
    // Print stats summary
    // stats.print_stats(cs_pq, cs_st);
}

/// Helper functions for specific hybrid combinations

/// ML-KEM 768 + Traditional (P-256 ECDSA)
pub fn hybrid_ml_kem768_traditional(client_num: u8, ratio: u8, epochs: i32) {
    hybrid_combiner_flex(
        client_num,
        ratio,
        epochs,
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256, // PQ KEM + traditional sig
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, // Traditional
    );
}

/// ML-KEM 768 + X25519 (Mixed security levels)
pub fn hybrid_ml_kem768_x25519(client_num: u8, ratio: u8, epochs: i32) {
    hybrid_combiner_flex(
        client_num,
        ratio,
        epochs,
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256, // PQ KEM + traditional sig
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, // Traditional
    );
}

/// Full PQ + Traditional comparison
pub fn hybrid_full_pq_traditional(client_num: u8, ratio: u8, epochs: i32) {
    hybrid_combiner_flex(
        client_num,
        ratio,
        epochs,
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, // Full PQ
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, // Traditional
    );
}

/// High security: ML-KEM 1024 + P-384
pub fn hybrid_ml_kem1024_p384(client_num: u8, ratio: u8, epochs: i32) {
    hybrid_combiner_flex(
        client_num,
        ratio,
        epochs,
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384, // ML-KEM 1024
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384, // P-384
    );
}

// *************************************************************************************************************
// *************************************************************************************************************
// *********************************************** STANDARD ONLY ***********************************************
// *************************************************************************************************************
// *************************************************************************************************************

pub fn solo(client_num: u8, cs: Ciphersuite) {
    solo_with_epochs(client_num, 500, cs);
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn solo_with_epochs(client_num: u8, epochs: i32, cs: Ciphersuite) {
    let stats = solo_with_epochs_with_stats(client_num, epochs, cs);
    // stats.print_stats(cs);
}

/// Solo with epochs that returns message size statistics
pub fn solo_with_epochs_with_stats (
    client_num: u8,
    epochs: i32, 
    cs: Ciphersuite,
) -> SoloMessageSizeStats {
    let mut stats = SoloMessageSizeStats::default();
    stats.epoch_count = epochs as usize;
    
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let epoch_total = epochs;

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create vector to store client credentials
    let mut clients: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the client list
    let owner: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs.signature_algorithm(), provider);
        clients.push(client);
    }

    // Generate KeyPackages
    let mut client_key_packages: Vec<KeyPackage> = Vec::new();

    for i in clients {
        let key_package = generate_key_package(cs, provider, &i.1, i.0);
        client_key_packages.push(key_package);
    }

    // Now Owner starts a new group ...
    let mut group = MlsGroup::new(
        provider,
        &owner.1,
        &MlsGroupCreateConfig::builder()
            .capabilities(Capabilities::new(None, Some(&[cs]), None, None, None))
            .ciphersuite(cs)
            .build(),
        owner.0,
    )
    .expect("An unexpected error occurred.");
    //
    //
    //
    // Initial Setup Complete
    //
    //
    //

    // Invite clients to group
    let (_mls_message_out, welcome_out, _group_info) = group
        .add_members(provider, &owner.1, &client_key_packages.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds Clients to the group.
    group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    stats.add_welcome(serialized_welcome.len());

    // The message is fanned out
    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups: Vec<MlsGroup> =
        welcome_message_fanout(&user_id_list, serialized_welcome, provider, &group);

    //
    //--------------------------------------------------------------------------
    // Group setup complete, current state is epoch 1, now to run followon epochs
    //---------------------------------------------------------------------------
    //

    let mut epoch = 1; //increments with each standard group epoch progression
    while epoch < epoch_total {
        // in each epoch, the group owner merges an empty commit to roll into the next epoch
        let queued_message = group
            .self_update(provider, &owner.1, LeafNodeParameters::default())
            .expect("error merging pending commit")
            .into_commit();

        let serialized_message = queued_message
            .tls_serialize_detached()
            .expect("Error serializing welcome");
        stats.add_commit(serialized_message.len());
                
        // Merge for owner
        group
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");

        message_fanout(&mut client_groups, serialized_message, provider);

        // Increment epoch once it has changed
        epoch = epoch + 1;
    }
    //println!("Final group state: {:?}", group);
    
    stats
}

pub fn solo_st(size: u8) {
    // Define ciphersuites ...
    let cs_st = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let client_num: u8 = size;
    let epoch_total: u32 = 500;

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create a vector to store client credentials
    let mut clients_st: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the group
    let owner_st: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_st.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client_st: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_st.signature_algorithm(), provider);
        clients_st.push(client_st);
    }

    // Generate KeyPackages
    let mut client_key_packages_st: Vec<KeyPackage> = Vec::new();

    for i in clients_st {
        let key_package_st = generate_key_package(cs_st, provider, &i.1, i.0);
        client_key_packages_st.push(key_package_st);
    }

    // This is where we begin collecting ********************

    // Now Owner starts a new group ...
    let mut group_st = MlsGroup::new(
        provider,
        &owner_st.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_st).build(),
        owner_st.0,
    )
    .expect("An unexpected error occurred.");

    // Invite clients to each group
    // message_out not used because message only gets sent to existing members, which is just the owner at this point
    // welcome_out is sent to all prospective group clients
    let (_mls_message_out, welcome_out, _group_info) = group_st
        .add_members(provider, &owner_st.1, &client_key_packages_st.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds clients.
    group_st
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // Here the message is fanned out, which is not simulated

    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups: Vec<MlsGroup> = Vec::new();

    // Now we handle the processing for each client
    for _i in &user_id_list {
        // Client will de-serialize the message
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_welcome.clone().as_slice())
                .expect("An unexpected error occurred.");

        // ... and inspect the message.
        let welcome = match mls_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            // We know it's a welcome message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        // Now Client can build a staged join for the group in order to inspect the welcome
        let client_staged_join = StagedWelcome::new_from_welcome(
            provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            // The public tree is needed and transferred out of band.
            // It is also possible to use the [`RatchetTreeExtension`]
            Some(group_st.export_ratchet_tree().into()),
        )
        .expect("Error creating a staged join from Welcome");

        // Finally, Client can create the group
        let client_group = client_staged_join
            .into_group(provider)
            .expect("Error creating the group from the staged join");

        assert!(group_st.members().eq(client_group.members()));

        assert_eq!(
            group_st.epoch_authenticator().as_slice(),
            client_group.epoch_authenticator().as_slice()
        );

        assert_eq!(
            group_st.export_ratchet_tree(),
            client_group.export_ratchet_tree()
        );

        client_groups.push(client_group);
    }

    //
    // Group setup complete, current state is epoch 1, now to run followon epochs
    //
    let mut epoch = 1;
    while epoch < epoch_total {
        //println!("epoch = {}", x);
        // in each epoch, the group owner merges an empty commit to roll into the next epoch
        let queued_message = group_st
            .self_update(provider, &owner_st.1, LeafNodeParameters::default())
            .expect("error merging pending commit")
            .to_welcome_msg()
            .expect("no new clients added in commit");

        group_st
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");

        let serialized_msg = queued_message
            .tls_serialize_detached()
            .expect("Error serializing update");

        for i in &mut client_groups {
            let msg_in = MlsMessageIn::tls_deserialize(&mut serialized_msg.clone().as_slice())
                .expect("An unexpected error occurred.");

            let public_msg = match msg_in.clone().extract() {
                MlsMessageBodyIn::PrivateMessage(public_msg) => public_msg,
                // We know it's a public message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            let processed_message = i
                .process_message(provider, public_msg)
                .expect("Error with processed message.");

            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                processed_message.into_content()
            {
                // Merge staged commit
                i.merge_staged_commit(provider, *staged_commit)
                    .expect("Error merging staged commit.");
            }
            assert_eq!(
                group_st.export_secret(provider.crypto(), "", &[], 32),
                i.export_secret(provider.crypto(), "", &[], 32)
            );

            // Make sure that both groups have the same public tree
            assert_eq!(group_st.export_ratchet_tree(), i.export_ratchet_tree());
        }

        // Increment epoch once it has changed
        epoch = epoch + 1;
    }
}

// *************************************************************************************************************
// *************************************************************************************************************
// ************************************************** PQ ONLY **************************************************
// *************************************************************************************************************
// *************************************************************************************************************

pub fn solo_pq(size: u8) {
    // Define ciphersuites ...
    let cs_pq = Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519;
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let client_num: u8 = size;
    let epoch_total: u32 = 500;

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create a vector to store client credentials
    let mut clients_pq: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the group
    let owner_pq: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_pq.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client_pq: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_pq.signature_algorithm(), provider);
        clients_pq.push(client_pq);
    }

    // Generate KeyPackages
    let mut client_key_packages_pq: Vec<KeyPackage> = Vec::new();

    for i in clients_pq {
        let key_package_pq = generate_key_package(cs_pq, provider, &i.1, i.0);
        client_key_packages_pq.push(key_package_pq);
    }

    // This is where we begin collecting ********************

    // Now Owner starts a new group ...
    let mut group_pq = MlsGroup::new(
        provider,
        &owner_pq.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_pq).build(),
        owner_pq.0,
    )
    .expect("An unexpected error occurred.");

    // Invite clients to each group
    // message_out not used because message only gets sent to existing members, which is just the owner at this point
    // welcome_out is sent to all prospective group clients
    let (_mls_message_out, welcome_out, _group_info) = group_pq
        .add_members(provider, &owner_pq.1, &client_key_packages_pq.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds clients.
    group_pq
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // Here the message is fanned out, which is not simulated

    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups: Vec<MlsGroup> = Vec::new();

    // Now we handle the processing for each client
    for _i in &user_id_list {
        // Client will de-serialize the message
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_welcome.clone().as_slice())
                .expect("An unexpected error occurred.");

        // ... and inspect the message.
        let welcome = match mls_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            // We know it's a welcome message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        // Now Client can build a staged join for the group in order to inspect the welcome
        let client_staged_join = StagedWelcome::new_from_welcome(
            provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            // The public tree is needed and transferred out of band.
            // It is also possible to use the [`RatchetTreeExtension`]
            Some(group_pq.export_ratchet_tree().into()),
        )
        .expect("Error creating a staged join from Welcome");

        // Finally, Client can create the group
        let client_group = client_staged_join
            .into_group(provider)
            .expect("Error creating the group from the staged join");

        assert!(group_pq.members().eq(client_group.members()));

        assert_eq!(
            group_pq.epoch_authenticator().as_slice(),
            client_group.epoch_authenticator().as_slice()
        );

        assert_eq!(
            group_pq.export_ratchet_tree(),
            client_group.export_ratchet_tree()
        );

        client_groups.push(client_group);
    }

    // Group setup complete, current state is epoch 1, now to run followon epochs
    let mut x = 1;
    while x < epoch_total {
        // in each epoch, the group owner merges an empty commit to roll into the next epoch
        let queued_message = group_pq
            .self_update(
                provider,
                &owner_pq.1,
                LeafNodeParameters::builder()
                    .with_capabilities(Capabilities::new(None, Some(&[cs_pq]), None, None, None))
                    .build(),
            )
            .unwrap()
            .into_commit();

        group_pq
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");

        let serialized_msg = queued_message
            .tls_serialize_detached()
            .expect("Error serializing update");

        let msg_in = MlsMessageIn::tls_deserialize(&mut serialized_msg.clone().as_slice())
            .expect("An unexpected error occurred.");

        for i in &mut client_groups {
            //println!("iteration = {:?}", i);
            let public_msg = match msg_in.clone().extract() {
                MlsMessageBodyIn::PrivateMessage(public_msg) => public_msg,
                // We know it's a public message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            let processed_message = i
                .process_message(provider, public_msg)
                .expect("Error with processed message.");

            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                processed_message.into_content()
            {
                // Merge staged commit
                i.merge_staged_commit(provider, *staged_commit)
                    .expect("Error merging staged commit.");
            }
            assert_eq!(
                group_pq.export_secret(provider.crypto(), "", &[], 32),
                i.export_secret(provider.crypto(), "", &[], 32)
            );

            // Make sure that both groups have the same public tree
            assert_eq!(group_pq.export_ratchet_tree(), i.export_ratchet_tree());
        }
        x = x + 1;
    }
}
// ***************************************************************
// ***************************************************************
// ************************** PQ-Conf-Only ***********************
// ***************************************************************
// ***************************************************************

pub fn solo_pq_conf(size: u8, epochs: i32, cs_pq: Ciphersuite) {
    // ... and the crypto provider to use.
    let provider = &OpenMlsRustCrypto::default();

    // Definition for scaling
    let client_num: u8 = size;
    let epoch_total: i32 = epochs; //changed from 500

    // Using random strings for unique client IDs
    let user_id_list = generate_unique_random_strings((client_num - 1).into(), 10);

    // Create a vector to store client credentials
    let mut clients_pq: Vec<(CredentialWithKey, SignatureKeyPair)> = Vec::new();

    // Owner is the first member of the group
    let owner_pq: (CredentialWithKey, SignatureKeyPair) =
        generate_credential_with_key("Owner".into(), cs_pq.signature_algorithm(), provider);

    // Each client gets a credential
    for i in &user_id_list {
        let client_pq: (CredentialWithKey, SignatureKeyPair) =
            generate_credential_with_key(i.clone().into(), cs_pq.signature_algorithm(), provider);
        clients_pq.push(client_pq);
    }

    // Generate KeyPackages
    let mut client_key_packages_pq: Vec<KeyPackage> = Vec::new();

    for i in clients_pq {
        let key_package_pq = generate_key_package(cs_pq, provider, &i.1, i.0);
        client_key_packages_pq.push(key_package_pq);
    }

    // This is where we begin collecting ********************

    // Now Owner starts a new group ...
    let mut group_pq = MlsGroup::new(
        provider,
        &owner_pq.1,
        &MlsGroupCreateConfig::builder().ciphersuite(cs_pq).build(),
        owner_pq.0,
    )
    .expect("An unexpected error occurred.");

    // Invite clients to each group
    // message_out not used because message only gets sent to existing members, which is just the owner at this point
    // welcome_out is sent to all prospective group clients
    let (_mls_message_out, welcome_out, _group_info) = group_pq
        .add_members(provider, &owner_pq.1, &client_key_packages_pq.clone())
        .expect("Could not add members.");

    // Owner merges the pending commit that adds clients.
    group_pq
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    // Owner serializes the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    // Here the message is fanned out, which is not simulated

    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups: Vec<MlsGroup> = Vec::new();

    // Now we handle the processing for each client
    for _i in &user_id_list {
        // Client will de-serialize the message
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_welcome.clone().as_slice())
                .expect("An unexpected error occurred.");

        // ... and inspect the message.
        let welcome = match mls_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            // We know it's a welcome message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        // Now Client can build a staged join for the group in order to inspect the welcome
        let client_staged_join = StagedWelcome::new_from_welcome(
            provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            // The public tree is needed and transferred out of band.
            // It is also possible to use the [`RatchetTreeExtension`]
            Some(group_pq.export_ratchet_tree().into()),
        )
        .expect("Error creating a staged join from Welcome");

        // Finally, Client can create the group
        let client_group = client_staged_join
            .into_group(provider)
            .expect("Error creating the group from the staged join");

        assert!(group_pq.members().eq(client_group.members()));

        assert_eq!(
            group_pq.epoch_authenticator().as_slice(),
            client_group.epoch_authenticator().as_slice()
        );

        assert_eq!(
            group_pq.export_ratchet_tree(),
            client_group.export_ratchet_tree()
        );

        client_groups.push(client_group);
    }

    // Group setup complete, current state is epoch 1, now to run followon epochs
    let mut x = 1;
    while x < epoch_total {
        // in each epoch, the group owner merges an empty commit to roll into the next epoch
        let queued_message = group_pq
            .self_update(
                provider,
                &owner_pq.1,
                LeafNodeParameters::builder()
                    .with_capabilities(Capabilities::new(None, Some(&[cs_pq]), None, None, None))
                    .build(),
            )
            .unwrap()
            .into_commit();

        group_pq
            .merge_pending_commit(provider)
            .expect("Error for owner merging pending commit.");

        let serialized_msg = queued_message
            .tls_serialize_detached()
            .expect("Error serializing update");

        let msg_in = MlsMessageIn::tls_deserialize(&mut serialized_msg.clone().as_slice())
            .expect("An unexpected error occurred.");

        for i in &mut client_groups {
            //println!("iteration = {:?}", i);
            let public_msg = match msg_in.clone().extract() {
                MlsMessageBodyIn::PrivateMessage(public_msg) => public_msg,
                // We know it's a public message, so we ignore all other cases.
                _ => unreachable!("Unexpected message type."),
            };

            let processed_message = i
                .process_message(provider, public_msg)
                .expect("Error with processed message.");

            if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                processed_message.into_content()
            {
                // Merge staged commit
                i.merge_staged_commit(provider, *staged_commit)
                    .expect("Error merging staged commit.");
            }
            assert_eq!(
                group_pq.export_secret(provider.crypto(), "", &[], 32),
                i.export_secret(provider.crypto(), "", &[], 32)
            );

            // Make sure that both groups have the same public tree
            assert_eq!(group_pq.export_ratchet_tree(), i.export_ratchet_tree());
        }
        x = x + 1;
    }
}

// *************************************************************************************************************
// *************************************************************************************************************
// ************************************************** HELPERS **************************************************
// *************************************************************************************************************
// *************************************************************************************************************

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    //credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm).expect("Error generating a signature key pair.");

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// A helper to create key package bundles.
fn generate_key_package(
    cs: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackage {
    // Create the key package
    KeyPackage::builder()
        .build(cs, provider, signer, credential_with_key)
        .unwrap()
        .key_package()
        .clone()
}

// A helper to create random strings for the client names
fn generate_random_string(length: usize) -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789";
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

// A helper to create a vector of random unique strings for the client generator
fn generate_unique_random_strings(count: usize, length: usize) -> Vec<String> {
    let mut unique_strings = HashSet::new();

    while unique_strings.len() < count {
        let new_string = generate_random_string(length);
        unique_strings.insert(new_string);
    }

    unique_strings.into_iter().collect()
}

fn message_fanout(
    client_groups: &mut Vec<MlsGroup>,
    serialized_message: Vec<u8>,
    provider: &OpenMlsRustCrypto, /* group: &MlsGroup */
) {
    //println!("\nin message_fanout\n");
    for i in client_groups.iter_mut() {
        // Simulate deserializing the message
        let msg_in = MlsMessageIn::tls_deserialize(&mut serialized_message.clone().as_slice())
            .expect("An unexpected error occurred.");

        // Handle the message
        let mls_msg = match msg_in.clone().extract() {
            MlsMessageBodyIn::PrivateMessage(mls_msg) => mls_msg,
            // We know it's a private message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        //println!("\n\nmessage fanout pre-process {:?}", i);

        let processed_message = i
            .process_message(provider, mls_msg)
            .expect("Error with processed message.");

        match processed_message.into_content() {
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                // Store the proposal
                i.store_pending_proposal(provider.storage(), *queued_proposal);
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // Merge the staged commit
                i.merge_staged_commit(provider, *staged_commit)
                    .expect("Error merging staged commit.");
            }
            _ => unreachable!(),
        }
        //println!("\n\nmessage fanout post-process {:?}", i);
        //println!("\n\nmessage fanout owner group {:?}", group);
        /* assert_eq!(
            group.export_secret(provider.crypto(), "", &[], 32),
            i.export_secret(provider.crypto(), "", &[], 32)
        ); */

        // Make sure that both groups have the same public tree
        /* assert_eq!(
            group.export_ratchet_tree(),
            i.export_ratchet_tree()
        ); */
    }
}

fn welcome_message_fanout(
    client_ids: &Vec<String>,
    serialized_message: Vec<u8>,
    provider: &OpenMlsRustCrypto,
    group: &MlsGroup,
) -> Vec<MlsGroup> {
    // Create a vector to hold each client's copy of the group, something that is only necessary for simulation
    let mut client_groups: Vec<MlsGroup> = Vec::new();

    // Iterate over each mutable reference to an MlsGroup in the vector
    for _i in client_ids.iter() {
        // Simulate deserializing the message
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut serialized_message.clone().as_slice())
                .expect("An unexpected error occurred.");

        // ... and inspect the message.
        let welcome = match mls_message_in.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            // We know it's a welcome message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        // Now Client can build a staged join for the group in order to inspect the welcome
        let client_staged_join = StagedWelcome::new_from_welcome(
            provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            // The public tree is needed and transferred out of band.
            // It is also possible to use the [`RatchetTreeExtension`]
            Some(group.export_ratchet_tree().into()),
        )
        .expect("Error creating a staged join from Welcome");

        // Finally, Client can create the group
        let new_client = client_staged_join
            .into_group(provider)
            .expect("Error creating the group from the staged join");

        //assert!(group_st.members().eq(client_group_st.members()));

        /* assert_eq!(
            group_st.epoch_authenticator().as_slice(),
            client_group_st.epoch_authenticator().as_slice()
        ); */

        /* assert_eq!(
            group_st.export_ratchet_tree(),
            client_group_st.export_ratchet_tree()
        ); */

        client_groups.push(new_client);
    }
    return client_groups;
}

#[cfg(test)]
mod provider_mldsa_tests {
    use openmls::prelude::SignatureScheme;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto};

    fn roundtrip(scheme: SignatureScheme) {
        let provider = OpenMlsRustCrypto::default();
        let msg = b"ml-dsa provider test";

        let (sk, pk) = provider
            .crypto()
            .signature_key_gen(scheme)
            .expect("keygen failed");

        let sig = provider
            .crypto()
            .sign(scheme, msg, &sk)
            .expect("sign failed");

        provider
            .crypto()
            .verify_signature(scheme, msg, &pk, &sig)
            .expect("verify failed");
    }

    #[test]
    fn mldsa_roundtrip_all() {
        for scheme in [
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            roundtrip(scheme);
        }
    }

    #[test]
    fn mldsa_negative_tamper() {
        let provider = OpenMlsRustCrypto::default();
        let scheme = SignatureScheme::MLDSA44;

        let (sk, pk) = provider.crypto().signature_key_gen(scheme).expect("keygen");
        let msg = b"message";
        let sig = provider.crypto().sign(scheme, msg, &sk).expect("sign");

        // Tamper message
        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 1;
        assert!(
            provider
                .crypto()
                .verify_signature(scheme, &bad_msg, &pk, &sig)
                .is_err()
        );

        // Tamper signature
        let mut sig_bad = sig.clone();
        if let Some(last) = sig_bad.last_mut() {
            *last ^= 1;
        }
        assert!(
            provider
                .crypto()
                .verify_signature(scheme, msg, &pk, &sig_bad)
                .is_err()
        );
    }

    #[test]
    fn mldsa_cross_scheme_fails() {
        let provider = OpenMlsRustCrypto::default();
        let (sk44, pk44) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::MLDSA44)
            .expect("keygen");
        let msg = b"msg";
        let sig44 = provider
            .crypto()
            .sign(SignatureScheme::MLDSA44, msg, &sk44)
            .expect("sign");

        // Verify with a different parameter set must fail
        assert!(
            provider
                .crypto()
                .verify_signature(SignatureScheme::MLDSA65, msg, &pk44, &sig44)
                .is_err()
        );
    }
}
