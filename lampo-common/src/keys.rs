use std::{sync::Arc, time::SystemTime};

use bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::ldk::sign::{InMemorySigner, NodeSigner, OutputSpender, SignerProvider};
use crate::ldk::sign::{EntropySource, KeysManager};
use crate::ldk::sign::Recipient;
#[cfg(feature = "rgb")]
pub use {
    crate::conf::LampoConf,
    std::{path::PathBuf, str::FromStr},
};

/// Lampo keys implementations
pub struct LampoKeys {
    pub keys_manager: Arc<LampoKeysManager>,
}

impl LampoKeys {

    #[cfg(feature = "vanilla")]
    pub fn new(seed: [u8; 32]) -> Self {
        // Fill in random_32_bytes with secure random data, or, on restart, reload the seed from disk.
        let start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        LampoKeys {
            keys_manager: Arc::new(LampoKeysManager::new(
                &seed,
                start_time.as_secs(),
                start_time.subsec_nanos(),
            )),
        }
    }

    // We need a different function definition for this function as the previous version of `lightning`
    // keysmanager takes also the path_dir as an argument.
    #[cfg(feature = "rgb")]
    pub fn new(seed: [u8; 32], conf: Arc<LampoConf>) -> Self {
        let start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        LampoKeys {
            keys_manager: Arc::new(LampoKeysManager::new(
                &seed,
                start_time.as_secs(),
                start_time.subsec_nanos(),
                conf,
            )),
        }
    }
    
    #[cfg(feature = "vanilla")]
    #[cfg(debug_assertions)]
    pub fn with_channel_keys(seed: [u8; 32], channels_keys: String) -> Self {
        // Fill in random_32_bytes with secure random data, or, on restart, reload the seed from disk.
        let start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let keys = channels_keys.split('/').collect::<Vec<_>>();

        let mut manager =
            LampoKeysManager::new(&seed, start_time.as_secs(), start_time.subsec_nanos());
        manager.set_channels_keys(
            keys[1].to_string(),
            keys[2].to_string(),
            keys[3].to_string(),
            keys[4].to_string(),
            keys[5].to_string(),
            keys[6].to_string(),
        );
        LampoKeys {
            keys_manager: Arc::new(manager),
        }
    }

    pub fn inner(&self) -> Arc<LampoKeysManager> {
        self.keys_manager.clone()
    }
}

pub struct LampoKeysManager {
    pub(crate) inner: KeysManager,

    funding_key: Option<SecretKey>,
    revocation_base_secret: Option<SecretKey>,
    payment_base_secret: Option<SecretKey>,
    delayed_payment_base_secret: Option<SecretKey>,
    htlc_base_secret: Option<SecretKey>,
    shachain_seed: Option<[u8; 32]>,
}

impl LampoKeysManager {
    #[cfg(feature = "vanilla")]
    pub fn new(seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32) -> Self {
        let inner = KeysManager::new(seed, starting_time_secs, starting_time_nanos);
        Self {
            inner,
            funding_key: None,
            revocation_base_secret: None,
            payment_base_secret: None,
            delayed_payment_base_secret: None,
            htlc_base_secret: None,
            shachain_seed: None,
        }
    }

    #[cfg(feature = "rgb")]
    pub fn new(seed: &[u8; 32], starting_time_secs: u64, starting_time_nanos: u32, conf: Arc<LampoConf>) -> Self {
        let path = format!("{}/{}/rgb/", conf.root_path, conf.network.to_string());
        let inner = KeysManager::new(seed, starting_time_secs, starting_time_nanos, PathBuf::from_str(path.as_str()).unwrap());
        Self {
            inner,
            funding_key: None,
            revocation_base_secret: None,
            payment_base_secret: None,
            delayed_payment_base_secret: None,
            htlc_base_secret: None,
            shachain_seed: None,
        }
    }

    // FIXME: put this under a debug a feature flag like `unsafe_channel_keys`
    #[cfg(debug_assertions)]
    pub fn set_channels_keys(
        &mut self,
        funding_key: String,
        revocation_base_secret: String,
        payment_base_secret: String,
        delayed_payment_base_secret: String,
        htlc_base_secret: String,
        _shachain_seed: String,
    ) {
        use std::str::FromStr;

        self.funding_key = Some(SecretKey::from_str(&funding_key).unwrap());
        self.revocation_base_secret = Some(SecretKey::from_str(&revocation_base_secret).unwrap());
        self.payment_base_secret = Some(SecretKey::from_str(&payment_base_secret).unwrap());
        self.delayed_payment_base_secret =
            Some(SecretKey::from_str(&delayed_payment_base_secret).unwrap());
        self.htlc_base_secret = Some(SecretKey::from_str(&htlc_base_secret).unwrap());
        self.shachain_seed = Some(self.inner.get_secure_random_bytes())
    }
}

impl EntropySource for LampoKeysManager {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }
}

impl NodeSigner for LampoKeysManager {
    fn ecdh(
        &self,
        recipient: crate::ldk::sign::Recipient,
        other_key: &bitcoin::secp256k1::PublicKey,
        tweak: Option<&bitcoin::secp256k1::Scalar>,
    ) -> Result<bitcoin::secp256k1::ecdh::SharedSecret, ()> {
        self.inner.ecdh(recipient, other_key, tweak)
    }

    fn get_inbound_payment_key_material(&self) -> crate::ldk::sign::KeyMaterial {
        self.inner.get_inbound_payment_key_material()
    }

    fn get_node_id(
        &self,
        recipient: crate::ldk::sign::Recipient,
    ) -> Result<bitcoin::secp256k1::PublicKey, ()> {
        self.inner.get_node_id(recipient)
    }

    fn sign_bolt12_invoice(
        &self,
        invoice: &crate::ldk::offers::invoice::UnsignedBolt12Invoice,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_bolt12_invoice(invoice)
    }

    fn sign_bolt12_invoice_request(
        &self,
        invoice_request: &crate::ldk::offers::invoice_request::UnsignedInvoiceRequest,
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, ()> {
        self.inner.sign_bolt12_invoice_request(invoice_request)
    }

    fn sign_gossip_message(
        &self,
        msg: crate::ldk::ln::msgs::UnsignedGossipMessage,
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
        self.inner.sign_gossip_message(msg)
    }

    fn sign_invoice(
        &self,
        hrp_bytes: &[u8],
        invoice_data: &[bitcoin::bech32::u5],
        recipient: crate::ldk::sign::Recipient,
    ) -> Result<bitcoin::secp256k1::ecdsa::RecoverableSignature, ()> {
        self.inner.sign_invoice(hrp_bytes, invoice_data, recipient)
    }
}

impl OutputSpender for LampoKeysManager {
    fn spend_spendable_outputs<C: bitcoin::secp256k1::Signing>(
        &self,
        descriptors: &[&crate::ldk::sign::SpendableOutputDescriptor],
        outputs: Vec<bitcoin::TxOut>,
        change_destination_script: bitcoin::ScriptBuf,
        feerate_sat_per_1000_weight: u32,
        locktime: Option<bitcoin::absolute::LockTime>,
        secp_ctx: &bitcoin::secp256k1::Secp256k1<C>,
    ) -> Result<bitcoin::Transaction, ()> {
        self.inner.spend_spendable_outputs(
            descriptors,
            outputs,
            change_destination_script,
            feerate_sat_per_1000_weight,
            locktime,
            secp_ctx,
        )
    }
}

impl SignerProvider for LampoKeysManager {
    // FIXME: this should be the same of the inner
    type EcdsaSigner = InMemorySigner;

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        // TODO: What needs to be done here? InMemorySigner requires a data directory 
        // which we can get from lampoconf, but how do we do this as we can't change 
        // the function definition.
        #[cfg(feature = "Vanilla")]
        if self.funding_key.is_some() {
            // FIXME(vincenzopalazzo): make this a general
            let commitment_seed = [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ];
            return InMemorySigner::new(
                &Secp256k1::new(),
                self.funding_key.unwrap(),
                self.revocation_base_secret.unwrap(),
                self.payment_base_secret.unwrap(),
                self.delayed_payment_base_secret.unwrap(),
                self.htlc_base_secret.unwrap(),
                commitment_seed,
                channel_value_satoshis,
                channel_keys_id,
                self.shachain_seed.unwrap(),
            );
        }
        self.inner
            .derive_channel_signer(channel_value_satoshis, channel_keys_id)
    }

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        self.inner
            .generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<bitcoin::ScriptBuf, ()> {
        self.inner.get_destination_script(channel_keys_id)
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<crate::ldk::ln::script::ShutdownScript, ()> {
        self.inner.get_shutdown_scriptpubkey()
    }

    fn read_chan_signer(
        &self,
        reader: &[u8],
    ) -> Result<Self::EcdsaSigner, crate::ldk::ln::msgs::DecodeError> {
        self.inner.read_chan_signer(reader)
    }
}
