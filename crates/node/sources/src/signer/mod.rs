//! Signer utilities for the Kona node.
//!
//! We currently support two types of block signers:
//!
//! 1. A local block signer that is used to sign blocks with a locally available private key.
//! 2. A remote block signer that is used to sign blocks with a remote private key.

use alloy_primitives::{Address, ChainId};
use alloy_signer::Signature;
use async_trait::async_trait;
use op_alloy_rpc_types_engine::PayloadHash;
use std::fmt::Debug;

/// A trait that should be implemented by all block signers.
#[async_trait]
pub trait BlockSigner: Debug {
    /// Signs a payload with the signer.
    async fn sign_block(
        &self,
        payload_hash: PayloadHash,
        chain_id: ChainId,
        sender_address: Address,
    ) -> Result<Signature, Box<dyn std::error::Error>>;
}

mod local;
pub use local::LocalSigner;

mod remote;
pub use remote::{
    CertificateError, ClientCert, RemoteSigner, RemoteSignerConfig, RemoteSignerError,
};
