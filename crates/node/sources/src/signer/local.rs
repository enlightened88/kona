use alloy_primitives::{Address, ChainId};
use alloy_signer::{Signature, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use derive_more::From;
use op_alloy_rpc_types_engine::PayloadHash;

use crate::BlockSigner;

/// Local signer using a private key stored in memory
#[derive(Debug, Clone, From)]
pub struct LocalSigner(#[from] alloy_signer_local::PrivateKeySigner);

impl LocalSigner {
    /// Creates a new local signer from a private key.
    pub fn new(private_key: PrivateKeySigner) -> Self {
        Self(PrivateKeySigner::from(private_key))
    }

    /// Signs a payload with the private key synchronously.
    pub fn sign_block_sync(
        &self,
        payload_hash: PayloadHash,
        chain_id: ChainId,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        // Signs the payload hash with the private key.
        let signature = self.0.sign_hash_sync(&payload_hash.signature_message(chain_id))?;
        Ok(signature)
    }
}

#[async_trait]
impl BlockSigner for LocalSigner {
    /// Signs a payload with the given signer and chain id.
    ///
    /// Spec: <https://specs.optimism.io/protocol/rollup-node-p2p.html#block-signatures>
    async fn sign_block(
        &self,
        payload_hash: PayloadHash,
        chain_id: ChainId,
        _sender_address: Address,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        Ok(self.sign_block_sync(payload_hash, chain_id)?)
    }
}
