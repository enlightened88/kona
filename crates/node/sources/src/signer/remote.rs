use std::io::BufReader;

use async_trait::async_trait;

use alloy_primitives::{Address, B256, ChainId, Signature, SignatureError};
use alloy_rpc_client::{ClientBuilder, RpcClient};
use alloy_transport_http::Http;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use op_alloy_rpc_types_engine::PayloadHash;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    mpsc::{self, Receiver},
};
use thiserror::Error;
use tokio::{sync::RwLock, task};
use url::Url;

use crate::BlockSigner;

/// Client certificate and key pair for mTLS authentication (PEM format)
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// Path to the client certificate in PEM format
    pub cert: std::path::PathBuf,
    /// Path to the client private key in PEM format
    pub key: std::path::PathBuf,
}

/// Configuration for the remote signer client
///
/// This configuration supports various TLS/certificate scenarios:
///
/// 1. **Basic HTTPS**: Only `endpoint` and `address` are required. Uses system CA certificates.
/// 2. **Custom CA**: Provide `ca_cert` to verify servers with custom/self-signed certificates.
/// 3. **Mutual TLS (mTLS)**: Provide both `client_cert` and `client_key` for client authentication.
/// 4. **Full mTLS with custom CA**: Combine all certificate options for maximum security.
///
/// Certificate formats supported:
/// - PEM format for all certificates and keys
/// - Certificates should be provided as file paths.
///
/// By default, the process will watch for changes in the client certificate files and reload the
/// client automatically.
#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    /// The URL of the remote signer endpoint
    pub endpoint: Url,
    /// Optional client certificate for mTLS (PEM format)
    pub client_cert: Option<ClientCert>,
    /// Optional CA certificate for server verification (PEM format)
    pub ca_cert: Option<std::path::PathBuf>,
    /// Request timeout in seconds
    pub timeout_secs: Option<u64>,
}

/// Errors that can occur when handling certificates
#[derive(Debug, Error)]
pub enum CertificateError {
    /// Invalid CA certificate path
    #[error("Invalid CA certificate path: {0}")]
    InvalidCACertificatePath(std::io::Error),
    /// Invalid certificate error
    #[error("Invalid CA certificate: {0}")]
    InvalidCACertificate(std::io::Error),
    /// Failed to add CA certificate
    #[error("Failed to add CA certificate: {0}")]
    AddCACertificate(rustls::Error),
    /// Failed to configure client auth
    #[error("Failed to configure client auth: {0}")]
    ConfigureClientAuth(rustls::Error),
    /// Invalid client certificate path
    #[error("Invalid client certificate path: {0}")]
    InvalidClientCertificatePath(std::io::Error),
    /// Invalid client certificate
    #[error("Invalid client certificate: {0}")]
    InvalidClientCertificate(std::io::Error),
    /// Invalid private key path
    #[error("Invalid private key path: {0}")]
    InvalidPrivateKeyPath(std::io::Error),
    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(std::io::Error),
    /// No private key found while parsing the client certificate
    #[error("No private key found while parsing the client certificate")]
    NoPrivateKey,
}

/// Errors that can occur when using the remote signer
#[derive(Debug, Error)]
pub enum RemoteSignerError {
    /// JSON-RPC transport error
    #[error("JSON-RPC transport error: {0}")]
    SigningRPCError(#[from] alloy_transport::TransportError),
    /// JSON serialization error
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// HTTP client build error
    #[error("HTTP client build error: {0}")]
    BuildError(#[from] reqwest::Error),
    /// Failed to ping signer
    #[error("Failed to ping signer: {0}")]
    PingError(alloy_transport::TransportError),
    /// Invalid certificate error
    #[error("Invalid certificate: {0}")]
    CertificateError(#[from] CertificateError),
    /// Certificate watcher error
    #[error("Certificate watcher error: {0}")]
    CertificateWatcherError(#[from] notify::Error),
    /// Invalid signature hex encoding
    #[error("Invalid signature hex encoding: {0}")]
    InvalidSignatureHex(hex::FromHexError),
    /// Invalid signature length
    #[error("Invalid signature length, expected 65 bytes, got {0}")]
    InvalidSignatureLength(usize),
    /// Signature error
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
}

/// Request parameters for signing a block payload
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlockPayloadArgs {
    domain: B256,
    chain_id: u64,
    payload_hash: B256,
    sender_address: Address,
}

/// Response from the remote signer
#[derive(Debug, Deserialize)]
struct SignResponse {
    signature: String,
}

/// Remote signer that communicates with an external signing service via JSON-RPC
pub struct RemoteSigner {
    client: Arc<RwLock<RpcClient>>,
    config: RemoteSignerConfig,
    watcher_handle: Option<task::JoinHandle<()>>,
}

impl std::fmt::Debug for RemoteSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("config", &self.config)
            .field("has_watcher", &self.watcher_handle.is_some())
            .finish_non_exhaustive()
    }
}

impl RemoteSigner {
    /// Creates a new remote signer with the given configuration
    ///
    /// If client certificates are configured, this will automatically start a certificate watcher
    /// that monitors the certificate files for changes. When certificates are updated (e.g., by
    /// cert-manager in Kubernetes), the TLS client will be automatically reloaded with the new
    /// certificates without requiring a restart.
    ///
    /// # Certificate Watching
    ///
    /// The certificate watcher monitors:
    /// - Client certificate file (if mTLS is configured)
    /// - Client private key file (if mTLS is configured)
    /// - CA certificate file (if custom CA is configured)
    ///
    /// When any of these files are modified, the watcher will:
    /// 1. Log the certificate change event
    /// 2. Reload the certificate files from disk
    /// 3. Rebuild the HTTP client with the new TLS configuration
    /// 4. Replace the existing client atomically
    ///
    /// This enables zero-downtime certificate rotation in production environments.
    pub async fn new(config: RemoteSignerConfig) -> Result<Self, RemoteSignerError> {
        let http_client = Self::build_http_client(config.clone())?;
        let transport = Http::with_client(http_client, config.endpoint.clone());
        let client = ClientBuilder::default().transport(transport, true);

        // Try to ping the signer to check if it's reachable
        let version: String =
            client.request("health_status", ()).await.map_err(RemoteSignerError::PingError)?;

        tracing::info!(target: "signer", version, "Connected to op-signer server");

        let client = Arc::new(RwLock::new(client));

        // Start certificate watcher if client certificates are configured
        let watcher_handle =
            Self::start_certificate_watcher(client.clone(), config.clone()).await?;

        Ok(Self { client, config, watcher_handle })
    }

    /// Starts a certificate watcher that monitors client certificate files and reloads the client
    /// automatically when they are updated.
    ///
    /// Returns `Ok(None)` if no client certificates are configured.
    async fn start_certificate_watcher(
        client: Arc<RwLock<RpcClient>>,
        config: RemoteSignerConfig,
    ) -> Result<Option<task::JoinHandle<()>>, RemoteSignerError> {
        let Some(ref client_cert) = config.client_cert else {
            return Ok(None);
        };

        let (tx, rx) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                // Ignore errors from the watcher channel
                let _ = tx.send(res).map_err(|e| {
                    tracing::error!(target: "signer:certificate-watcher-sender", error = %e, "Failed to send event to watcher channel.");
                    e
                });
            },
            Config::default(),
        )?;

        tracing::info!(target: "signer", "Starting certificate watcher for automatic TLS reload");

        watcher.watch(&client_cert.cert, RecursiveMode::NonRecursive)?;
        watcher.watch(&client_cert.key, RecursiveMode::NonRecursive)?;

        Ok(Some(task::spawn(Self::certificate_watcher_task(client, config, rx))))
    }

    async fn certificate_watcher_task(
        client: Arc<RwLock<RpcClient>>,
        config: RemoteSignerConfig,
        rx: Receiver<Result<Event, notify::Error>>,
    ) {
        while let Ok(event) = rx.recv() {
            match event {
                Ok(Event { kind: EventKind::Modify(_), .. }) => {
                    tracing::debug!(
                        target: "signer:certificate-watcher",
                        "Certificate file changed, reloading TLS configuration"
                    );

                    match Self::build_http_client(config.clone()) {
                        Ok(new_client) => {
                            let transport = Http::with_client(new_client, config.endpoint.clone());
                            let new_client = ClientBuilder::default().transport(transport, false);

                            let mut client_guard = client.write().await;
                            *client_guard = new_client;
                            tracing::info!(target: "signer:certificate-watcher", "TLS configuration reloaded successfully");
                        }
                        Err(e) => {
                            tracing::error!(target: "signer:certificate-watcher", error = %e, "Failed to reload TLS configuration");
                        }
                    }
                }
                Ok(event) => {
                    tracing::trace!(target: "signer:certificate-watcher", event = ?event, "Ignoring non-modify event.");
                }
                Err(e) => {
                    tracing::error!(target: "signer:certificate-watcher", error = %e, "Failed to receive event from watcher channel.");
                }
            }
        }
    }

    /// Returns true if certificate watching is enabled
    pub const fn is_certificate_watching_enabled(&self) -> bool {
        self.watcher_handle.is_some()
    }

    /// Builds an HTTP client with certificate handling
    fn build_http_client(config: RemoteSignerConfig) -> Result<reqwest::Client, RemoteSignerError> {
        let mut client_builder = reqwest::Client::builder();

        // Set timeout if specified
        if let Some(timeout_secs) = config.timeout_secs {
            client_builder = client_builder.timeout(std::time::Duration::from_secs(timeout_secs));
        }

        // Configure TLS if certificates are provided
        if config.client_cert.is_some() || config.ca_cert.is_some() {
            let tls_config = Self::build_tls_config(config)?;
            client_builder = client_builder.use_preconfigured_tls(tls_config);
        }

        client_builder.build().map_err(RemoteSignerError::BuildError)
    }

    /// Builds TLS configuration with certificate handling
    fn build_tls_config(config: RemoteSignerConfig) -> Result<ClientConfig, RemoteSignerError> {
        let mut root_store = RootCertStore::empty();

        // Add custom CA certificate if provided
        if let Some(ca_cert_path) = config.ca_cert {
            let ca_cert_file = std::fs::File::open(ca_cert_path)
                .map_err(CertificateError::InvalidCACertificatePath)?;
            let mut ca_cert_reader = BufReader::new(ca_cert_file);
            let ca_cert = rustls_pemfile::certs(&mut ca_cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(CertificateError::InvalidCACertificate)?;

            for cert in ca_cert {
                root_store.add(cert).map_err(CertificateError::AddCACertificate)?;
            }
        }

        let tls_config = ClientConfig::builder().with_root_certificates(root_store);

        // Configure client certificates for mTLS if provided
        match config.client_cert {
            None => Ok(tls_config.with_no_client_auth()),
            Some(ClientCert { cert, key }) => {
                let cert_file = std::fs::File::open(cert)
                    .map_err(CertificateError::InvalidClientCertificatePath)?;
                let mut cert_reader = BufReader::new(cert_file);
                let certs = rustls_pemfile::certs(&mut cert_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(CertificateError::InvalidClientCertificate)?;

                let key_file =
                    std::fs::File::open(key).map_err(CertificateError::InvalidPrivateKeyPath)?;
                let mut key_reader = BufReader::new(key_file);
                let key = rustls_pemfile::private_key(&mut key_reader)
                    .map_err(CertificateError::InvalidPrivateKey)?
                    .ok_or_else(|| CertificateError::NoPrivateKey)?;

                Ok(tls_config
                    .with_client_auth_cert(certs, key)
                    .map_err(CertificateError::ConfigureClientAuth)?)
            }
        }
    }

    /// Signs a block payload hash using the remote signer via JSON-RPC
    pub async fn sign_block_v1(
        &self,
        payload_hash: PayloadHash,
        chain_id: ChainId,
        sender_address: Address,
    ) -> Result<Signature, RemoteSignerError> {
        let params = BlockPayloadArgs {
            // For v1 payloads, the domain is always zero
            domain: B256::ZERO,
            chain_id,
            payload_hash: payload_hash.0,
            sender_address,
        };

        // Make JSON-RPC call to the custom method
        let response: SignResponse = {
            self.client
                .read()
                .await
                .request("opsigner_signBlockPayload", &params)
                .await
                .map_err(RemoteSignerError::SigningRPCError)?
        };

        // Parse the hex signature
        let signature_bytes = hex::decode(response.signature.trim_start_matches("0x"))
            .map_err(RemoteSignerError::InvalidSignatureHex)?;

        if signature_bytes.len() != 65 {
            return Err(RemoteSignerError::InvalidSignatureLength(signature_bytes.len()));
        }

        let signature = Signature::from_raw(signature_bytes.as_slice())
            .map_err(RemoteSignerError::SignatureError)?;

        Ok(signature)
    }
}

#[async_trait]
impl BlockSigner for RemoteSigner {
    async fn sign_block(
        &self,
        payload_hash: PayloadHash,
        chain_id: ChainId,
        sender_address: Address,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        self.sign_block_v1(payload_hash, chain_id, sender_address)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
