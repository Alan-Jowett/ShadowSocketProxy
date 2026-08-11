// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Shared rustls identity loading and pinned mutual-TLS verification.

use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};

use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ParsedCertificate, WebPkiClientVerifier,
    },
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors raised while loading or constructing certificate-pinned TLS state.
#[derive(Debug, Error)]
pub enum RustlsConfigError {
    #[error("read TLS certificate file: {0}")]
    /// The certificate PEM file could not be read.
    CertificateIo(#[source] io::Error),
    #[error("parse TLS certificate PEM: {0}")]
    /// The certificate PEM file contains invalid data.
    CertificatePem(#[source] io::Error),
    #[error("TLS certificate file contains no certificates")]
    /// At least one certificate is required.
    MissingCertificate,
    #[error("read TLS private key file: {0}")]
    /// The private-key PEM file could not be read.
    KeyIo(#[source] io::Error),
    #[error("parse TLS private key PEM: {0}")]
    /// The private-key PEM file contains invalid data.
    KeyPem(#[source] io::Error),
    #[error("TLS private key file contains no supported private key")]
    /// A supported PKCS#1, SEC1, or PKCS#8 key is required.
    MissingPrivateKey,
    #[error("invalid TLS peer certificate SHA-256 pin: expected 64 hexadecimal digits")]
    /// The peer pin is not a normalized 32-byte hexadecimal digest.
    InvalidPeerPin,
    #[error("TLS configuration rejected: {0}")]
    /// Rustls rejected the certificate or key configuration.
    Rustls(String),
}

/// A loaded PEM certificate chain and private key.
#[derive(Debug)]
pub struct RustlsIdentity {
    /// Certificates sent to the peer, with the first certificate as the leaf.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Private key matching the first certificate.
    pub private_key: PrivateKeyDer<'static>,
}

impl RustlsIdentity {
    /// Loads a certificate chain and private key from PEM files.
    pub fn load(
        certificate_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
    ) -> Result<Self, RustlsConfigError> {
        let certificate_file =
            File::open(certificate_file).map_err(RustlsConfigError::CertificateIo)?;
        let mut certificates = BufReader::new(certificate_file);
        let cert_chain = rustls_pemfile::certs(&mut certificates)
            .collect::<Result<Vec<_>, _>>()
            .map_err(RustlsConfigError::CertificatePem)?;
        if cert_chain.is_empty() {
            return Err(RustlsConfigError::MissingCertificate);
        }

        let key_file = File::open(key_file).map_err(RustlsConfigError::KeyIo)?;
        let mut keys = BufReader::new(key_file);
        let private_key = rustls_pemfile::private_key(&mut keys)
            .map_err(RustlsConfigError::KeyPem)?
            .ok_or(RustlsConfigError::MissingPrivateKey)?;

        Ok(Self {
            cert_chain,
            private_key,
        })
    }
}

impl Clone for RustlsIdentity {
    /// Clones the certificate chain and private key.
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

/// Identity plus the SHA-256 pin for the peer's leaf certificate.
#[derive(Clone, Debug)]
pub struct RustlsConfig {
    /// Local certificate chain and private key.
    pub identity: RustlsIdentity,
    /// SHA-256 digest of the peer's exact leaf DER bytes.
    pub peer_cert_sha256: [u8; 32],
}

impl RustlsConfig {
    /// Loads a mutual-TLS configuration from PEM files and a normalized pin.
    pub fn load(
        certificate_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        peer_cert_sha256: &str,
    ) -> Result<Self, RustlsConfigError> {
        Ok(Self {
            identity: RustlsIdentity::load(certificate_file, key_file)?,
            peer_cert_sha256: parse_sha256_pin(peer_cert_sha256)?,
        })
    }

    /// Builds the TLS server configuration with mandatory pinned client auth.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, RustlsConfigError> {
        self.server_config_with_protocol_versions(rustls::ALL_VERSIONS)
    }

    /// Builds a pinned mutual-TLS server configuration for the supplied
    /// protocol versions.
    pub fn server_config_with_protocol_versions(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Result<Arc<ServerConfig>, RustlsConfigError> {
        let provider = provider();
        let verifier = PinnedClientCertVerifier {
            pin: self.peer_cert_sha256,
            provider: provider.clone(),
        };
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(rustls_error)?
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(
                self.identity.cert_chain.clone(),
                self.identity.private_key.clone_key(),
            )
            .map_err(rustls_error)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Arc::new(config))
    }

    /// Builds the TLS client configuration with mandatory pinned server auth.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, RustlsConfigError> {
        self.client_config_with_protocol_versions(rustls::ALL_VERSIONS)
    }

    /// Builds a pinned mutual-TLS client configuration for the supplied
    /// protocol versions.
    pub fn client_config_with_protocol_versions(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Result<Arc<ClientConfig>, RustlsConfigError> {
        let provider = provider();
        let verifier = PinnedServerCertVerifier {
            pin: self.peer_cert_sha256,
            provider: provider.clone(),
        };
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(rustls_error)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(
                self.identity.cert_chain.clone(),
                self.identity.private_key.clone_key(),
            )
            .map_err(rustls_error)?;
        let mut config = config;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Arc::new(config))
    }
}

/// Parses a case-insensitive SHA-256 digest, accepting common display
/// separators and an optional `0x` prefix.
pub fn parse_sha256_pin(value: &str) -> Result<[u8; 32], RustlsConfigError> {
    let mut value = value.trim();
    if let Some(stripped) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        value = stripped;
    }

    let mut normalized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            normalized.push(character);
        } else if character.is_ascii_whitespace() || character == ':' || character == '-' {
            continue;
        } else {
            return Err(RustlsConfigError::InvalidPeerPin);
        }
    }
    if normalized.len() != 64 {
        return Err(RustlsConfigError::InvalidPeerPin);
    }

    let mut digest = [0_u8; 32];
    for (index, chunk) in normalized.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(digest)
}

/// Converts one hexadecimal digit to its numeric value.
fn hex_nibble(value: u8) -> Result<u8, RustlsConfigError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(RustlsConfigError::InvalidPeerPin),
    }
}

/// Returns the cryptographic provider used by rustls.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Converts a rustls error into the public configuration error.
fn rustls_error(error: RustlsError) -> RustlsConfigError {
    RustlsConfigError::Rustls(error.to_string())
}

/// Checks whether a certificate matches the configured SHA-256 pin.
fn pin_matches(pin: &[u8; 32], certificate: &CertificateDer<'_>) -> bool {
    let digest: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
    digest == *pin
}

/// Builds a trust store containing the pinned certificate.
fn roots_for_leaf(certificate: &CertificateDer<'_>) -> Result<RootCertStore, RustlsError> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).map_err(|error| {
        RustlsError::General(format!("invalid pinned peer certificate: {error}"))
    })?;
    Ok(roots)
}

/// Server-side verifier for a pinned self-signed peer certificate.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    /// SHA-256 digest of the expected peer certificate.
    pin: [u8; 32],
    /// Cryptographic provider used for certificate verification.
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    /// Verifies the pinned server certificate and its signature chain.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !pin_matches(&self.pin, end_entity) {
            return Err(RustlsError::General(
                "peer certificate SHA-256 pin mismatch".into(),
            ));
        }
        let parsed = ParsedCertificate::try_from(end_entity)?;
        let roots = roots_for_leaf(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies a TLS 1.2 handshake signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            certificate,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Verifies a TLS 1.3 handshake signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            certificate,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Lists the signature schemes supported by the provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client-side verifier for a pinned self-signed peer certificate.
#[derive(Debug)]
struct PinnedClientCertVerifier {
    /// SHA-256 digest of the expected peer certificate.
    pin: [u8; 32],
    /// Cryptographic provider used for certificate verification.
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    /// Returns no distinguished-name hints for the pinned self-signed peer.
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    /// Verifies the pinned client certificate and its signature chain.
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if !pin_matches(&self.pin, end_entity) {
            return Err(RustlsError::General(
                "peer certificate SHA-256 pin mismatch".into(),
            ));
        }
        let roots = roots_for_leaf(end_entity)?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|error| RustlsError::General(error.to_string()))?;
        verifier.verify_client_cert(end_entity, intermediates, now)
    }

    /// Verifies a TLS 1.2 handshake signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            certificate,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Verifies a TLS 1.3 handshake signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            certificate,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Lists the signature schemes supported by the provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, generate_simple_self_signed, CertificateParams, ExtendedKeyUsagePurpose,
        KeyPair,
    };
    use rustls::pki_types::pem::PemObject;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{rustls::pki_types::ServerName, TlsAcceptor, TlsConnector};

    fn identity(name: &str) -> RustlsIdentity {
        let generated = generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        identity_from_parts(
            generated.cert.der().to_vec(),
            generated.signing_key.serialize_pem(),
        )
    }

    fn identity_with_eku(name: &str, usage: ExtendedKeyUsagePurpose) -> RustlsIdentity {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![usage];
        let signing_key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&signing_key).unwrap();
        identity_from_parts(certificate.der().to_vec(), signing_key.serialize_pem())
    }

    fn identity_with_validity(
        name: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> RustlsIdentity {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        let signing_key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&signing_key).unwrap();
        identity_from_parts(certificate.der().to_vec(), signing_key.serialize_pem())
    }

    fn identity_from_parts(der: Vec<u8>, key_pem: String) -> RustlsIdentity {
        let certificate = CertificateDer::from(der);
        let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        RustlsIdentity {
            cert_chain: vec![certificate],
            private_key,
        }
    }

    fn pin(identity: &RustlsIdentity) -> [u8; 32] {
        Sha256::digest(identity.cert_chain[0].as_ref()).into()
    }

    #[test]
    fn parses_normalized_pin_forms() {
        let compact =
            parse_sha256_pin("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        let separated = parse_sha256_pin(
            "0x00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:\
             00-11-22-33-44-55-66-77-88-99-aa-bb-cc-dd-ee-ff",
        )
        .unwrap();
        assert_eq!(compact, separated);
    }

    #[test]
    fn rejects_malformed_pin() {
        assert!(matches!(
            parse_sha256_pin("not-a-pin"),
            Err(RustlsConfigError::InvalidPeerPin)
        ));
        assert!(matches!(
            parse_sha256_pin(&"00".repeat(31)),
            Err(RustlsConfigError::InvalidPeerPin)
        ));
    }

    #[tokio::test]
    async fn mutual_pinned_tls_accepts_without_hostname_matching() {
        let server_identity = identity("server.invalid");
        let client_identity = identity("client.invalid");
        let server = RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client = RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: pin(&server_identity),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(server.server_config().unwrap())
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            stream.write_all(b"ok").await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
        let mut stream = TlsConnector::from(client.client_config().unwrap())
            .connect(server_name, stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn mutual_pinned_tls_accepts_tls12_and_tls13() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let server_identity = identity("server.invalid");
            let client_identity = identity("client.invalid");
            let server = RustlsConfig {
                identity: server_identity.clone(),
                peer_cert_sha256: pin(&client_identity),
            };
            let client = RustlsConfig {
                identity: client_identity,
                peer_cert_sha256: pin(&server_identity),
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_config = server
                .server_config_with_protocol_versions(&[version])
                .unwrap();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = TlsAcceptor::from(server_config)
                    .accept(stream)
                    .await
                    .unwrap();
                assert_eq!(stream.get_ref().1.protocol_version(), Some(version.version));
            });

            let stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
            let stream = TlsConnector::from(
                client
                    .client_config_with_protocol_versions(&[version])
                    .unwrap(),
            )
            .connect(server_name, stream)
            .await
            .unwrap();
            assert_eq!(stream.get_ref().1.protocol_version(), Some(version.version));
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn mismatched_pin_rejects_the_peer() {
        let server_identity = identity("server.invalid");
        let client_identity = identity("client.invalid");
        let server = RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client = RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: [0_u8; 32],
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result = TlsAcceptor::from(server.server_config().unwrap())
                .accept(stream)
                .await;
            assert!(result.is_err());
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
        let result = TlsConnector::from(client.client_config().unwrap())
            .connect(server_name, stream)
            .await;
        assert!(result.is_err());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn expired_pinned_server_certificate_is_rejected() {
        let server_identity = identity_with_validity(
            "server.invalid",
            date_time_ymd(2000, 1, 1),
            date_time_ymd(2001, 1, 1),
        );
        let client_identity = identity("client.invalid");
        let server = RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client = RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: pin(&server_identity),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(server.server_config().unwrap())
                .accept(stream)
                .await
                .is_err()
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
        let result = TlsConnector::from(client.client_config().unwrap())
            .connect(server_name, stream)
            .await;
        assert!(result.is_err());
        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn bad_signature_on_pinned_server_certificate_is_rejected() {
        let generated = generate_simple_self_signed(vec!["server.invalid".to_owned()]).unwrap();
        let mut certificate = generated.cert.der().to_vec();
        *certificate.last_mut().unwrap() ^= 1;
        let server_identity =
            identity_from_parts(certificate, generated.signing_key.serialize_pem());
        let client_identity = identity("client.invalid");
        let server = RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client = RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: pin(&server_identity),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(server.server_config().unwrap())
                .accept(stream)
                .await
                .is_err()
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
        let result = TlsConnector::from(client.client_config().unwrap())
            .connect(server_name, stream)
            .await;
        assert!(result.is_err());
        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn pinned_peer_with_wrong_server_key_usage_is_rejected() {
        let server_identity =
            identity_with_eku("server.invalid", ExtendedKeyUsagePurpose::ClientAuth);
        let client_identity = identity("client.invalid");
        let server = RustlsConfig {
            identity: server_identity.clone(),
            peer_cert_sha256: pin(&client_identity),
        };
        let client = RustlsConfig {
            identity: client_identity,
            peer_cert_sha256: pin(&server_identity),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(server.server_config().unwrap())
                .accept(stream)
                .await
                .is_err()
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("not-the-certificate-name".to_owned()).unwrap();
        let result = TlsConnector::from(client.client_config().unwrap())
            .connect(server_name, stream)
            .await;
        assert!(result.is_err());
        assert!(server_task.await.unwrap());
    }

    #[test]
    fn mismatched_private_key_is_rejected_before_handshake() {
        let certificate = generate_simple_self_signed(vec!["server.invalid".to_owned()]).unwrap();
        let wrong_key = generate_simple_self_signed(vec!["other.invalid".to_owned()]).unwrap();
        let config = RustlsConfig {
            identity: identity_from_parts(
                certificate.cert.der().to_vec(),
                wrong_key.signing_key.serialize_pem(),
            ),
            peer_cert_sha256: [0_u8; 32],
        };
        assert!(matches!(
            config.server_config(),
            Err(RustlsConfigError::Rustls(_))
        ));
        assert!(matches!(
            config.client_config(),
            Err(RustlsConfigError::Rustls(_))
        ));
    }
}
