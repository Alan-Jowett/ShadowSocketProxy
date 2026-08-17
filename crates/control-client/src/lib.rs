// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Data-plane-neutral authenticated control-channel constructors.

#[cfg(all(feature = "tls-psk", feature = "tls-rustls"))]
compile_error!("tls-psk and tls-rustls are mutually exclusive");

#[cfg(feature = "tls-psk")]
mod psk {
    use hyper_util::rt::TokioIo;
    use openssl::{
        error::ErrorStack,
        ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslStream, SslVersion},
    };
    use std::{pin::Pin, sync::Arc, time::Duration};
    use tokio::{net::TcpStream, time};
    use tonic::transport::{Channel, Endpoint};
    use tower::service_fn;

    pub async fn connect(endpoint: &str, identity: &str, secret: &[u8]) -> Result<Channel, String> {
        if identity.is_empty() || identity.as_bytes().contains(&0) || secret.is_empty() {
            return Err("invalid TLS-PSK credentials".into());
        }
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|error| format!("invalid endpoint: {error}"))?;
        let context = build_context(identity, secret).map_err(|error| error.to_string())?;
        let connector = service_fn(move |uri: http::Uri| {
            let context = context.clone();
            async move { connect_tls(uri, context).await }
        });
        Endpoint::from(uri)
            .connect_with_connector(connector)
            .await
            .map_err(|error| error.to_string())
    }

    fn build_context(identity: &str, secret: &[u8]) -> Result<Arc<SslContext>, ErrorStack> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_cipher_list("PSK-AES256-GCM-SHA384")?;
        builder.set_alpn_protos(b"\x02h2")?;
        let identity = identity.as_bytes().to_vec();
        let secret = secret.to_vec();
        builder.set_psk_client_callback(move |_, _, identity_out, key_out| {
            if identity_out.len() < identity.len() + 1 || key_out.len() < secret.len() {
                return Err(ErrorStack::get());
            }
            identity_out[..identity.len()].copy_from_slice(&identity);
            identity_out[identity.len()] = 0;
            key_out[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(Arc::new(builder.build()))
    }

    async fn connect_tls(
        uri: http::Uri,
        context: Arc<SslContext>,
    ) -> Result<TokioIo<SslStream<TcpStream>>, std::io::Error> {
        let authority = uri.authority().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "authority missing")
        })?;
        let stream = time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(authority.as_str()),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
        let mut ssl = Ssl::new(&context).map_err(std::io::Error::other)?;
        ssl.set_hostname(authority.host())
            .map_err(std::io::Error::other)?;
        let mut stream = SslStream::new(ssl, stream).map_err(std::io::Error::other)?;
        time::timeout(Duration::from_secs(5), Pin::new(&mut stream).connect())
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timeout")
            })?
            .map_err(std::io::Error::other)?;
        Ok(TokioIo::new(stream))
    }
}

#[cfg(feature = "tls-rustls")]
mod rustls {
    use hyper_util::rt::TokioIo;
    use shadow_socket_proxy_tls_rustls::RustlsConfig;
    use std::{path::Path, sync::Arc, time::Duration};
    use tokio::{net::TcpStream, time};
    use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName, TlsConnector};
    use tonic::transport::{Channel, Endpoint};
    use tower::service_fn;

    pub async fn connect(
        endpoint: &str,
        certificate_file: &Path,
        key_file: &Path,
        peer_cert_sha256: &str,
    ) -> Result<Channel, String> {
        let config = RustlsConfig::load(certificate_file, key_file, peer_cert_sha256)
            .map_err(|error| error.to_string())?
            .client_config()
            .map_err(|error| error.to_string())?;
        let uri: http::Uri = endpoint
            .parse()
            .map_err(|error| format!("invalid endpoint: {error}"))?;
        let connector = service_fn(move |uri: http::Uri| {
            let config = config.clone();
            async move { connect_tls(uri, config).await }
        });
        Endpoint::from(uri)
            .connect_with_connector(connector)
            .await
            .map_err(|error| error.to_string())
    }

    async fn connect_tls(
        uri: http::Uri,
        config: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> Result<TokioIo<TlsStream<TcpStream>>, std::io::Error> {
        let authority = uri.authority().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "authority missing")
        })?;
        let stream = time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(authority.as_str()),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
        let server_name = ServerName::try_from("ssp.invalid".to_owned()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?;
        let stream = time::timeout(
            Duration::from_secs(5),
            TlsConnector::from(config).connect(server_name, stream),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timeout"))?
        .map_err(std::io::Error::other)?;
        Ok(TokioIo::new(stream))
    }
}

#[cfg(feature = "tls-psk")]
pub use psk::connect as connect_psk;
#[cfg(feature = "tls-rustls")]
pub use rustls::connect as connect_rustls;
