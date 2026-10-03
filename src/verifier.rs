use crate::ResultType;
use rustls_pki_types::{ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::{self, client::WebPkiServerVerifier, CertificateError, ClientConfig};
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error as TLSError, SignatureScheme,
};

// https://github.com/seanmonstar/reqwest/blob/fd61bc93e6f936454ce0b978c6f282f06eee9287/src/tls.rs#L608
#[derive(Debug)]
pub(crate) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A certificate verifier that tries a primary verifier first,
/// and falls back to a platform verifier if the primary fails.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[derive(Debug)]
struct FallbackPlatformVerifier {
    primary: Arc<dyn ServerCertVerifier>,
    fallback: Arc<dyn ServerCertVerifier>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl FallbackPlatformVerifier {
    fn with_platform_fallback(
        primary: Arc<dyn ServerCertVerifier>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, TLSError> {
        #[cfg(target_os = "android")]
        if !crate::config::ANDROID_RUSTLS_PLATFORM_VERIFIER_INITIALIZED
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(TLSError::General(
                "rustls-platform-verifier not initialized".to_string(),
            ));
        }
        let fallback = Arc::new(rustls_platform_verifier::Verifier::new(provider)?);
        Ok(Self { primary, fallback })
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl ServerCertVerifier for FallbackPlatformVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        match self.primary.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(primary_err) => {
                match self.fallback.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                ) {
                    Ok(verified) => Ok(verified),
                    Err(fallback_err) => {
                        log::error!(
                            "Both primary and fallback verifiers failed to verify server certificate, primary error: {:?}, fallback error: {:?}",
                            primary_err,
                            fallback_err
                        );
                        Err(primary_err)
                    }
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        // Both WebPkiServerVerifier and rustls_platform_verifier use the same signature verification implementation.
        // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/webpki/server_verifier.rs#L278
        // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/crypto/mod.rs#L17
        // https://github.com/rustls/rustls-platform-verifier/blob/1099f161bfc5e3ac7f90aad88b1bf788e72906cb/rustls-platform-verifier/src/verification/android.rs#L9
        // https://github.com/rustls/rustls-platform-verifier/blob/1099f161bfc5e3ac7f90aad88b1bf788e72906cb/rustls-platform-verifier/src/verification/apple.rs#L6
        self.primary.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        // Same implementation as verify_tls12_signature.
        self.primary.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Both WebPkiServerVerifier and rustls_platform_verifier use the same crypto provider,
        // so their supported signature schemes are identical.
        // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/webpki/server_verifier.rs#L172C52-L172C85
        // https://github.com/rustls/rustls-platform-verifier/blob/1099f161bfc5e3ac7f90aad88b1bf788e72906cb/rustls-platform-verifier/src/verification/android.rs#L327
        // https://github.com/rustls/rustls-platform-verifier/blob/1099f161bfc5e3ac7f90aad88b1bf788e72906cb/rustls-platform-verifier/src/verification/apple.rs#L304
        self.primary.supported_verify_schemes()
    }
}

fn webpki_server_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> ResultType<Arc<WebPkiServerVerifier>> {
    // Load root certificates from both bundled webpki_roots and system-native certificate stores.
    // This approach is consistent with how reqwest and tokio-tungstenite handle root certificates.
    // https://github.com/snapview/tokio-tungstenite/blob/35d110c24c9d030d1608ec964d70c789dfb27452/src/tls.rs#L95
    // https://github.com/seanmonstar/reqwest/blob/b126ca49da7897e5d676639cdbf67a0f6838b586/src/async_impl/client.rs#L643
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_native_certs::CertificateResult { certs, errors, .. } =
        rustls_native_certs::load_native_certs();
    if !errors.is_empty() {
        log::warn!("native root CA certificate loading errors: {errors:?}");
    }
    root_cert_store.add_parsable_certificates(certs);

    // Build verifier using with_root_certificates behavior (WebPkiServerVerifier without CRLs).
    // Both reqwest and tokio-tungstenite use this approach.
    // https://github.com/seanmonstar/reqwest/blob/b126ca49da7897e5d676639cdbf67a0f6838b586/src/async_impl/client.rs#L749
    // https://github.com/snapview/tokio-tungstenite/blob/35d110c24c9d030d1608ec964d70c789dfb27452/src/tls.rs#L127
    // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/client/builder.rs#L47
    // with_root_certificates creates a WebPkiServerVerifier without revocation checking:
    // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/webpki/server_verifier.rs#L177
    // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/webpki/server_verifier.rs#L168
    // Since no CRL is provided (as is the case here), we must explicitly set allow_unknown_revocation_status()
    // to match the behavior of with_root_certificates, which allows unknown revocation status by default.
    // https://github.com/rustls/rustls/blob/1ee126adb3352a2dcd72420dcd6040351a6ddc1e/rustls/src/webpki/server_verifier.rs#L37
    // Note: build() only returns an error if the root certificate store is empty, which won't happen here.
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_cert_store),
        provider.clone(),
    )
    .allow_unknown_revocation_status()
    .build()
    .map_err(|e| anyhow::anyhow!(e))?;
    Ok(verifier)
}

pub fn client_config(danger_accept_invalid_cert: bool) -> ResultType<ClientConfig> {
    if danger_accept_invalid_cert {
        client_config_danger()
    } else {
        client_config_safe()
    }
}

pub fn client_config_safe() -> ResultType<ClientConfig> {
    // Use the default builder which uses the default protocol versions and crypto provider.
    // The with_protocol_versions API has been removed in rustls master branch:
    // https://github.com/rustls/rustls/pull/2599
    // This approach is consistent with tokio-tungstenite's usage:
    // https://github.com/snapview/tokio-tungstenite/blob/35d110c24c9d030d1608ec964d70c789dfb27452/src/tls.rs#L126
    let config_builder = rustls::ClientConfig::builder();
    let provider = config_builder.crypto_provider().clone();
    let webpki_verifier = webpki_server_verifier(provider.clone())?;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        match FallbackPlatformVerifier::with_platform_fallback(webpki_verifier.clone(), provider) {
            Ok(fallback_verifier) => {
                let config = config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(fallback_verifier))
                    .with_no_client_auth();
                Ok(config)
            }
            Err(e) => {
                log::error!(
                    "Failed to create fallback verifier: {:?}, use webpki verifier instead",
                    e
                );
                let config = config_builder
                    .with_webpki_verifier(webpki_verifier)
                    .with_no_client_auth();
                Ok(config)
            }
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let config = config_builder
            .with_webpki_verifier(webpki_verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

pub fn client_config_danger() -> ResultType<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(config)
}

/// 自建服务器证书钉扎验证器：只比对叶子证书 SPKI 的 SHA-256 指纹，
/// 与 `config::SELF_HOSTED_SPKI_SHA256` 一致即通过；域名与 CA 链不校验
/// （服务器证书为自签，真实性完全由公钥指纹保证）。
#[derive(Debug)]
pub struct PinVerifier {
    expected_spki_sha256: [u8; 32],
}

impl PinVerifier {
    pub fn new() -> ResultType<Self> {
        Ok(Self {
            expected_spki_sha256: parse_spki_hex(crate::config::SELF_HOSTED_SPKI_SHA256)?,
        })
    }
}

/// 解析 64 字符 hex 字符串为 32 字节指纹。
fn parse_spki_hex(s: &str) -> ResultType<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16);
        let lo = (bytes[i * 2 + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => *b = (hi << 4 | lo) as u8,
            _ => anyhow::bail!("non-hex char in SPKI fingerprint"),
        }
    }
    Ok(out)
}

/// 读取 DER TLV 头部，返回 (tag, header 长度, content 长度)。
fn der_tlv(bytes: &[u8]) -> Option<(u8, usize, usize)> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (header_len, content_len) = if first < 0x80 {
        (2, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if !(1..=4).contains(&n) || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | b as usize;
        }
        (2 + n, len)
    };
    if bytes.len() < header_len + content_len {
        return None;
    }
    Some((tag, header_len, content_len))
}

/// 提取证书 SubjectPublicKeyInfo 的完整 DER（含 TLV 头，与
/// `openssl pkey -pubin -outform DER` 输出一致）。
/// X.509 结构字段顺序固定，跳过可选 version 与 serial/signature/issuer/validity/subject
/// 五个必选字段后即是 SPKI。
fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let (tag, hdr, len) = der_tlv(cert_der)?;
    if tag != 0x30 {
        return None;
    }
    let tbs = cert_der.get(hdr..hdr + len)?;
    let (tag, hdr, _len) = der_tlv(tbs)?;
    if tag != 0x30 {
        return None;
    }
    let mut pos = hdr;
    // 可选的 version [0] EXPLICIT
    if let Some((0xa0, h, l)) = der_tlv(tbs.get(pos..)?) {
        pos += h + l;
    }
    for _ in 0..5 {
        let (_, h, l) = der_tlv(tbs.get(pos..)?)?;
        pos += h + l;
    }
    let (tag, h, l) = der_tlv(tbs.get(pos..)?)?;
    if tag != 0x30 {
        return None;
    }
    tbs.get(pos..pos + h + l)
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TLSError> {
        let spki = extract_spki(end_entity.as_ref()).ok_or_else(|| {
            TLSError::General("failed to extract SPKI from certificate".to_owned())
        })?;
        if Sha256::digest(spki).as_slice() == self.expected_spki_sha256.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            // 指纹不符：既可能是中间人，也可能是服务器换证书后未同步更新常量
            Err(TLSError::InvalidCertificate(CertificateError::UnknownIssuer))
        }
    }

    // 握手签名必须真实验证：跳过的话，只持有证书（无私钥）的攻击者也能冒充服务器。
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 自建服务器 TLS 客户端配置（SPKI 钉扎），供 socket_client 的 TLS 连接入口使用。
pub fn client_config_pinned() -> ResultType<ClientConfig> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier::new()?))
        .with_no_client_auth();
    Ok(config)
}
