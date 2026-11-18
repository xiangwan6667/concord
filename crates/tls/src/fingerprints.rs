use std::fmt;
use std::str::FromStr;

use crate::TlsError;

pub const GREASE: u16 = 0x0a0a;
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_P256: u16 = 0x0017;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientFingerprint {
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Qihoo360,
    Qq,
    Random,
    Chrome120,
    Firefox120,
    Safari16,
    None,
}

impl ClientFingerprint {
    pub const ALL: [ClientFingerprint; 13] = [
        Self::Chrome,
        Self::Firefox,
        Self::Safari,
        Self::Ios,
        Self::Android,
        Self::Edge,
        Self::Qihoo360,
        Self::Qq,
        Self::Random,
        Self::Chrome120,
        Self::Firefox120,
        Self::Safari16,
        Self::None,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Edge => "edge",
            Self::Qihoo360 => "360",
            Self::Qq => "qq",
            Self::Random => "random",
            Self::Chrome120 => "chrome120",
            Self::Firefox120 => "firefox120",
            Self::Safari16 => "safari16",
            Self::None => "none",
        }
    }

    /// `Random` resolves once per node: the same weights as mihomo, which
    /// picks a browser family and keeps it for the process.
    pub fn resolve_random(self) -> ClientFingerprint {
        if self != Self::Random {
            return self;
        }
        // mihomo draws the random fingerprint once per process (`once.OnceValue`).
        static PICKED: std::sync::OnceLock<ClientFingerprint> = std::sync::OnceLock::new();
        *PICKED.get_or_init(|| match rand::random_range(0..12u8) {
            0..=5 => Self::Chrome,
            6..=8 => Self::Safari,
            9..=10 => Self::Ios,
            _ => Self::Firefox,
        })
    }

    /// The table entry that describes this value, `None` for `Random` and
    /// `None`, which have no hello of their own.
    pub fn spec(self) -> Option<&'static FingerprintSpec> {
        Some(match self {
            Self::Chrome => &CHROME,
            Self::Chrome120 => &CHROME_120,
            Self::Firefox | Self::Firefox120 => &FIREFOX,
            Self::Safari | Self::Safari16 => &SAFARI,
            Self::Ios => &IOS,
            Self::Android => &ANDROID,
            Self::Edge => &EDGE,
            Self::Qihoo360 => &QIHOO_360,
            Self::Qq => &QQ,
            Self::Random | Self::None => return Option::None,
        })
    }

    /// What the BoringSSL backend can produce for this value, with a warning
    /// when it is not the value itself. BoringSSL fixes the extension order
    /// of every hello it builds and cannot send `record_size_limit`,
    /// `delegated_credentials` or ALPS, so only the Chrome family is
    /// reproducible; REALITY encodes its hello itself and ignores this.
    pub fn effective(self) -> (ClientFingerprint, Option<&'static str>) {
        match self {
            Self::Chrome | Self::Chrome120 | Self::None => (self, Option::None),
            Self::Random => (self, Option::None),
            Self::Edge | Self::Qq => (
                Self::Chrome120,
                Some("client-fingerprint is approximated by chrome120 on TLS backends"),
            ),
            Self::Firefox | Self::Firefox120 => (
                Self::Chrome,
                Some(
                    "firefox needs a fixed extension order and record_size_limit that BoringSSL \
                     cannot send; using chrome",
                ),
            ),
            Self::Safari | Self::Safari16 | Self::Ios => (
                Self::Chrome,
                Some(
                    "safari and ios need a fixed extension order that BoringSSL cannot send; \
                     using chrome",
                ),
            ),
            Self::Android | Self::Qihoo360 => (
                Self::Chrome,
                Some("this TLS 1.2 era hello cannot be built with BoringSSL; using chrome"),
            ),
        }
    }
}

impl fmt::Display for ClientFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ClientFingerprint {
    type Err = TlsError;

    fn from_str(value: &str) -> Result<Self, TlsError> {
        if value.is_empty() {
            return Ok(Self::None);
        }
        Self::ALL
            .into_iter()
            .find(|fp| fp.name() == value)
            .ok_or_else(|| TlsError::Config(format!("unknown client-fingerprint {value:?}")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ext {
    Grease,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups,
    PointFormats,
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms,
    SignatureAlgorithmsCert(&'static [u16]),
    Sct,
    KeyShare,
    PskModes,
    SupportedVersions,
    CompressCertificate,
    /// The codepoint differs between Chrome generations: 17513 and 17613.
    Alps(u16),
    EchGrease,
    DelegatedCredentials,
    RecordSizeLimit,
    NextProtocolNegotiation,
    ChannelId,
    Padding,
}

impl Ext {
    pub fn is_pinned(self) -> bool {
        matches!(self, Self::Grease | Self::Padding)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyShareKind {
    Grease,
    X25519,
    X25519MlKem768,
    P256,
}

#[derive(Clone, Copy, Debug)]
pub struct EchGrease {
    pub aeads: &'static [u16],
    pub payload_lens: &'static [u16],
}

#[derive(Debug)]
pub struct FingerprintSpec {
    pub name: &'static str,
    pub grease: bool,
    /// Chrome 106 and later randomise extension order per connection.
    pub permute_extensions: bool,
    pub tls13: bool,
    /// `GREASE` marks the slot of the per-connection GREASE suite.
    pub cipher_suites: &'static [u16],
    pub extensions: &'static [Ext],
    pub groups: &'static [u16],
    pub key_shares: &'static [KeyShareKind],
    pub signature_algorithms: &'static [u16],
    pub delegated_credentials: &'static [u16],
    pub versions: &'static [u16],
    pub alpn: &'static [&'static str],
    pub alps_protocols: &'static [&'static str],
    pub cert_compression: &'static [u16],
    pub record_size_limit: u16,
    pub ech_grease: Option<EchGrease>,
}

impl FingerprintSpec {
    pub fn offers_mlkem(&self) -> bool {
        self.groups.contains(&GROUP_X25519_MLKEM768)
    }
}

const CERT_ZLIB: u16 = 1;
const CERT_BROTLI: u16 = 2;

const CHROME_CIPHERS: &[u16] = &[
    GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];

const CHROME_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

const BORING_ECH: EchGrease = EchGrease {
    aeads: &[0x0001],
    payload_lens: &[144, 176, 208, 240],
};

const CHROME_EXTENSIONS: &[Ext] = &[
    Ext::Grease,
    Ext::ServerName,
    Ext::ExtendedMasterSecret,
    Ext::RenegotiationInfo,
    Ext::SupportedGroups,
    Ext::PointFormats,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::StatusRequest,
    Ext::SignatureAlgorithms,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::SupportedVersions,
    Ext::CompressCertificate,
    Ext::Alps(17613),
    Ext::EchGrease,
    Ext::Grease,
];

const CHROME_120_EXTENSIONS: &[Ext] = &[
    Ext::Grease,
    Ext::ServerName,
    Ext::ExtendedMasterSecret,
    Ext::RenegotiationInfo,
    Ext::SupportedGroups,
    Ext::PointFormats,
    Ext::SessionTicket,
    Ext::Alpn,
    Ext::StatusRequest,
    Ext::SignatureAlgorithms,
    Ext::Sct,
    Ext::KeyShare,
    Ext::PskModes,
    Ext::SupportedVersions,
    Ext::CompressCertificate,
    Ext::Alps(17513),
    Ext::EchGrease,
    Ext::Grease,
    Ext::Padding,
];

pub static CHROME: FingerprintSpec = FingerprintSpec {
    name: "chrome",
    grease: true,
    permute_extensions: true,
    tls13: true,
    cipher_suites: CHROME_CIPHERS,
    extensions: CHROME_EXTENSIONS,
    groups: &[
        GREASE,
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        GROUP_P256,
        0x0018,
    ],
    key_shares: &[
        KeyShareKind::Grease,
        KeyShareKind::X25519MlKem768,
        KeyShareKind::X25519,
    ],
    signature_algorithms: CHROME_SIGALGS,
    delegated_credentials: &[],
    versions: &[GREASE, 0x0304, 0x0303],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &["h2"],
    cert_compression: &[CERT_BROTLI],
    record_size_limit: 0,
    ech_grease: Some(BORING_ECH),
};

pub static CHROME_120: FingerprintSpec = FingerprintSpec {
    name: "chrome120",
    grease: true,
    permute_extensions: true,
    tls13: true,
    cipher_suites: CHROME_CIPHERS,
    extensions: CHROME_120_EXTENSIONS,
    groups: &[GREASE, GROUP_X25519, GROUP_P256, 0x0018],
    key_shares: &[KeyShareKind::Grease, KeyShareKind::X25519],
    signature_algorithms: CHROME_SIGALGS,
    delegated_credentials: &[],
    versions: &[GREASE, 0x0304, 0x0303],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &["h2"],
    cert_compression: &[CERT_BROTLI],
    record_size_limit: 0,
    ech_grease: Some(BORING_ECH),
};

pub static EDGE: FingerprintSpec = FingerprintSpec {
    name: "edge",
    grease: true,
    permute_extensions: false,
    tls13: true,
    cipher_suites: CHROME_CIPHERS,
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
        Ext::Sct,
        Ext::KeyShare,
        Ext::PskModes,
        Ext::SupportedVersions,
        Ext::CompressCertificate,
        Ext::Grease,
        Ext::Padding,
    ],
    groups: &[GREASE, GROUP_X25519, GROUP_P256, 0x0018],
    key_shares: &[KeyShareKind::Grease, KeyShareKind::X25519],
    signature_algorithms: CHROME_SIGALGS,
    delegated_credentials: &[],
    versions: &[GREASE, 0x0304, 0x0303, 0x0302, 0x0301],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[CERT_BROTLI],
    record_size_limit: 0,
    ech_grease: None,
};

pub static QQ: FingerprintSpec = FingerprintSpec {
    name: "qq",
    grease: true,
    permute_extensions: false,
    tls13: true,
    cipher_suites: CHROME_CIPHERS,
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
        Ext::Sct,
        Ext::KeyShare,
        Ext::PskModes,
        Ext::SupportedVersions,
        Ext::CompressCertificate,
        Ext::Alps(17513),
        Ext::Grease,
        Ext::Padding,
    ],
    groups: &[GREASE, GROUP_X25519, GROUP_P256, 0x0018],
    key_shares: &[KeyShareKind::Grease, KeyShareKind::X25519],
    signature_algorithms: CHROME_SIGALGS,
    delegated_credentials: &[],
    versions: &[GREASE, 0x0304, 0x0303, 0x0302, 0x0301],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &["h2"],
    cert_compression: &[CERT_BROTLI],
    record_size_limit: 0,
    ech_grease: None,
};

pub static FIREFOX: FingerprintSpec = FingerprintSpec {
    name: "firefox",
    grease: false,
    permute_extensions: false,
    tls13: true,
    cipher_suites: &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: &[
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::DelegatedCredentials,
        Ext::KeyShare,
        Ext::SupportedVersions,
        Ext::SignatureAlgorithms,
        Ext::PskModes,
        Ext::RecordSizeLimit,
        Ext::EchGrease,
    ],
    groups: &[GROUP_X25519, GROUP_P256, 0x0018, 0x0019, 0x0100, 0x0101],
    key_shares: &[KeyShareKind::X25519, KeyShareKind::P256],
    signature_algorithms: &[
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
    ],
    delegated_credentials: &[0x0403, 0x0503, 0x0603, 0x0203],
    versions: &[0x0304, 0x0303],
    alpn: &["h2", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[],
    record_size_limit: 0x4001,
    ech_grease: Some(EchGrease {
        aeads: &[0x0001, 0x0003],
        payload_lens: &[239],
    }),
};

const APPLE_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

const APPLE_GROUPS: &[u16] = &[GREASE, GROUP_X25519, GROUP_P256, 0x0018, 0x0019];

const APPLE_VERSIONS: &[u16] = &[GREASE, 0x0304, 0x0303, 0x0302, 0x0301];

pub static SAFARI: FingerprintSpec = FingerprintSpec {
    name: "safari",
    grease: true,
    permute_extensions: false,
    tls13: true,
    cipher_suites: &[
        GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
        0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
        Ext::Sct,
        Ext::KeyShare,
        Ext::PskModes,
        Ext::SupportedVersions,
        Ext::CompressCertificate,
        Ext::Grease,
        Ext::Padding,
    ],
    groups: APPLE_GROUPS,
    key_shares: &[KeyShareKind::Grease, KeyShareKind::X25519],
    signature_algorithms: APPLE_SIGALGS,
    delegated_credentials: &[],
    versions: APPLE_VERSIONS,
    alpn: &["h2", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[CERT_ZLIB],
    record_size_limit: 0,
    ech_grease: None,
};

pub static IOS: FingerprintSpec = FingerprintSpec {
    name: "ios",
    grease: true,
    permute_extensions: false,
    tls13: true,
    cipher_suites: &[
        GREASE, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024,
        0xc023, 0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c,
        0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
    ],
    extensions: &[
        Ext::Grease,
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::Alpn,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
        Ext::Sct,
        Ext::KeyShare,
        Ext::PskModes,
        Ext::SupportedVersions,
        Ext::Grease,
        Ext::Padding,
    ],
    groups: APPLE_GROUPS,
    key_shares: &[KeyShareKind::Grease, KeyShareKind::X25519],
    signature_algorithms: APPLE_SIGALGS,
    delegated_credentials: &[],
    versions: APPLE_VERSIONS,
    alpn: &["h2", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[],
    record_size_limit: 0,
    ech_grease: None,
};

/// TLS 1.2 only: it has no key share, so REALITY cannot use it.
pub static ANDROID: FingerprintSpec = FingerprintSpec {
    name: "android",
    grease: false,
    permute_extensions: false,
    tls13: false,
    cipher_suites: &[
        0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
        0x0035,
    ],
    extensions: &[
        Ext::ServerName,
        Ext::ExtendedMasterSecret,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
    ],
    groups: &[GROUP_X25519, GROUP_P256, 0x0018],
    key_shares: &[],
    signature_algorithms: &[
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
    ],
    delegated_credentials: &[],
    versions: &[],
    alpn: &[],
    alps_protocols: &[],
    cert_compression: &[],
    record_size_limit: 0,
    ech_grease: None,
};

/// TLS 1.2 only, with NPN and channel id.
pub static QIHOO_360: FingerprintSpec = FingerprintSpec {
    name: "360",
    grease: false,
    permute_extensions: false,
    tls13: false,
    cipher_suites: &[
        0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013,
        0xc027, 0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a,
    ],
    extensions: &[
        Ext::ServerName,
        Ext::RenegotiationInfo,
        Ext::SupportedGroups,
        Ext::PointFormats,
        Ext::SessionTicket,
        Ext::NextProtocolNegotiation,
        Ext::Alpn,
        Ext::ChannelId,
        Ext::StatusRequest,
        Ext::SignatureAlgorithms,
    ],
    groups: &[GROUP_P256, 0x0018, 0x0019],
    key_shares: &[],
    signature_algorithms: &[
        0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202,
    ],
    delegated_credentials: &[],
    versions: &[],
    alpn: &["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"],
    alps_protocols: &[],
    cert_compression: &[],
    record_size_limit: 0,
    ech_grease: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_round_trips_through_its_name() {
        for fp in ClientFingerprint::ALL {
            assert_eq!(fp.name().parse::<ClientFingerprint>().unwrap(), fp);
        }
        assert_eq!(
            "".parse::<ClientFingerprint>().unwrap(),
            ClientFingerprint::None
        );
        assert!("netscape".parse::<ClientFingerprint>().is_err());
    }

    #[test]
    fn grease_is_only_where_the_spec_says_so() {
        for fp in ClientFingerprint::ALL {
            let Some(spec) = fp.spec() else { continue };
            let has = spec.cipher_suites.contains(&GREASE);
            assert_eq!(has, spec.grease, "{}", spec.name);
            assert_eq!(
                spec.extensions.contains(&Ext::Grease),
                spec.grease,
                "{}",
                spec.name
            );
        }
    }

    #[test]
    fn key_shares_follow_the_offered_groups() {
        for fp in ClientFingerprint::ALL {
            let Some(spec) = fp.spec() else { continue };
            assert_eq!(spec.tls13, !spec.key_shares.is_empty(), "{}", spec.name);
            for share in spec.key_shares {
                let group = match share {
                    KeyShareKind::Grease => GREASE,
                    KeyShareKind::X25519 => GROUP_X25519,
                    KeyShareKind::X25519MlKem768 => GROUP_X25519_MLKEM768,
                    KeyShareKind::P256 => GROUP_P256,
                };
                assert!(spec.groups.contains(&group), "{} {group:04x}", spec.name);
            }
        }
    }

    #[test]
    fn random_resolves_to_a_concrete_family() {
        for _ in 0..64 {
            let fp = ClientFingerprint::Random.resolve_random();
            assert!(fp.spec().is_some());
        }
    }

    #[test]
    fn effective_warns_exactly_when_it_substitutes() {
        for fp in ClientFingerprint::ALL {
            let (used, warning) = fp.effective();
            assert_eq!(used != fp, warning.is_some(), "{fp}");
        }
    }
}
