#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod crypt;
pub mod dns;
pub mod error;
pub mod filter;
pub mod general;
pub mod geox;
pub mod group;
pub mod hosts;
pub mod keys;
pub mod lenient;
pub mod merge;
pub mod mitm;
pub mod net;
pub mod ntp;
pub mod profile;
pub mod provider;
pub mod proxy;
pub mod raw;
pub mod report;
pub mod rule;
pub mod schema;
pub mod share_link;
pub mod sniffer;
pub mod tls;
pub mod tun;
pub mod yaml;

pub type Map = serde_json::Map<String, serde_json::Value>;

pub use error::{ConfigError, Result};
pub use merge::{
    ProfileBase, ProfileOutbound, ProfileOutbounds, is_match_rule, merge_document, merge_profile,
    profile_base, profile_outbounds,
};
pub use mitm::MitmDef;
pub use profile::{LoadOptions, Profile, load, load_raw, load_str};
pub use provider::parse_provider_content;
pub use proxy::{Capabilities, ProxyDef, ProxyKind, ProxyParse, Quarantined, parse_proxy};
pub use raw::{RawConfig, parse_raw, parse_raw_str, parse_raw_with_key, raw_to_yaml};
pub use report::{Level, LoadReport, Warning};
pub use rule::{Cond, RuleDef, RuleLines, parse_rule};
pub use schema::config_schema;
