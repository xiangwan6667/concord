#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod build;
mod client;
mod dialer;
mod doh;
mod doh3;
mod doq;
mod dot;
mod engine;
mod enhance;
mod fakeip;
mod hosts;
mod lru;
mod matchers;
mod msg;
mod plain;
mod query;
mod record;
mod resets;
mod resolver;
mod shared_dial;
mod system;
#[cfg(test)]
mod tests;
mod trie;

use std::net::IpAddr;
use std::sync::Arc;

pub use dialer::{RESPECT_RULES, UpstreamDialer};
pub use engine::{Resolver, ResolverDeps};
pub use fakeip::FakeIpPool;
pub use hosts::{HostValue, Hosts};
pub use matchers::{CidrSet, domain_matchers, ip_matchers};
pub use msg::{Admission, admit};
pub use query::{QueryError, QueryView, QuestionView, RecordView};
pub use trie::{DomainSet, DomainTrie, InvalidDomain};

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("{0}")]
    Config(String),
    /// Keeps the rule engine's error as the source: a missing or invalid geo file is fetched
    /// and the build retried.
    #[error("{message}")]
    Rule { message: String, source: RuleError },
}

impl DnsError {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        DnsError::Config(message.into())
    }

    pub(crate) fn rule(message: String, source: RuleError) -> Self {
        DnsError::Rule { message, source }
    }
}

pub type RuleError = Box<dyn std::error::Error + Send + Sync>;

pub trait DomainMatch: Send + Sync {
    fn matches(&self, domain: &str) -> bool;
}

pub trait IpMatch: Send + Sync {
    fn matches(&self, ip: IpAddr) -> bool;
}

pub trait GeoIpLookup: Send + Sync {
    fn country_codes(&self, ip: IpAddr) -> Vec<String>;
}

/// The parts of the rule engine that DNS keys refer to by name: `geosite:`,
/// `rule-set:` and `fallback-filter.geoip`. The engine implements it over the
/// geo store and the provider handles, which are swapped on update.
pub trait RuleEnv: Send + Sync {
    fn geosite(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError>;

    fn domain_rule_set(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError>;

    fn geoip(&self) -> Result<Arc<dyn GeoIpLookup>, RuleError>;

    fn ip_rule_set(&self, name: &str) -> Result<Arc<dyn IpMatch>, RuleError>;
}

pub struct NoRules;

impl RuleEnv for NoRules {
    fn geosite(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
        Err(format!("geosite {name} is not available").into())
    }

    fn domain_rule_set(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
        Err(format!("not found rule-set: {name}").into())
    }

    fn geoip(&self) -> Result<Arc<dyn GeoIpLookup>, RuleError> {
        Err("GeoIP is not available".into())
    }

    fn ip_rule_set(&self, name: &str) -> Result<Arc<dyn IpMatch>, RuleError> {
        Err(format!("not found rule-set: {name}").into())
    }
}
