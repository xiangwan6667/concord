use concord_config::general::General;
use concord_config::net::IpCidr;
use concord_inbound::Cidr;

use crate::engine::UpdateRequest;
use crate::error::Failure;

/// A live update's LAN keys, checked whole before any of the update applies: mihomo decodes the
/// lists as `netip.Prefix`, so one bad entry fails the request.
pub(crate) struct LanPatch {
    bind_address: Option<String>,
    allowed: Option<Vec<IpCidr>>,
    disallowed: Option<Vec<IpCidr>>,
}

impl LanPatch {
    pub(crate) fn of(request: &UpdateRequest) -> Result<Self, Failure> {
        Ok(LanPatch {
            bind_address: request.bind_address.clone(),
            allowed: request
                .lan_allowed_ips
                .as_deref()
                .map(prefixes)
                .transpose()?,
            disallowed: request
                .lan_disallowed_ips
                .as_deref()
                .map(prefixes)
                .transpose()?,
        })
    }

    pub(crate) fn apply(self, general: &mut General) {
        if let Some(bind) = self.bind_address {
            general.bind_address = bind;
        }
        if let Some(allowed) = self.allowed {
            general.lan_allowed_ips = allowed;
        }
        if let Some(disallowed) = self.disallowed {
            general.lan_disallowed_ips = disallowed;
        }
    }
}

fn prefixes(texts: &[String]) -> Result<Vec<IpCidr>, Failure> {
    texts
        .iter()
        .map(|text| {
            IpCidr::parse(text.trim())
                .ok_or_else(|| Failure::new("invalid_arguments", format!("invalid prefix: {text}")))
        })
        .collect()
}

pub(crate) fn cidrs(prefixes: &[IpCidr]) -> Vec<Cidr> {
    prefixes
        .iter()
        .filter_map(|prefix| Cidr::new(prefix.addr, prefix.prefix))
        .collect()
}

pub(crate) fn texts(prefixes: &[IpCidr]) -> Vec<String> {
    prefixes.iter().map(ToString::to_string).collect()
}
