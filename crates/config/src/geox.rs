use crate::Map;
use crate::error::Result;
use crate::lenient::Fields;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoConfig {
    pub mmdb_url: String,
    pub asn_url: String,
    pub geosite_url: String,
}

impl GeoConfig {
    pub fn from_map(geox: &Map) -> Result<GeoConfig> {
        let mut f = Fields::new(geox, "geox-url", false);
        Ok(GeoConfig {
            mmdb_url: f.string("mmdb")?,
            asn_url: f.string("asn")?,
            geosite_url: f.string("geosite")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::geox_defaults;

    #[test]
    fn defaults_point_at_meta_rules_dat() {
        let config = GeoConfig::from_map(&geox_defaults()).unwrap();
        assert!(config.mmdb_url.ends_with("/geoip.metadb"));
        assert!(config.asn_url.ends_with("/GeoLite2-ASN.mmdb"));
    }
}
