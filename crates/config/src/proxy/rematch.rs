use crate::error::{ConfigError, Result};
use crate::lenient::Fields;

use super::types::RematchOpts;

pub(super) fn parse(fields: &mut Fields<'_>) -> Result<RematchOpts> {
    let target_rematch_name = fields.opt_string("target-rematch-name")?;
    let target_sub_rule = fields.opt_string("target-sub-rule")?;
    if target_rematch_name.is_none() && target_sub_rule.is_none() {
        return Err(ConfigError::new(
            "rematch requires at least one of target-rematch-name or target-sub-rule",
        ));
    }
    Ok(RematchOpts {
        target_rematch_name,
        target_sub_rule,
    })
}
