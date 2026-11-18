use super::issue::LineError;
use super::pattern::check_pattern;
use super::text::Field;

pub const REQUEST_HEAD: &str = "request-head";
pub const RESPONSE_HEAD: &str = "response-head";

/// Concord's `request-head <re>` and `response-head <re>` after a header or body rewrite's
/// URL: patterns over a head as the MITM engine writes it out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeadConditionsDef {
    pub request: Option<String>,
    pub response: Option<String>,
}

impl HeadConditionsDef {
    /// `false` when `keyword` names no condition.
    pub fn set(
        &mut self,
        keyword: &str,
        pattern: Option<&str>,
        response: bool,
    ) -> Result<bool, LineError> {
        let (keyword, slot) = match keyword.to_ascii_lowercase().as_str() {
            REQUEST_HEAD => (REQUEST_HEAD, &mut self.request),
            RESPONSE_HEAD if response => (RESPONSE_HEAD, &mut self.response),
            RESPONSE_HEAD => {
                return Err(LineError::unsupported(format!(
                    "{RESPONSE_HEAD} needs an http-response rule"
                )));
            }
            _ => return Ok(false),
        };
        let pattern =
            pattern.ok_or_else(|| LineError::missing(format!("{keyword} needs a pattern")))?;
        if slot.is_some() {
            return Err(LineError::syntax(format!("{keyword} is given twice")));
        }
        check_pattern(pattern)?;
        *slot = Some(pattern.to_string());
        Ok(true)
    }

    /// Reads the conditions from `at` on and returns where the fields after them start.
    pub fn read(
        fields: &[Field],
        response: bool,
        mut at: usize,
    ) -> Result<(Self, usize), LineError> {
        let mut conditions = HeadConditionsDef::default();
        while let Some(keyword) = fields.get(at)
            && conditions.set(
                &keyword.text,
                fields.get(at + 1).map(|field| field.text.as_str()),
                response,
            )?
        {
            at += 2;
        }
        Ok((conditions, at))
    }
}
