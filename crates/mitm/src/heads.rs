//! Concord's conditions on a request's or a response's head, and the heads they read.

use std::cell::OnceCell;

use concord_config::mitm::HeadConditionsDef;

use crate::pattern::{Pattern, PatternError};

/// Concord's `request-head <re>` and `response-head <re>` after a header or body rewrite's
/// URL: patterns over a head as [crate::headers::head_text] writes it.
#[derive(Debug, Default)]
pub(crate) struct HeadConditions {
    pub(crate) request: Option<Pattern>,
    pub(crate) response: Option<Pattern>,
}

impl HeadConditions {
    pub(crate) fn compile(def: &HeadConditionsDef) -> Result<Self, PatternError> {
        let compile = |pattern: &Option<String>| pattern.as_deref().map(Pattern::new).transpose();
        Ok(HeadConditions {
            request: compile(&def.request)?,
            response: compile(&def.response)?,
        })
    }
}

/// The heads a rule's conditions read, each written at most once and only when a rule
/// whose URL matched asks for it. A head that is not known yet lets its condition pass.
pub(crate) struct Heads<'a> {
    request: Option<&'a dyn Fn() -> String>,
    response: Option<&'a dyn Fn() -> String>,
    request_text: OnceCell<String>,
    response_text: OnceCell<String>,
}

impl<'a> Heads<'a> {
    pub(crate) fn new(
        request: Option<&'a dyn Fn() -> String>,
        response: Option<&'a dyn Fn() -> String>,
    ) -> Self {
        Heads {
            request,
            response,
            request_text: OnceCell::new(),
            response_text: OnceCell::new(),
        }
    }

    pub(crate) fn allow(&self, conditions: &HeadConditions) -> bool {
        self.request_allows(conditions.request.as_ref())
            && pass(
                conditions.response.as_ref(),
                self.response,
                &self.response_text,
            )
    }

    pub(crate) fn request_allows(&self, condition: Option<&Pattern>) -> bool {
        pass(condition, self.request, &self.request_text)
    }
}

fn pass(
    pattern: Option<&Pattern>,
    head: Option<&dyn Fn() -> String>,
    text: &OnceCell<String>,
) -> bool {
    match (pattern, head) {
        (Some(pattern), Some(head)) => pattern.is_match(text.get_or_init(head)),
        _ => true,
    }
}
