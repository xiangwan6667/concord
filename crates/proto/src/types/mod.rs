//! The wire types. Every field is `camelCase`, times are Unix milliseconds and
//! ports are numbers. Clash fragments and proxy mappings are the only free-form
//! values and are typed `Json`.

macro_rules! dto {
    ($($(#[$meta:meta])* pub struct $name:ident { $($(#[$fmeta:meta])* pub $field:ident: $ty:ty,)* })*) => { $(
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
        #[serde(rename_all = "camelCase")]
        pub struct $name { $($(#[$fmeta])* pub $field: $ty,)* }
    )* };
}

mod common;
mod config;
mod live;
mod mitm;
mod probe;
mod proxy;
mod state;

pub use common::*;
pub use config::*;
pub use live::*;
pub use mitm::*;
pub use probe::*;
pub use proxy::*;
pub use state::*;
