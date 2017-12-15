#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unreachable_code)]

extern crate time;
extern crate rand;
extern crate crypto;
extern crate crc;

extern crate reqwest;
extern crate hyper;
extern crate url;
extern crate cookie;

extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate error_chain;

extern crate regex;

pub mod api;
pub mod common;
pub mod util;
pub mod errors;

pub use errors::{ApiError, ApiErrorKind, ApiResult};

mod cookies;

pub use self::api::Api;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
