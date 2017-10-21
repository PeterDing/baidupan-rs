#![warn(unused_variables)]

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

extern crate regex;

pub mod api;
pub mod common;
pub mod util;
mod cookies;

pub use self::api::Api;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
