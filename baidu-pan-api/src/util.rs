use url::percent_encoding::{utf8_percent_encode, percent_decode, DEFAULT_ENCODE_SET};
use time;

use rand::thread_rng;
use rand::Rng;

use common::HEX_SYMBOLS;

use crypto::md5::Md5;
use crypto::digest::Digest;

pub fn get_time_string() -> String {
    let now = time::get_time();
    let now_string = format!("{}{}", now.sec, now.nsec);
    String::from(&now_string[..13])
}

pub fn urlencode(input: &str) -> String {
    utf8_percent_encode(input, DEFAULT_ENCODE_SET).to_string()
}

pub fn urldecode(input: &str) -> String {
    percent_decode(input.as_bytes()).decode_utf8().unwrap().to_string()
}

pub fn rand_md5() -> String {
    let mut rng = thread_rng();
    let mut rmd5 = String::new();
    for _ in 0..32 {
        let index = rng.gen_range(0, 16);
        rmd5.push_str(HEX_SYMBOLS[index]);
    }
    rmd5
}

pub fn md5(input: &[u8]) -> String {
    let mut sh = Md5::new();
    sh.input(input);
    sh.result_str()
}
