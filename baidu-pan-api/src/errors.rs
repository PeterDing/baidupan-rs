use std::io;
use std::num;

use url;
use serde_json;
use reqwest;

error_chain! {
    types {
        ApiError, ApiErrorKind, ApiResultExt, ApiResult;
    }

    foreign_links {
        Io(io::Error);
        SerdeJson(serde_json::Error);
        ParseInt(num::ParseIntError);
        Reqwest(reqwest::Error);
        Url(url::ParseError);
    }

    errors {
        ResponseNoOk(msg: String) {
            description("response is not ok.")
            display("response is not ok: {}", msg)
        }

        NoYunData(msg: String) {
            description("yundata is not finded.")
            display("yundata is not finded: {}", msg)
        }
    }
}
