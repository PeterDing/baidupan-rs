use cookie::Cookie;
use cookie::CookieJar;


pub struct Cookies {
    pub inner: CookieJar,
}

impl Cookies {
    pub fn new(raw_cookies: String) -> Cookies {
        let mut cookiejar = CookieJar::new();
        for raw_cookie in raw_cookies.split("; ") {
            let c = Cookie::parse(raw_cookie.to_string()).unwrap();
            cookiejar.add_original(c);
        }
        Cookies { inner: cookiejar }
    }

    pub fn add(&mut self, new_cookie: String) {
        let c = Cookie::parse(new_cookie).unwrap();
        self.inner.add(c);
    }
}


impl<'a> From<&'a Cookies> for String {
    fn from(cookies: &'a Cookies) -> Self {
        let ls: Vec<_> = cookies
            .inner
            .iter()
            .map(|cookie| {
                //println!(" ++++++++ -- {:?}", &cookie.encoded().to_string());
                cookie.encoded().to_string()
            })
            .collect();
        ls.join("; ")
    }
}
