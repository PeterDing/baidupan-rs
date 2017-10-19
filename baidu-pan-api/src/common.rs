lazy_static! {
    pub static ref HEADERS: Vec<(&'static str, &'static str)> = vec![
        ("Accept", "application/json, text/javascript, text/html, */*; q=0.01",),
        ("Accept-Encoding", "gzip, deflate, sdch",),
        ("Accept-Language", "en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2",),
        ("Referer", "http://pan.baidu.com/disk/home",),
        ("X-Requested-With", "XMLHttpRequest",),
        ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",),
        ("Connection", "keep-alive",),
    ];

    pub static ref HEX_SYMBOLS: Vec<&'static str> = vec![
        "0", "1", "2", "3",
        "4", "5", "6", "7",
        "8", "9", "a", "b",
        "c", "d", "e", "f"
    ];
}
