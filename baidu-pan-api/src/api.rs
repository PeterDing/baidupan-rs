use std::io;
use std::io::Read;
use std::cell::RefCell;
use std::borrow::Borrow;
use std::fs::File;
use std::path::Path;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Cursor;

use reqwest;
use reqwest::Client;
use reqwest::Response;
use reqwest::Body;
use hyper::header::Headers;
use url::Url;

use time;

use serde::Serialize;
use serde_json;
use serde_json::Value as JsonValue;

use common::HEADERS;
use util;
use util::{get_time_string, urlencode, rand_md5};
use cookies::Cookies;

use crypto::md5::Md5;
use crypto::digest::Digest;

use crc::crc32;
use crc::Hasher32;


macro_rules! literal_const {
    ($($cst:ident $type:ty : $value:expr,)+) => (
        $(
            pub const $cst: $type = $value;
         )+
    );
}

literal_const! {
    HOME_URL &'static str : "https://pan.baidu.com/disk/home/",
    BASIC_URL &'static str : "http://pan.baidu.com/api",
    META_URL &'static str : "http://pan.baidu.com/api/filemetas",
    QUOTA_URL &'static str : "http://pan.baidu.com/api/quota",
    FILELIST_URL &'static str : "http://pan.baidu.com/api/list",
    CPCS_URL &'static str : "https://c.pcs.baidu.com/rest/2.0/pcs/file",
    CREATE_URL &'static str : "https://pan.baidu.com/api/create",
    SEARCH_URL &'static str : "http://pan.baidu.com/api/search",
    FILEMANAGER_URL &'static str : "http://pan.baidu.com/api/filemanager",
    CLOUD_DL_URL &'static str : "http://pan.baidu.com/rest/2.0/services/cloud_dl",
    SHARE_URL &'static str : "http://pan.baidu.com/share/set",

    OneK u64 : 1024,
    OneM u64 : 1024 * 1024,
    OneG u64 : 1024 * 1024 * 1024,
    OneT u64 : 1024 * 1024 * 1024 * 1024,
}


pub struct Api {
    client: Client,
    cookies: Cookies,
    bdstoken: Option<String>,
}

impl Api {

    #[inline]
    pub fn new(cookies: &str) -> Api {
        let client = Client::builder()
            .timeout(::std::time::Duration::from_secs(24 * 60 * 60))
            .build().unwrap();
        Api {
            client: client,
            cookies: Cookies::new(cookies.to_string()),
            bdstoken: None,
        }
    }

    #[inline]
    pub fn build_headers(&self, custom_headers: Option<Vec<(String, String)>>) -> Headers {
        let mut headers = Headers::new();
        for &(key, value) in HEADERS.iter() {
            headers.set_raw(key, value);
        }
        if let Some(custom_headers) = custom_headers {
            for (key, value) in custom_headers {
                headers.set_raw(key, value);
            }
        }
        headers.set_raw("Cookie", String::from(&self.cookies).as_str());
        headers
    }

    #[inline]
    pub fn update_cookies(&mut self, response: &Response) {
        if let Some(raw_cookies) = response.headers().get_raw("Set-Cookie") {
            for raw_cookie in raw_cookies.iter() {
                self.cookies.add(
                    String::from_utf8(raw_cookie.to_vec()).unwrap());
            }
        }
    }

    #[inline]
    pub fn rbdstoken(&mut self) -> String {
        let bdstoken = rand_md5();
        self.bdstoken = Some(String::from(bdstoken.as_str()));
        bdstoken
    }

    #[inline]
    pub fn bdstoken(&mut self) -> String {
        if let Some(ref bdstoken) = self.bdstoken {
            return String::from(bdstoken.as_str());
        }
        //println!("+ ok1");

        let url = Url::parse(HOME_URL).unwrap();
        //let url = Url::parse("http://127.0.0.1:9999").unwrap();
        let headers = self.build_headers(None);
        let resp = self.client.get(url)
            .headers(headers)
            .send();
        if let Err(_) = resp {
            return self.rbdstoken();
        }
        //println!("+ ok2");
        let mut resp = resp.unwrap();
        if !resp.status().is_success() {
            return self.rbdstoken();
        }

        self.update_cookies(&resp);

        //println!("+ ok3");
        let mut content = String::new();
        resp.read_to_string(&mut content);

        //for header in resp.headers().iter() {
            //println!("{:?} {:?}", header.name(), header.raw());
        //}

        //println!("{:?}", resp.headers().get_raw("Set-Cookie"));

        //println!("{}", &content);

        if let Some(index) = content.find("\"bdstoken\"") {
            let bdstoken = &content[index + 12 .. index + 12 + 32];
            self.bdstoken = Some(String::from(bdstoken));
            println!("++++++++++++");
            return bdstoken.to_string();
        }

        self.rbdstoken()
    }

    #[inline]
    pub fn check_login(&self) -> io::Result<bool> {
        match self.meta(&["/"]) {
            Ok(_) => Ok(true),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn meta<T: Serialize>(&self, paths: &T) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            META_URL,
            &[
                ("method", "filemetas"),
                ("dlink", "1"),
                ("blocks", "0")
            ]).unwrap();
        let headers = self.build_headers(None);
        let data = serde_json::to_string(paths).unwrap();
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(&[("target", &data)])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn quota(&self) -> io::Result<JsonValue> {
        let url = Url::parse(QUOTA_URL).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn file_list(&self,
                 dir: &str,
                 order: &str,
                 desc: usize,
                 size: usize,
                 page: usize) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            FILELIST_URL,
            &[
                ("channel", "chunlei"),
                ("clienttype", "0"),
                ("web", "1"),
                ("showempty", "1"),
                ("num", size.to_string().as_str()),   // max amount is 10000
                ("t", get_time_string().as_str()),
                ("dir", dir),
                ("page", page.to_string().as_str()),
                ("desc", desc.to_string().as_str()),   // 0 or 1
                ("order", order),    // sort by name, or size, time
                ("method", "filemetas"),
                ("dlink", "1"),
                ("blocks", "0"),
                ("_", get_time_string().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn dlink(&self, path: &str) -> io::Result<String> {
        Ok(format!("http://d.pcs.baidu.com/rest/2.0/pcs/file?method=download&app_id=250528&path={}&ver=2.0&clienttype=1",
                   urlencode(path)))
    }

    #[inline]
    fn m3u8(&self, path: &str) -> io::Result<String> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("method", "streaming"),
                ("path", path),
                ("type", "M3U8_AUTO_720"),
                ("app_id", "250528"),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let mut v = String::new();
        resp.read_to_string(&mut v);
        Ok(v)
    }

    #[inline]
    pub fn make_dir(&mut self, dir: &str) -> io::Result<bool> {
        let url = Url::parse_with_params(
            CREATE_URL,
            &[
                ("a", "commit"),
                ("channel", "chunlei"),
                ("clienttype", "0"),
                ("web", "1"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("path", dir),
                    ("isdir", "1"),
                    ("size", ""),
                    ("method", "post"),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        match v.get("errno") {
            Some(errno) => {
                //if *errno == JsonValue::Number(0) {
                if *errno == 0 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            _ => Ok(false)
        }
    }

    #[inline]
    pub fn search(&self,
                  keyword: &str,
                  dir: &str,
                  recursion: bool) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            SEARCH_URL,
            &[
                ("key", keyword),
                ("dir", dir),
                ("recursion", if recursion { "1" } else { "0" }),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn exist<T: Serialize>(&self, paths: &T) -> io::Result<bool> {
        self.meta(paths).map(|v| {
            match v.get("errno") {
                Some(errno) => {
                    if *errno == 0 {
                        true
                    } else {
                        false
                    }
                },
                _ => false
            }
        })
    }

    #[inline]
    pub fn file_operate(&mut self, opera: &str, data: &str) -> io::Result<bool> {
        let url = Url::parse_with_params(
            FILEMANAGER_URL,
            &[
                ("opera", opera),
                ("web", "1"),
                ("async", "2"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(&[("filelist", data)])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        match v.get("errno") {
            Some(errno) => {
                if *errno == 0 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            _ => Ok(false)
        }
    }

    #[inline]
    pub fn move_files(&mut self, paths: &Vec<&str>, dir: &str) -> io::Result<bool> {
        let opera = "move";
        let js_data: Vec<FileManagerData> = paths.iter().map(|path| {
            let index = path.rfind("/").unwrap_or(0);
            FileManagerData {
                path: path.to_string(),
                dest: dir.to_string(),
                newname: path[index..].to_string(),
            }
        }).collect();
        let data = serde_json::to_string(&js_data).unwrap();
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn rename_file(&mut self, path: &str, new_path: &str) -> io::Result<bool> {
        let opera = "move";
        let js_data = vec![
            {
                let index = new_path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: new_path[..index].to_string(),
                    newname: new_path[index..].to_string(),
                }
            }
        ];
        let data = serde_json::to_string(&js_data).unwrap();
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn copy_files1(&mut self, path: &str, new_path: &str) -> io::Result<bool> {
        let opera = "copy";
        let js_data = vec![
            {
                let index = new_path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: new_path[..index].to_string(),
                    newname: new_path[index..].to_string(),
                }
            }
        ];
        let data = serde_json::to_string(&js_data).unwrap();
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn copy_files2(&mut self, paths: &Vec<&str>, new_path: &str) -> io::Result<bool> {
        let opera = "copy";
        let js_data: Vec<FileManagerData> = paths.iter().map(|path| {
            let index = path.rfind("/").unwrap_or(0);
            FileManagerData {
                path: path.to_string(),
                dest: new_path.to_string(),
                newname: path[index..].to_string(),
            }
        }).collect();
        let data = serde_json::to_string(&js_data).unwrap();
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn remove_files(&mut self, paths: &Vec<&str>) -> io::Result<bool> {
        let opera = "delete";
        let data = serde_json::to_string(paths).unwrap();
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn add_task(&mut self, task_url: &str, dir: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "3"),
                    ("save_path", dir),
                    ("app_id", "250528"),
                    ("method", "add_task"),
                    ("source_url", task_url),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn add_bt(&mut self, path: &str, dir: &str, sha1: &str, selected_idx: &str, input: &str, vcode: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "2"),
                    ("input", input),
                    ("vcode", vcode),
                    ("file_sha1", sha1),
                    ("task_from", "1"),
                    ("save_path", dir),
                    ("app_id", "250528"),
                    ("source_path", path),
                    ("method", "add_task"),
                    ("selected_idx", selected_idx),
                    ("t", get_time_string().as_str()),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn add_magnet(&mut self, magnet: &str, dir: &str, selected_idx: &str, input: &str, vcode: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "4"),
                    ("input", input),
                    ("vcode", vcode),
                    ("file_sha1", ""),
                    ("task_from", "1"),
                    ("save_path", dir),
                    ("app_id", "250528"),
                    ("source_url", magnet),
                    ("method", "add_task"),
                    ("selected_idx", selected_idx),
                    ("t", get_time_string().as_str()),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn magnet_info(&mut self, magnet: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "4"),
                    ("save_path", "/"),
                    ("app_id", "250528"),
                    ("source_url", magnet),
                    ("method", "query_magnetinfo"),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn torrent_info(&mut self, path: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("type", "2"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("app_id", "250528"),
                ("source_path", path),
                ("channel", "chunlei"),
                ("method", "query_sinfo"),
                ("t", get_time_string().as_str()),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn tasks(&mut self, task_ids: &str) -> io::Result<JsonValue>
    {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("op_type", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("task_ids", task_ids),
                ("method", "query_task"),
                ("t", get_time_string().as_str()),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn all_task_ids(&mut self) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("start", "0"),
                ("limit", "1000"),
                ("status", "255"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("method", "list_task"),
                ("need_task_info", "1"),
                ("t", get_time_string().as_str()),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn clear_completed_tasks(&mut self) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("method", "clear_task"),
                ("t", get_time_string().as_str()),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn cancel_task(&mut self, task_id: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("task_id", task_id),
                ("channel", "chunlei"),
                ("method", "cancel_task"),
                ("t", get_time_string().as_str()),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url)
            .headers(headers)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn share<T: Serialize>(&mut self, fs_ids: &T, password: &str) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            SHARE_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("schannel", "4"),
                    ("pwd", password),
                    ("channel_list", "[]"),
                    ("fid_list", serde_json::to_string(fs_ids).unwrap().as_str()),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn rapidupload_file(&self, local_path: &str, dir: &str) -> io::Result<JsonValue> {
        let metadata = ::std::fs::metadata(local_path)?;
        let size = metadata.len();

        let mut file = File::open(local_path)?;

        let mut buf = [0; 256 * OneK as usize];
        file.read(&mut buf);
        let slice_md5 = util::md5(&buf);

        file.seek(SeekFrom::Start(0));

        let mut sh = Md5::new();
        let mut digest = crc32::Digest::new(crc32::IEEE);

        loop {
            let mut buf = [0; OneM as usize];
            let r = file.read(&mut buf).unwrap();

            sh.input(&buf[..r]);
            digest.write(&buf[..r]);

            if r < OneM as usize {
                break
            }
        }

        let content_md5 = sh.result_str();
        let content_crc32 = digest.sum32() & 0xffffffff;

        let lpath = Path::new(local_path);
        let filename = lpath.file_name().unwrap();
        let rpath = if dir == "/" {
            "/".to_owned() + filename.to_str().unwrap()
        } else {
            dir.trim_right_matches('/').to_owned() + "/" + filename.to_str().unwrap()
        };

        //println!("--- {}", rpath.as_str());
        //println!("slice_md5: {}\ncontent_md5: {}\ncontent_crc32: {}\nsize: {}",
                 //&slice_md5, &content_md5, &content_crc32, &size);

        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("app_id", "250528"),
                ("method", "rapidupload"),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("path", rpath.as_str()),
                    ("ondup", "overwrite"),
                    ("slice-md5", slice_md5.as_str()),
                    ("content-md5", content_md5.as_str()),
                    ("content-crc32", content_crc32.to_string().as_str()),
                    ("content-length", size.to_string().as_str()),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn upload_one_file(&self, local_path: &str, dir: &str) -> io::Result<JsonValue> {
        let lpath = Path::new(local_path);
        let filename = lpath.file_name().unwrap();

        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("dir", dir),
                ("app_id", "250528"),
                ("method", "upload"),
                ("ondup", "overwrite"),
                ("filename", filename.to_str().unwrap()),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let part = reqwest::multipart::Part::file(local_path)?;
        let part = part.file_name("");
        let form = reqwest::multipart::Form::new().part("file", part);
        let mut resp = self.client.post(url)
            .headers(headers)
            .multipart(form)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    #[inline]
    pub fn upload_slice(&self, block: &[u8]) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("app_id", "250528"),
                ("method", "upload"),
                ("type", "tmpfile"),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ]).unwrap();
        let headers = self.build_headers(None);

        let block = block.to_vec();
        let size = block.len() as u64;
        let part = reqwest::multipart::Part::reader_with_length(Cursor::new(block), size)
            .file_name("");
        let form = reqwest::multipart::Form::new()
            .part("file", part);
        let mut resp = self.client.post(url)
            .headers(headers)
            .multipart(form)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    pub fn combine_file<T: Serialize>(&self, remote_path: &str, slice_md5s: &T) -> io::Result<JsonValue> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("app_id", "250528"),
                ("path", remote_path),
                ("ondup", "overwrite"),
                ("method", "createsuperfile"),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ]).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.post(url)
            .headers(headers)
            .form(
                &[
                    ("param", format!("{{\"block_list\":{}}}", serde_json::to_string(slice_md5s).unwrap())),
                ])
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        if !resp.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", resp.status())));
        }
        let v = resp.json::<JsonValue>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
        Ok(v)
    }

    //pub fn share_()

}


#[derive(Serialize)]
struct FileManagerData {
    path: String,
    dest: String,
    newname: String,
}
