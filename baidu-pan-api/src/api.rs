use std::io;
use std::io::Read;
use std::fs::File;
use std::path::Path;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Cursor;

use reqwest;
use reqwest::Client;
use reqwest::Response;
//use reqwest::Body;
use hyper::header::Headers;
use url::Url;

//use time;

use serde::Serialize;
use serde_json;
use serde_json::Value as JsonValue;

use crypto::md5::Md5;
use crypto::digest::Digest;

use crc::crc32;
use crc::Hasher32;

use regex::Regex;

use common::HEADERS;
use util;
use util::{get_time_string, urlencode, rand_md5};
use cookies::Cookies;

use errors::{ApiError, ApiErrorKind, ApiResult};


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
    TRANSFER_URL &'static str : "https://pan.baidu.com/share/transfer",

    ONE_K u64 : 1024,
    ONE_M u64 : 1024 * 1024,
    ONE_G u64 : 1024 * 1024 * 1024,
    ONE_T u64 : 1024 * 1024 * 1024 * 1024,
}

macro_rules! valid_response {
    ($resp:expr, $method:expr) => {
        if !$resp.status().is_success() {
            return bail!(ApiErrorKind::ResponseNoOk(
                format!("[Api::{}] response.status is {}", $method, $resp.status()),
            ));
        }
    }
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
            .build()
            .unwrap();
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
                    String::from_utf8(raw_cookie.to_vec()).unwrap(),
                );
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
        let resp = self.client.get(url).headers(headers).send();
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
            let bdstoken = &content[index + 12..index + 12 + 32];
            self.bdstoken = Some(String::from(bdstoken));
            println!("++++++++++++");
            return bdstoken.to_string();
        }

        self.rbdstoken()
    }

    #[inline]
    pub fn check_login(&self) -> ApiResult<bool> {
        match self.meta(&["/"]) {
            Ok(_) => Ok(true),
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn meta<T: Serialize>(&self, paths: &T) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            META_URL,
            &[("method", "filemetas"), ("dlink", "1"), ("blocks", "0")],
        )?;
        let headers = self.build_headers(None);
        let data = serde_json::to_string(paths).unwrap();
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(&[("target", &data)])
            .send()?;
        valid_response!(resp, "meta");
        //if !resp.status().is_success() {
        //return bail!(ApiErrorKind::ResponseNoOk(
        //format!("[Api::meta] response.status is {}", resp.status()),
        //));
        //}
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn quota(&self) -> ApiResult<JsonValue> {
        let url = Url::parse(QUOTA_URL).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "quota");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn file_list(&self, dir: &str, order: &str, desc: &str, size: usize, page: usize) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            FILELIST_URL,
            &[
                ("channel", "chunlei"),
                ("clienttype", "0"),
                ("web", "1"),
                ("showempty", "1"),
                ("num", size.to_string().as_str()), // max amount is 10000
                ("t", get_time_string().as_str()),
                ("dir", dir),
                ("page", page.to_string().as_str()),
                ("desc", desc), // 0 or 1
                ("order", order), // sort by name, or size, time
                ("method", "filemetas"),
                ("dlink", "1"),
                ("blocks", "0"),
                ("_", get_time_string().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "file_list");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn dlink(&self, path: &str) -> ApiResult<String> {
        Ok(format!(
            "http://d.pcs.baidu.com/rest/2.0/pcs/file?method=download&app_id=250528&path={}&ver=2.0&clienttype=1",
            urlencode(path)
        ))
    }

    #[inline]
    fn m3u8(&self, path: &str) -> ApiResult<String> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("method", "streaming"),
                ("path", path),
                ("type", "M3U8_AUTO_720"),
                ("app_id", "250528"),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "m3u8");
        let mut v = String::new();
        resp.read_to_string(&mut v);
        Ok(v)
    }

    #[inline]
    pub fn make_dir(&mut self, dir: &str) -> ApiResult<bool> {
        let url = Url::parse_with_params(
            CREATE_URL,
            &[
                ("a", "commit"),
                ("channel", "chunlei"),
                ("clienttype", "0"),
                ("web", "1"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("path", dir),
                    ("isdir", "1"),
                    ("size", ""),
                    ("method", "post"),
                ],
            )
            .send()?;
        valid_response!(resp, "make_dir");
        let v = resp.json::<JsonValue>()?;
        match v.get("errno") {
            Some(errno) => {
                //if *errno == JsonValue::Number(0) {
                if *errno == 0 { Ok(true) } else { Ok(false) }
            }
            _ => Ok(false),
        }
    }

    #[inline]
    pub fn search(&self, keyword: &str, dir: &str, recursion: bool) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            SEARCH_URL,
            &[
                ("key", keyword),
                ("dir", dir),
                ("recursion", if recursion { "1" } else { "0" }),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "search");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn exist<T: Serialize>(&self, paths: &T) -> ApiResult<bool> {
        self.meta(paths).map(|v| match v.get("errno") {
            Some(errno) => if *errno == 0 { true } else { false },
            _ => false,
        })
    }

    #[inline]
    pub fn file_operate(&mut self, opera: &str, data: &str) -> ApiResult<bool> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(&[("filelist", data)])
            .send()?;
        valid_response!(resp, "file_operate");
        let v = resp.json::<JsonValue>()?;
        match v.get("errno") {
            Some(errno) => if *errno == 0 { Ok(true) } else { Ok(false) },
            _ => Ok(false),
        }
    }

    #[inline]
    pub fn move_files(&mut self, paths: &Vec<&str>, dir: &str) -> ApiResult<bool> {
        let opera = "move";
        let js_data: Vec<FileManagerData> = paths
            .iter()
            .map(|path| {
                let index = path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: dir.to_string(),
                    newname: path[index..].to_string(),
                }
            })
            .collect();
        let data = serde_json::to_string(&js_data)?;
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn rename_file(&mut self, path: &str, new_path: &str) -> ApiResult<bool> {
        let opera = "move";
        let js_data = vec![
            {
                let index = new_path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: new_path[..index].to_string(),
                    newname: new_path[index..].to_string(),
                }
            },
        ];
        let data = serde_json::to_string(&js_data)?;
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn copy_files1(&mut self, path: &str, new_path: &str) -> ApiResult<bool> {
        let opera = "copy";
        let js_data = vec![
            {
                let index = new_path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: new_path[..index].to_string(),
                    newname: new_path[index..].to_string(),
                }
            },
        ];
        let data = serde_json::to_string(&js_data)?;
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn copy_files2(&mut self, paths: &Vec<&str>, new_path: &str) -> ApiResult<bool> {
        let opera = "copy";
        let js_data: Vec<FileManagerData> = paths
            .iter()
            .map(|path| {
                let index = path.rfind("/").unwrap_or(0);
                FileManagerData {
                    path: path.to_string(),
                    dest: new_path.to_string(),
                    newname: path[index..].to_string(),
                }
            })
            .collect();
        let data = serde_json::to_string(&js_data)?;
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn remove_files(&mut self, paths: &Vec<&str>) -> ApiResult<bool> {
        let opera = "delete";
        let data = serde_json::to_string(paths)?;
        self.file_operate(opera, data.as_str())
    }

    #[inline]
    pub fn add_task(&mut self, task_url: &str, dir: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "3"),
                    ("save_path", dir),
                    ("app_id", "250528"),
                    ("method", "add_task"),
                    ("source_url", task_url),
                ],
            )
            .send()?;
        valid_response!(resp, "add_task");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn add_bt(&mut self, path: &str, dir: &str, sha1: &str, selected_idx: &str, input: &str, vcode: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
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
                ],
            )
            .send()?;
        valid_response!(resp, "add_bt");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn add_magnet(&mut self, magnet: &str, dir: &str, selected_idx: &str, input: &str, vcode: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
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
                ],
            )
            .send()?;
        valid_response!(resp, "add_magnet");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn magnet_info(&mut self, magnet: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CLOUD_DL_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("type", "4"),
                    ("save_path", "/"),
                    ("app_id", "250528"),
                    ("source_url", magnet),
                    ("method", "query_magnetinfo"),
                ],
            )
            .send()?;
        valid_response!(resp, "magnet_info");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn torrent_info(&mut self, path: &str) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "torrent_info");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn tasks(&mut self, task_ids: &str) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "tasks");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn all_task_ids(&mut self) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "all_task_ids");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn clear_completed_tasks(&mut self) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "clear_completed_tasks");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn cancel_task(&mut self, task_id: &str) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "cancel_task");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn share<T: Serialize>(&mut self, fs_ids: &T, password: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            SHARE_URL,
            &[
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("schannel", "4"),
                    ("pwd", password),
                    ("channel_list", "[]"),
                    ("fid_list", serde_json::to_string(fs_ids).unwrap().as_str()),
                ],
            )
            .send()?;
        valid_response!(resp, "share");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn rapidupload_file(&self, local_path: &str, dir: &str) -> ApiResult<JsonValue> {
        let metadata = ::std::fs::metadata(local_path)?;
        let size = metadata.len();

        let mut file = File::open(local_path)?;

        let mut buf = [0; 256 * ONE_K as usize];
        file.read(&mut buf);
        let slice_md5 = util::md5(&buf);

        file.seek(SeekFrom::Start(0));

        let mut sh = Md5::new();
        let mut digest = crc32::Digest::new(crc32::IEEE);

        loop {
            let mut buf = [0; ONE_M as usize];
            let r = file.read(&mut buf).unwrap();

            sh.input(&buf[..r]);
            digest.write(&buf[..r]);

            if r < ONE_M as usize {
                break;
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
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("path", rpath.as_str()),
                    ("ondup", "overwrite"),
                    ("slice-md5", slice_md5.as_str()),
                    ("content-md5", content_md5.as_str()),
                    //("content-crc32", content_crc32.to_string().as_str()),
                    ("content-length", size.to_string().as_str()),
                ],
            )
            .send()?;
        valid_response!(resp, "rapidupload_file");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn upload_one_file(&self, local_path: &str, dir: &str) -> ApiResult<JsonValue> {
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
            ],
        )?;
        let headers = self.build_headers(None);
        let part = reqwest::multipart::Part::file(local_path)?;
        let part = part.file_name("");
        let form = reqwest::multipart::Form::new().part("file", part);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .multipart(form)
            .send()?;
        valid_response!(resp, "upload_one_file");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn upload_slice(&self, block: &[u8]) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("app_id", "250528"),
                ("method", "upload"),
                ("type", "tmpfile"),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ],
        )?;
        let headers = self.build_headers(None);

        // correct to build Part from &[u8]
        // https://github.com/seanmonstar/reqwest/issues/215
        let block = block.to_vec();
        let size = block.len() as u64;
        let part = reqwest::multipart::Part::reader_with_length(Cursor::new(block), size).file_name("");
        let form = reqwest::multipart::Form::new().part("file", part);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .multipart(form)
            .send()?;
        valid_response!(resp, "upload_slice");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    pub fn combine_file<T: Serialize>(&self, remote_path: &str, slice_md5s: &T) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            CPCS_URL,
            &[
                ("app_id", "250528"),
                ("path", remote_path),
                ("ondup", "overwrite"),
                ("method", "createsuperfile"),
                ("BDUSS", self.cookies.inner.get("BDUSS").unwrap().value()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    (
                        "param",
                        serde_json::to_string(&json!({
                            "block_list": slice_md5s
                        })).unwrap()
                            .as_str(),
                    ),
                ],
            )
            .send()?;
        valid_response!(resp, "combine_file");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }

    #[inline]
    pub fn shared_data(&self, shared_url: &str) -> ApiResult<JsonValue> {
        let url = Url::parse(shared_url).unwrap();
        let headers = self.build_headers(None);
        let mut resp = self.client.get(url).headers(headers).send()?;
        valid_response!(resp, "shared_data");
        let mut html = String::new();
        resp.read_to_string(&mut html);

        // find yundata
        let re = Regex::new(r"yunData.setData\((.+?)\);").unwrap();
        let yundata: JsonValue = if let Some(m) = re.captures(&html) {
            serde_json::from_str(&m[1])?
        } else {
            return bail!(ApiErrorKind::NoYunData(
                "`yunData.setData` is not finded".to_string(),
            ));
        };
        Ok(yundata)
    }

    pub fn transfer_file(&mut self, uk: &str, shareid: &str, path: &str, dir: &str) -> ApiResult<JsonValue> {
        let url = Url::parse_with_params(
            TRANSFER_URL,
            &[
                ("from", uk),
                ("web", "1"),
                ("clienttype", "0"),
                ("app_id", "250528"),
                ("shareid", shareid),
                ("channel", "chunlei"),
                ("bdstoken", self.bdstoken().as_str()),
            ],
        )?;
        let headers = self.build_headers(None);
        let mut resp = self.client
            .post(url)
            .headers(headers)
            .form(
                &[
                    ("filelist", serde_json::to_string(&json!([path]))?.as_str()),
                    ("path", dir),
                ],
            )
            .send()?;
        valid_response!(resp, "transfer_file");
        let v = resp.json::<JsonValue>()?;
        Ok(v)
    }
}


#[derive(Serialize)]
struct FileManagerData {
    path: String,
    dest: String,
    newname: String,
}
