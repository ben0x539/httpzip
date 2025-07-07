use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};

use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderValue, CONTENT_LENGTH, RANGE};

#[derive(thiserror::Error, Debug)]
enum HttpError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error("missing content-length header in response")]
    MissingContentLength,
    #[error("got weird content-length {0:?} in response")]
    WeirdContentLength(HeaderValue),
    #[error("got content-length {0} in response, expected {1}")]
    UnexpectedContentLength(u64, u64),
}

const CACHE_CHUNK_SIZE: usize = 4096;

struct HttpReadSeek {
    client: Client,
    url: Url,
    size: u64,
    pos: u64,
    cache: BTreeMap<usize, Vec<u8>>,
}

fn cache_entry(pos: usize) -> (usize, usize) {
    (pos / CACHE_CHUNK_SIZE, pos % CACHE_CHUNK_SIZE)
}

impl HttpReadSeek {
    fn get(&mut self, pos: u64, mut buf: &mut [u8]) -> Result<u64, HttpError> {
        let buf_size = buf.len() as u64;

        let mut resp = self.client.get(self.url.clone())
            .header(RANGE, format!("bytes={}-{}", pos, pos + buf_size - 1))
            .send()?
            .error_for_status()?;

        let content_length = get_content_length(&resp)?;
        if content_length != buf_size {
            return Err(HttpError::UnexpectedContentLength(content_length, buf_size));
        }
    
        Ok(resp.copy_to(&mut buf)?)
    }

    fn fill_cache(&mut self, n: usize) -> Result<(), HttpError> {
        let (first_entry, _first_offset) = cache_entry(self.pos as usize);
        let (last_entry, _last_offset) = cache_entry(self.pos as usize + n - 1);

        // TODO just make one request and split into chunks lol
        for key in first_entry..=last_entry {
            if self.cache.contains_key(&key) {
                eprintln!("  cache key={key} already cached");
                continue;
            }
            eprintln!("  cache key={key} not cached");

            let pos = key * CACHE_CHUNK_SIZE;
            let len = usize::min(CACHE_CHUNK_SIZE, self.size as usize - pos);
            let mut buf = vec![0u8; len];
            let n = self.get(pos as u64, &mut buf[..])?;
            buf.truncate(n as usize);
            self.cache.insert(key, buf);
        }

        Ok(())
    }

    fn read_from_cache(&self, mut buf: &mut [u8]) -> Result<(), HttpError> {
        let (first_entry, first_offset) = cache_entry(self.pos as usize);
        let (last_entry, _last_offset) = cache_entry(self.pos as usize + buf.len() - 1);

        // TODO return error if read request isn't in bounds
        // TODO return error if cache isn't the right size? but that can't happen
        // TODO any measure of abstraction so this+fill isn't awful
        for key in first_entry..=last_entry {
            let e = self.cache.get(&key).unwrap();
            let offset = if key == first_entry { first_offset } else { 0 };
            let cached = &e[offset..];
            let len = usize::min(buf.len(), cached.len());
            eprintln!("  cached key={key} offset={offset} len={len} {} {}", buf.len(), cached.len());
            buf[..len].copy_from_slice(&cached[..len]);
            buf = &mut buf[len..];
        }
        debug_assert_eq!(buf.len(), 0);

        Ok(())
    }
}

impl Seek for HttpReadSeek {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        eprintln!("seek {:?}", target);
        // TODO bounds checking
        match target {
            SeekFrom::Current(offset) => {
                self.pos = self.pos + offset as u64;
            }
            SeekFrom::Start(offset) => {
                self.pos = offset;
            }
            SeekFrom::End(offset) => {
                self.pos = self.size - offset as u64;
            }
        }

        Ok(self.pos)
    }
}

impl Read for HttpReadSeek {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            eprintln!("read pos={} ({} from end) len={}", self.pos, self.size - self.pos, buf.len());
            if buf.len() == 0 {
                return Ok(0);
            }

            self.fill_cache(buf.len())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            self.read_from_cache(buf)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            self.pos += buf.len() as u64;
            return Ok(buf.len());
        }
}

#[derive(clap::Parser, Debug)]
struct Opt {
    url: Url,
}

fn get_content_length(resp: &Response) -> Result<u64, HttpError> {
    let content_length_value = resp.headers().get(CONTENT_LENGTH)
        .ok_or(HttpError::MissingContentLength)?;
    let content_length_str = content_length_value.to_str()
        .map_err(|_| HttpError::WeirdContentLength(content_length_value.clone()))?;
    let content_length: u64 = content_length_str.parse()
        .map_err(|_| HttpError::WeirdContentLength(content_length_value.clone()))?;
    Ok(content_length)
}

fn main() -> anyhow::Result<()> {
    let opt: Opt = clap::Parser::parse();
    let client = Client::new();
    // would like to do head request here but i guess
    // some people dont set content-length on head
    let resp = client.get(opt.url.clone())
        // would like to ask to not receive any bytes except
        // then of course we also get content-length: 1
        //.header(RANGE, "bytes=0-0")
        .send()?;
    let size = get_content_length(&resp)?;
    drop(resp);

    let totally_a_real_file = HttpReadSeek {
        client: client,
        url: opt.url,
        size: size,
        pos: 0,
        cache: BTreeMap::new(),
    };

    let archive = zip::ZipArchive::new(totally_a_real_file)?;
    for entry in archive.file_names() {
        println!("found file: {}", entry);
    }

    Ok(())
}
