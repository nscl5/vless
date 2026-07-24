use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use chrono_tz::Asia::Tehran;
use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as TokioTlsConnector;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_HOME: &str = "/";
const PATH_META: &str = "/meta";

const DEFAULT_PROXY_FILE: &str = "edge/assets/p-list-july.txt";
const OUTPUT_FILE_AZ: &str = "sub/ProxyIP-Daily.mdt";
const OUTPUT_FILE_PRIORITY: &str = "sub/ProxyIP-Daily.md";

const MAX_CONCURRENT: usize = 150;
const TIMEOUT_SECONDS: u64 = 8;
const TARGET_PORT: u16 = 443;

const PRIVATE_SOURCES_ENV: &str = "PRIVATE_PROXY_DOMAINS";
const LEGACY_SOURCES_ENV: &str = "RE_NORTHERN_TERRITORY";
const PRIORITY_COUNTRIES: [&str; 4] = ["US", "DE", "TR", "GB"];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct ProxyInfo {
    ip: String,
    port: u16,
    country: String,
    org: String,
    city: String,
    region: String,
}

#[derive(Debug, Clone)]
struct CookieJar {
    cookies: Vec<String>,
}

impl CookieJar {
    fn new() -> Self {
        Self { cookies: Vec::new() }
    }

    fn add_from_headers(&mut self, headers: &str) {
        for line in headers.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("set-cookie:") {
                let cookie = line[11..].trim();
                if let Some(cookie_value) = cookie.split(';').next() {
                    self.cookies.push(cookie_value.to_string());
                }
            }
        }
    }

    fn to_header(&self) -> String {
        if self.cookies.is_empty() {
            String::new()
        } else {
            format!("Cookie: {}\r\n", self.cookies.join("; "))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("==========================================");
    println!("   CLOUDFLARE PROXY SCANNER (RAW TLS)    ");
    println!("==========================================");

    for output_file in &[OUTPUT_FILE_AZ, OUTPUT_FILE_PRIORITY] {
        if let Some(parent) = Path::new(output_file).parent() {
            fs::create_dir_all(parent)?;
        }
        File::create(output_file)?;
    }

    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(String, u16)> = Vec::new();

    // 1. Read proxy list from file
    match read_proxy_file(DEFAULT_PROXY_FILE) {
        Ok(lines) => {
            for (ip, port) in lines {
                if port == TARGET_PORT && seen_ips.insert(ip.clone()) {
                    candidates.push((ip, port));
                }
            }
            println!("✓ Loaded candidates from file: {}", candidates.len());
        }
        Err(e) => println!("⚠️ Could not read proxy file: {}", e),
    }

    // 2. Resolve private domain candidates from Environment Variables
    let private_sources = std::env::var(PRIVATE_SOURCES_ENV)
        .or_else(|_| std::env::var(LEGACY_SOURCES_ENV));

    if let Ok(raw) = private_sources {
        let domains: Vec<String> = raw
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        println!("Resolving {} private domains...", domains.len());
        for domain in domains {
            if let Ok(ips) = resolve_domain(&domain).await {
                for ip in ips {
                    if seen_ips.insert(ip.clone()) {
                        candidates.push((ip, TARGET_PORT));
                    }
                }
            }
        }
    }

    println!("✓ Total unique candidates to test: {}", candidates.len());

    // 3. Get Original IP info
    println!("\n[1/3] Fetching original client IP...");
    let original_ip = match get_original_ip_info().await {
        Ok(ip) => {
            println!("✓ Real IP detected: {}", ip);
            ip
        }
        Err(e) => {
            println!("⚠️ Failed to fetch self IP ({}), defaulting to 0.0.0.0", e);
            "0.0.0.0".to_string()
        }
    };

    // 4. Scan candidates
    let active_proxies = Arc::new(Mutex::new(Vec::<ProxyInfo>::new()));
    let counter = Arc::new(Mutex::new((0u32, candidates.len())));

    println!("\n[2/3] Testing candidates with concurrency {}...", MAX_CONCURRENT);

    let tasks = futures::stream::iter(candidates.into_iter().map(|(ip, port)| {
        let original_ip = original_ip.clone();
        let active_proxies = Arc::clone(&active_proxies);
        let counter = Arc::clone(&counter);

        async move {
            process_proxy_candidate(ip, port, &original_ip, &active_proxies).await;

            let mut lock = counter.lock().unwrap();
            lock.0 += 1;
            if lock.0 % 500 == 0 || lock.0 == lock.1 as u32 {
                println!("Progress: {}/{} ({:.1}%)", lock.0, lock.1, (lock.0 as f32 / lock.1 as f32) * 100.0);
            }
        }
    }))
    .buffer_unordered(MAX_CONCURRENT)
    .collect::<Vec<()>>();

    tasks.await;

    // 5. Process and Save Results
    println!("\n[3/3] Saving results...");
    let locked_proxies = active_proxies.lock().unwrap().clone();
    println!("✓ Total Active Validated Proxies: {}", locked_proxies.len());

    if !locked_proxies.is_empty() {
        let mut az_list = locked_proxies.clone();
        az_list.sort_by(|a, b| a.country.cmp(&b.country));
        write_markdown_file(&az_list, OUTPUT_FILE_AZ)?;

        let mut priority_list = locked_proxies;
        sort_priority(&mut priority_list);
        write_markdown_file(&priority_list, OUTPUT_FILE_PRIORITY)?;
    }

    println!("==========================================");
    println!("   SCANNING COMPLETED SUCCESSFULLY!       ");
    println!("==========================================");

    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<(String, u16)>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut result = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').collect();
        let ip = parts[0].trim().to_string();
        let port: u16 = if parts.len() > 1 {
            parts[1].trim().parse().unwrap_or(443)
        } else {
            443
        };
        result.push((ip, port));
    }

    Ok(result)
}

async fn resolve_domain(domain: &str) -> Result<Vec<String>> {
    use tokio::net::lookup_host;
    let addrs = lookup_host(format!("{}:443", domain)).await?;
    Ok(addrs.map(|addr| addr.ip().to_string()).collect())
}

async fn get_original_ip_info() -> Result<String> {
    let mut cookie_jar = CookieJar::new();
    let _ = make_request(IP_RESOLVER, PATH_HOME, None, &mut cookie_jar, false).await;
    let (_, body) = make_request(IP_RESOLVER, PATH_META, None, &mut cookie_jar, true).await?;
    let json = parse_json_response(&body)?;
    
    json.get("clientIp")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "No clientIp in response".into())
}

async fn process_proxy_candidate(
    ip: String,
    port: u16,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<ProxyInfo>>>,
) {
    let mut cookie_jar = CookieJar::new();

    // Step 1: Visit Homepage for cookies
    if make_request(IP_RESOLVER, PATH_HOME, Some((&ip, port)), &mut cookie_jar, false).await.is_err() {
        return;
    }

    // Step 2: Visit /meta endpoint
    if let Ok((_, body)) = make_request(IP_RESOLVER, PATH_META, Some((&ip, port)), &mut cookie_jar, true).await {
        if let Ok(json) = parse_json_response(&body) {
            if let Some(proxy_ip) = json.get("clientIp").and_then(|v| v.as_str()) {
                if proxy_ip != original_ip {
                    let country = json.get("country").and_then(|v| v.as_str()).unwrap_or("XX").to_string();
                    let org = json.get("asOrganization").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                    let city = json.get("city").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                    let region = json.get("region").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();

                    let info = ProxyInfo {
                        ip,
                        port,
                        country,
                        org,
                        city,
                        region,
                    };

                    let mut lock = active_proxies.lock().unwrap();
                    lock.push(info);
                }
            }
        }
    }
}

async fn make_request(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
    cookie_jar: &mut CookieJar,
    is_meta: bool,
) -> Result<(String, String)> {
    let timeout = Duration::from_secs(TIMEOUT_SECONDS);

    tokio::time::timeout(timeout, async {
        let mut headers = Vec::new();
        headers.push(format!("Host: {}", host));
        headers.push("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string());
        headers.push("Accept: */*".to_string());
        headers.push("Accept-Language: en-US,en;q=0.9".to_string());
        headers.push("Accept-Encoding: identity".to_string());
        headers.push("Connection: close".to_string());

        let cookie_str = cookie_jar.to_header();
        if !cookie_str.is_empty() {
            headers.push(cookie_str);
        }

        if is_meta {
            headers.push("Referer: https://speed.cloudflare.com/".to_string());
            headers.push("Sec-Fetch-Dest: empty".to_string());
            headers.push("Sec-Fetch-Mode: cors".to_string());
            headers.push("Sec-Fetch-Site: same-origin".to_string());
            headers.push("Origin: https://speed.cloudflare.com".to_string());
        }

        let request_payload = format!("GET {} HTTP/1.1\r\n{}\r\n\r\n", path, headers.join("\r\n"));

        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            TcpStream::connect(format!("{}:{}", proxy_ip, proxy_port)).await?
        } else {
            TcpStream::connect(format!("{}:443", host)).await?
        };

        let native_connector = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let tokio_connector = TokioTlsConnector::from(native_connector);

        let mut tls_stream = tokio_connector.connect(host, stream).await?;
        tls_stream.write_all(request_payload.as_bytes()).await?;

        let mut response_bytes = Vec::new();
        let mut buffer = [0u8; 8192];

        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => response_bytes.extend_from_slice(&buffer[..n]),
                Err(_) => break,
            }
        }

        let response_str = String::from_utf8_lossy(&response_bytes).to_string();

        if let Some(pos) = response_str.find("\r\n\r\n") {
            let headers_part = &response_str[..pos];
            let body_part = response_str[pos + 4..].to_string();
            cookie_jar.add_from_headers(headers_part);
            Ok((headers_part.to_string(), body_part))
        } else {
            Ok(("".to_string(), response_str))
        }
    })
    .await
    .map_err(|_| Box::<dyn std::error::Error + Send + Sync>::from("Timeout"))?
}

fn parse_json_response(body: &str) -> Result<Value> {
    let trimmed = body.trim();
    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if val.get("clientIp").is_some() {
            return Ok(val);
        }
    }
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            if end > start {
                if let Ok(val) = serde_json::from_str::<Value>(&trimmed[start..=end]) {
                    if val.get("clientIp").is_some() {
                        return Ok(val);
                    }
                }
            }
        }
    }
    Err("Invalid JSON response".into())
}

fn sort_priority(proxies: &mut [ProxyInfo]) {
    proxies.sort_by(|a, b| {
        let a_p = PRIORITY_COUNTRIES.iter().position(|&c| c == a.country);
        let b_p = PRIORITY_COUNTRIES.iter().position(|&c| c == b.country);
        match (a_p, b_p) {
            (Some(a_idx), Some(b_idx)) => a_idx.cmp(&b_idx),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.country.cmp(&b.country),
        }
    });
}

fn write_markdown_file(proxies: &[ProxyInfo], output_file: &str) -> io::Result<()> {
    let mut file = File::create(output_file)?;
    let mut grouped: BTreeMap<String, Vec<&ProxyInfo>> = BTreeMap::new();

    for p in proxies {
        grouped.entry(p.country.clone()).or_default().push(p);
    }

    let now = Utc::now().with_timezone(&Tehran);
    let tehran_next = now + ChronoDuration::days(1);

    writeln!(file, "### Cloudflare Active Proxies")?;
    writeln!(file, "> Last Updated: {} (UTC+3:30)", now.format("%a, %d %b %Y %H:%M"))?;
    writeln!(file, "> Next Update: {} (UTC+3:30)\n", tehran_next.format("%a, %d %b %Y %H:%M"))?;

    for (country, list) in grouped {
        writeln!(file, "## {} ({} proxies)", country, list.len())?;
        writeln!(file, "| IP | Port | ISP | Location |")?;
        writeln!(file, "|:---|:---:|:---|:---:|")?;
        for p in list {
            writeln!(
                file,
                "| `<pre>{}</pre>` | {} | {} | {}, {} |",
                p.ip, p.port, p.org, p.region, p.city
            )?;
        }
        writeln!(file, "\n---\n")?;
    }

    Ok(())
}
