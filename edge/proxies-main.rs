use std::collections::{BTreeMap, HashMap, HashSet};
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
const DEFAULT_OUTPUT_FILE: &str = "sub/ProxyIP-Daily.md";

const MAX_CONCURRENT: usize = 150;
const TIMEOUT_SECONDS: u64 = 8;
const TARGET_PORT: u16 = 443;

const LEGACY_SOURCES_ENV: &str = "RE_NORTHERN_TERRITORY";
const RISK_API_ENV: &str = "RISK_API_HOST";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone)]
struct ProxyInfo {
    ip: String,
    port: u16,
    isp: String,
    country_code: String,
    city: String,
    region: String,
    fraud_score: i64,
    risk: String,
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
    let api_host = std::env::var(RISK_API_ENV).expect("Environment variable RISK_API_HOST is missing");

    if let Some(parent) = Path::new(DEFAULT_OUTPUT_FILE).parent() {
        fs::create_dir_all(parent)?;
    }
    File::create(DEFAULT_OUTPUT_FILE)?;

    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut candidates: Vec<(String, u16, String)> = Vec::new();

    match read_proxy_file(DEFAULT_PROXY_FILE) {
        Ok(list) => {
            for (ip, port, isp) in list {
                if port == TARGET_PORT && seen_ips.insert(ip.clone()) {
                    candidates.push((ip, port, isp));
                }
            }
            println!("System: Loaded {} candidates from file", candidates.len());
        }
        Err(e) => println!("System Warning: Could not read proxy file: {}", e),
    }

    if let Ok(raw) = std::env::var(LEGACY_SOURCES_ENV) {
        let domains: Vec<String> = raw
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        println!("System: Resolving {} domains from secrets", domains.len());
        for domain in domains {
            if let Ok(ips) = resolve_domain(&domain).await {
                for ip in ips {
                    if seen_ips.insert(ip.clone()) {
                        candidates.push((ip, TARGET_PORT, "Private Domain".to_string()));
                    }
                }
            }
        }
    }

    println!("System: Total unique candidates for scanning: {}", candidates.len());

    let self_ip = match get_original_ip_info().await {
        Ok(ip) => ip,
        Err(_) => "0.0.0.0".to_string(),
    };
    println!("System: Origin IP identified as: {}", self_ip);

    let active_proxies = Arc::new(Mutex::new(BTreeMap::<String, Vec<ProxyInfo>>::new()));

    let tasks = futures::stream::iter(candidates.into_iter().map(|(ip, port, csv_isp)| {
        let active_proxies = Arc::clone(&active_proxies);
        let self_ip = self_ip.clone();
        let api_host = api_host.clone();
        async move {
            scan_candidate(ip, port, csv_isp, &active_proxies, &self_ip, &api_host).await;
        }
    }))
    .buffer_unordered(MAX_CONCURRENT)
    .collect::<Vec<()>>();

    tasks.await;

    let locked_proxies = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
    write_markdown_file(&locked_proxies, DEFAULT_OUTPUT_FILE)?;

    println!("System: Workflow completed successfully.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<(String, u16, String)>> {
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
        let isp = if parts.len() > 3 {
            parts[3].trim().to_string()
        } else {
            "Unknown ISP".to_string()
        };
        result.push((ip, port, isp));
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

async fn fetch_risk_data(ip: &str, api_host: &str) -> Result<(i64, String)> {
    let timeout = Duration::from_secs(TIMEOUT_SECONDS);
    tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(format!("{}:443", api_host)).await?;
        let native_connector = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        let tokio_connector = TokioTlsConnector::from(native_connector);

        let mut tls_stream = tokio_connector.connect(api_host, stream).await?;
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: RustClient/1.0\r\nConnection: close\r\n\r\n",
            ip, api_host
        );
        tls_stream.write_all(request.as_bytes()).await?;

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
            let body_part = &response_str[pos + 4..];
            if let Ok(val) = serde_json::from_str::<Value>(body_part) {
                let score = val.get("fraud_score").and_then(|v| v.as_i64()).unwrap_or(100);
                let risk = val.get("risk").and_then(|v| v.as_str()).unwrap_or("high").to_string();
                return Ok((score, risk));
            }
        }
        Err("Invalid API Response".into())
    })
    .await
    .map_err(|_| Box::<dyn std::error::Error + Send + Sync>::from("Timeout"))?
}

async fn scan_candidate(
    ip: String,
    port: u16,
    csv_isp: String,
    active_proxies: &Arc<Mutex<BTreeMap<String, Vec<ProxyInfo>>>>,
    self_ip: &str,
    api_host: &str,
) {
    let mut cookie_jar = CookieJar::new();

    println!("Action: Connecting to candidate {}", ip);

    if make_request(IP_RESOLVER, PATH_HOME, Some((&ip, port)), &mut cookie_jar, false).await.is_err() {
        return;
    }

    match make_request(IP_RESOLVER, PATH_META, Some((&ip, port)), &mut cookie_jar, true).await {
        Ok((_, body)) => {
            if let Ok(json) = parse_json_response(&body) {
                if let Some(out_ip) = json.get("clientIp").and_then(|v| v.as_str()) {
                    if out_ip != self_ip {
                        let isp = json
                            .get("asOrganization")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or(csv_isp);

                        println!("Action: Analyzing risk profile for {}", ip);
                        let (fraud_score, risk) = fetch_risk_data(&ip, api_host)
                            .await
                            .unwrap_or((100, "high".to_string()));

                        let info = ProxyInfo {
                            ip: ip.clone(),
                            port,
                            isp,
                            country_code: json.get("country").and_then(|v| v.as_str()).unwrap_or("XX").to_string(),
                            city: json.get("city").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                            region: json.get("region").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                            fraud_score,
                            risk,
                        };

                        println!("Result: Approved {} with Fraud Score: {} ({})", ip, info.fraud_score, info.risk);

                        let mut locked = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
                        locked.entry(info.country_code.clone()).or_default().push(info);
                    }
                }
            }
        }
        Err(_) => {}
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

fn write_markdown_file(proxies_by_country: &BTreeMap<String, Vec<ProxyInfo>>, output_file: &str) -> io::Result<()> {
    let mut file = File::create(output_file)?;

    let total_active = proxies_by_country.values().map(|v| v.len()).sum::<usize>();
    let total_countries = proxies_by_country.len();

    let now = Utc::now();
    let tehran_now = now.with_timezone(&Tehran);
    let tehran_next = tehran_now + ChronoDuration::days(1);
    let last_updated_str = tehran_now.format("%a, %d %b %Y %H:%M").to_string();
    let next_update_str = tehran_next.format("%a, %d %b %Y %H:%M").to_string();

    fn encode_badge_label(s: &str) -> String {
        s.replace(' ', "%20")
            .replace(':', "%3A")
            .replace(',', "%2C")
            .replace('+', "%2B")
            .replace('(', "%28")
            .replace(')', "%29")
    }

    let last_badge_label = encode_badge_label(&format!("{} (UTC+3:30)", last_updated_str));
    let next_badge_label = encode_badge_label(&format!("{} (UTC+3:30)", next_update_str));

    let last_badge = format!("<img src=\"https://img.shields.io/badge/Last_Update-{}-966600\" />", last_badge_label);
    let next_badge = format!("<img src=\"https://img.shields.io/badge/Next_Update-{}-966600\" />", next_badge_label);
    let active_badge = format!("<img src=\"https://img.shields.io/badge/Active_Proxies-{}-966600\" />", total_active);
    let countries_badge = format!("<img src=\"https://img.shields.io/badge/Countries-{}-966600\" />", total_countries);

    writeln!(
        file,
        r##"<p align="left">
 <img src="https://latex.codecogs.com/svg.image?\huge&space;{{\color{{Golden}}\mathrm{{PR{{\color{{black}}\O}}XY\;IP}}" width=220px" </p><br/>

> [!WARNING]
>
> <p><b>Daily Fresh Proxies</b></p>
>
> A curated list of <b>high-quality</b>, fully-tested proxies sourced from reputable ISPs and major global data centers (e.g., Google, Amazon, Cloudflare, Tencent, Hetzner, and others)
>
> <br/>
>
> <p><b>Auto-Updated Daily</b></p>
>
> {last}  
> {next}
>
> <br/>
>
> <p><b>Overview</b></p>  
>
> {active}  
> {countries}  
>
> <br><br/>  
"##,
        last = last_badge,
        next = next_badge,
        active = active_badge,
        countries = countries_badge,
    )?;

    let top_providers = ["Google", "Amazon", "Cloudflare", "Tencent", "Hetzner"];

    let mut provider_buckets: HashMap<&str, Vec<ProxyInfo>> = HashMap::new();
    for prov in top_providers.iter() {
        provider_buckets.insert(prov, Vec::new());
    }

    for proxies in proxies_by_country.values() {
        for info in proxies.iter() {
            for prov in top_providers.iter() {
                if info.isp.to_lowercase().contains(&prov.to_lowercase()) {
                    if let Some(vec) = provider_buckets.get_mut(prov) {
                        vec.push(info.clone());
                    }
                }
            }
        }
    }

    for prov in top_providers.iter() {
        if let Some(list) = provider_buckets.get(prov) {
            if !list.is_empty() {
                let prov_logo = provider_logo_html(prov);
                let prov_title = match prov_logo {
                    Some(ref html) => format!("{} {}", html, prov),
                    None => prov.to_string(),
                };
                writeln!(file, "## {} ({})", prov_title, list.len())?;
                writeln!(file, "<details>")?;
                writeln!(file, "<summary>Click to expand</summary>\n")?;
                writeln!(file, "|   IP   |   ISP    |   Location   |   Risk Score   |")?;
                writeln!(file, "|:-------|:---------|:------------:|:--------------:|")?;
                let mut sorted = list.clone();
                sorted.sort_by_key(|info| info.fraud_score);
                for info in sorted.iter() {
                    let location = format!("{}, {}", info.region, info.city);
                    let emoji = match info.risk.to_lowercase().as_str() {
                        "low" => "⚪",
                        "medium" => "🟡",
                        _ => "⚫",
                    };

                    writeln!(
                        file,
                        "| <pre><code>{}</code></pre> | {} | {} | {} {} |",
                        info.ip, info.isp, location, info.fraud_score, emoji
                    )?;
                }
                writeln!(file, "\n</details>\n\n---\n")?;
            }
        }
    }

    for (country_code, proxies) in proxies_by_country.iter() {
        let mut sorted_proxies = proxies.clone();
        sorted_proxies.sort_by_key(|info| info.fraud_score);
        let flag = country_flag(country_code);
        let name = get_country_name(country_code);

        writeln!(
            file,
            "## {} {} ({} proxies)",
            flag,
            name,
            sorted_proxies.len()
        )?;
        writeln!(file, "<details>")?;
        writeln!(file, "<summary>Click to expand</summary>\n")?;
        writeln!(file, "|   IP   |   ISP   |   Location   |   Risk Score   |")?;
        writeln!(file, "|:-------|:--------|:------------:|:--------------:|")?;

        for info in sorted_proxies.iter() {
            let location = format!("{}, {}", info.region, info.city);
            let emoji = match info.risk.to_lowercase().as_str() {
                "low" => "⚪",
                "medium" => "🟡",
                _ => "⚫",
            };

            writeln!(
                file,
                "| <pre><code>{}</code></pre> | {} | {} | {} {} |",
                info.ip, info.isp, location, info.fraud_score, emoji
            )?;
        }

        writeln!(file, "\n</details>\n\n---\n")?;
    }

    println!("System: Markdown file updated successfully at {}", output_file);
    Ok(())
}

fn provider_logo_html(isp: &str) -> Option<String> {
    let mapping = [
        ("Google", "google.com"),
        ("Amazon", "amazon.com"),
        ("Cloudflare", "cloudflare.com"),
        ("Hetzner", "hetzner.com"),
        ("Hostinger", "hostinger.com"),
        ("Tencent", "www.tencent.com"),
        ("DigitalOcean", "digitalocean.com"),
        ("Vultr", "vultr.com"),
    ];

    for (kw, domain) in mapping.iter() {
        if isp.to_lowercase().contains(&kw.to_lowercase()) {
            return Some(format!(
                "<img alt=\"{}\" src=\"https://www.google.com/s2/favicons?sz=22&domain_url={}\" />",
                isp, domain
            ));
        }
    }
    None
}

fn country_flag(code: &str) -> String {
    code.chars()
        .filter_map(|c| {
            if c.is_ascii_alphabetic() {
                Some(char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() as u32 - 'A' as u32)).unwrap())
            } else {
                None
            }
        })
        .collect()
}

fn get_country_name(code: &str) -> String {
    match code.to_uppercase().as_str() {
        "US" => "United States".to_string(),
        "DE" => "Germany".to_string(),
        "GB" => "United Kingdom".to_string(),
        "FR" => "France".to_string(),
        "NL" => "Netherlands".to_string(),
        "CA" => "Canada".to_string(),
        "AU" => "Australia".to_string(),
        "JP" => "Japan".to_string(),
        "CN" => "China".to_string(),
        "SG" => "Singapore".to_string(),
        "KR" => "South Korea".to_string(),
        "IN" => "India".to_string(),
        "RU" => "Russia".to_string(),
        "BR" => "Brazil".to_string(),
        "IT" => "Italy".to_string(),
        "ES" => "Spain".to_string(),
        "SE" => "Sweden".to_string(),
        "CH" => "Switzerland".to_string(),
        "TR" => "Turkey".to_string(),
        "PL" => "Poland".to_string(),
        "FI" => "Finland".to_string(),
        "NO" => "Norway".to_string(),
        "IE" => "Ireland".to_string(),
        "BE" => "Belgium".to_string(),
        "AT" => "Austria".to_string(),
        "DK" => "Denmark".to_string(),
        "CZ" => "Czech Republic".to_string(),
        "UA" => "Ukraine".to_string(),
        "HK" => "Hong Kong".to_string(),
        "TW" => "Taiwan".to_string(),
        "IR" => "Iran".to_string(),
        "ZA" => "South Africa".to_string(),
        "RO" => "Romania".to_string(),
        "ID" => "Indonesia".to_string(),
        "VN" => "Vietnam".to_string(),
        "TH" => "Thailand".to_string(),
        "MY" => "Malaysia".to_string(),
        "MX" => "Mexico".to_string(),
        "AR" => "Argentina".to_string(),
        "CL" => "Chile".to_string(),
        "CO" => "Colombia".to_string(),
        "IL" => "Israel".to_string(),
        "AE" => "United Arab Emirates".to_string(),
        "SA" => "Saudi Arabia".to_string(),
        "PT" => "Portugal".to_string(),
        "HU" => "Hungary".to_string(),
        "GR" => "Greece".to_string(),
        "BG" => "Bulgaria".to_string(),
        "AM" => "Armenia".to_string(),
        _ => code.to_string(),
    }
}
