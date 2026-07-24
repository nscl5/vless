use anyhow::{Context, Result};
use chrono::{Duration as ChronoDuration, Utc};
use chrono_tz::Asia::Tehran;
use clap::Parser;
use colored::*;
use futures::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_OUTPUT_FILE: &str = "sub/ProxyIP-Daily.md";
const DEFAULT_MAX_CONCURRENT: usize = 80;
const DEFAULT_TIMEOUT_SECONDS: u64 = 6;
const REQUEST_DELAY_MS: u64 = 20;
const TEST_PORTS: &[u16] = &[443, 2096];

const SHODAN_QUERIES: &[&str] = &[
    "port:80 product:\"CloudFlare\" title:\"Direct IP access not allowed\"",
    "port:443 product:\"CloudFlare\" title:\"Direct IP access not allowed\"",
];

#[derive(Parser, Clone)]
#[command(name = "Shodan Proxy Scanner")]
struct Args {
    #[arg(short, long, default_value = DEFAULT_OUTPUT_FILE)]
    output_file: String,

    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT)]
    max_concurrent: usize,

    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    timeout: u64,
}

#[derive(Debug, Deserialize)]
struct ShodanResponse {
    matches: Vec<ShodanMatch>,
}

#[derive(Debug, Deserialize)]
struct ShodanMatch {
    ip_str: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerCf {
    #[serde(rename = "asOrganization")]
    isp: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Clone)]
struct ProxyInfo {
    ip: String,
    port: u16,
    isp: String,
    country_code: String,
    city: String,
    region: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let api_key = std::env::var("SHODAN_API_KEY")
        .context("SHODAN_API_KEY environment variable not set")?;

    if let Some(parent) = Path::new(&args.output_file).parent() {
        std::fs::create_dir_all(parent).context("Failed to create output directory")?;
    }
    File::create(&args.output_file).context("Failed to create output file")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;

    let mut seen_ips: HashSet<String> = HashSet::new();
    let mut candidate_ips: Vec<String> = Vec::new();

    for query in SHODAN_QUERIES.iter() {
        println!("Querying Shodan: {}", query);
        match fetch_shodan_ips(&client, &api_key, query).await {
            Ok(ips) => {
                println!("  -> {} IPs found", ips.len());
                for ip in ips {
                    if seen_ips.insert(ip.clone()) {
                        candidate_ips.push(ip);
                    }
                }
            }
            Err(e) => {
                println!("  -> query failed: {}", e);
            }
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }

    println!("Total unique candidate IPs to scan: {}", candidate_ips.len());

    let self_ip = fetch_self_ip(&client).await.unwrap_or_else(|_| "0.0.0.0".to_string());
    println!("Your real IP: {}", self_ip);

    let active_proxies = Arc::new(Mutex::new(BTreeMap::<String, Vec<ProxyInfo>>::new()));

    let tasks = futures::stream::iter(candidate_ips.into_iter().map(|ip| {
        let active_proxies = Arc::clone(&active_proxies);
        let self_ip = self_ip.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(REQUEST_DELAY_MS)).await;
            scan_ip(ip, &active_proxies, &self_ip).await;
        }
    }))
    .buffer_unordered(args.max_concurrent)
    .collect::<Vec<()>>();

    tasks.await;

    let locked_proxies = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
    write_markdown_file(&locked_proxies, &args.output_file).context("Failed to write Markdown file")?;

    println!("Scan completed.");
    Ok(())
}

async fn fetch_shodan_ips(client: &Client, api_key: &str, query: &str) -> Result<Vec<String>> {
    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}",
        api_key,
        urlencoding::encode(query)
    );

    let resp = client.get(&url).send().await?;
    let status = resp.status();

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Shodan returned {}: {}", status, body);
    }

    let parsed = resp.json::<ShodanResponse>().await?;
    Ok(parsed.matches.into_iter().map(|m| m.ip_str).collect())
}

async fn fetch_self_ip(client: &Client) -> Result<String> {
    let resp = client.get("https://api.ipify.org").send().await?.text().await?;
    Ok(resp.trim().to_string())
}

async fn check_ip_port(ip: &str, port: u16, self_ip: &str) -> Result<(WorkerCf, u128)> {
    use anyhow::anyhow;
    use native_tls::TlsConnector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_native_tls::TlsConnector as TokioTlsConnector;

    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECONDS);

    let start_ping = Instant::now();
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(format!("{}:{}", ip, port))).await??;

    let tls = TokioTlsConnector::from(TlsConnector::builder().build()?);
    let mut stream = tokio::time::timeout(timeout, tls.connect("speed.cloudflare.com", tcp)).await??;

    let ping = start_ping.elapsed().as_millis();

    let req = concat!(
        "GET /meta HTTP/1.1\r\n",
        "Host: speed.cloudflare.com\r\n",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n",
        "Accept: */*\r\n",
        "Accept-Encoding: identity\r\n",
        "Connection: close\r\n\r\n"
    );

    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    while let Ok(n) = stream.read(&mut tmp).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let text = String::from_utf8_lossy(&buf);
    let body = if let Some(pos) = text.find("\r\n\r\n") {
        &text[pos + 4..]
    } else {
        &text
    };
    let body = body.trim();

    let v: serde_json::Value = serde_json::from_str(body)?;

    let out_ip = v.get("clientIp").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if out_ip.is_empty() || out_ip == self_ip {
        return Err(anyhow!("IP match or empty"));
    }

    Ok((
        WorkerCf {
            isp: v.get("asOrganization").and_then(|v| v.as_str()).map(String::from),
            city: v.get("city").and_then(|v| v.as_str()).map(String::from),
            region: v.get("region").and_then(|v| v.as_str()).map(String::from),
            country: v.get("country").and_then(|v| v.as_str()).map(String::from),
        },
        ping,
    ))
}

async fn scan_ip(ip: String, active_proxies: &Arc<Mutex<BTreeMap<String, Vec<ProxyInfo>>>>, self_ip: &str) {
    for &port in TEST_PORTS.iter() {
        match check_ip_port(&ip, port, self_ip).await {
            Ok((cf, ping)) => {
                let info = ProxyInfo {
                    ip: ip.clone(),
                    port,
                    isp: cf.isp.unwrap_or_else(|| "Unknown".to_string()),
                    country_code: cf.country.unwrap_or_else(|| "XX".to_string()),
                    city: cf.city.unwrap_or_else(|| "Unknown".to_string()),
                    region: cf.region.unwrap_or_else(|| "Unknown".to_string()),
                };

                println!(
                    "{}",
                    format!("PROXY LIVE 🟩: {}:{} ({} ms) - {}", ip, port, ping, info.city).green()
                );

                let mut locked = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
                locked.entry(info.country_code.clone()).or_default().push(info);
                return;
            }
            Err(_) => continue,
        }
    }
    println!("PROXY DEAD ❌: {}", ip);
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

    writeln!(
        file,
        r##"> [!WARNING]
>
> <p><b>Shodan-Discovered Fresh Proxies</b></p>
>
> <img src="https://img.shields.io/badge/Last_Update-{}-966600" />
> <img src="https://img.shields.io/badge/Next_Update-{}-966600" />
> <img src="https://img.shields.io/badge/Active_Proxies-{}-966600" />
> <img src="https://img.shields.io/badge/Countries-{}-966600" />
>
> <br><br/>
"##,
        last_badge_label, next_badge_label, total_active, total_countries,
    )?;

    for (country_code, proxies) in proxies_by_country.iter() {
        let flag = country_flag(country_code);
        let name = get_country_name(country_code);

        writeln!(file, "## {} {} ({} proxies)", flag, name, proxies.len())?;
        writeln!(file, "<details>")?;
        writeln!(file, "<summary>Click to expand</summary>\n")?;
        writeln!(file, "|   IP   |   Port   |   ISP   |   Location   |")?;
        writeln!(file, "|:-------|:--------:|:--------|:------------:|")?;

        for info in proxies.iter() {
            let location = format!("{}, {}", info.region, info.city);
            writeln!(
                file,
                "| <pre><code>{}</code></pre> | {} | {} | {} |",
                info.ip, info.port, info.isp, location
            )?;
        }

        writeln!(file, "\n</details>\n\n---\n")?;
    }

    println!("All active proxies saved to {}", output_file);
    Ok(())
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
        _ => code.to_string(),
    }
}
