use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use chrono_tz::Asia::Tehran;
use futures::stream::{self, StreamExt};
use native_tls::TlsConnector as NativeTlsConnector;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_native_tls::TlsConnector;

const CF_API: &str = "https://api.cloudflare.com/client/v4/ips";
const CF_HOST: &str = "cloudflare.com";
const CF_PATH: &str = "/cdn-cgi/trace";

const IPV4_SAMPLES_PER_RANGE: usize = 120;
const IPV4_OUTPUT_COUNT: usize = 25;
const IPV6_OUTPUT_COUNT: usize = 25;
const CONCURRENCY: usize = 100;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct CloudflareApiResponse {
    success: bool,
    result: CloudflareRanges,
}

#[derive(Debug, Deserialize)]
struct CloudflareRanges {
    ipv4_cidrs: Vec<String>,
    ipv6_cidrs: Vec<String>,
}

#[derive(Debug, Clone)]
struct TestResult {
    ip: IpAddr,
    latency: u64,
    colo: String,
}

#[derive(Debug, Serialize)]
struct IpRecord {
    colo: String,
    ip: String,
    latency: u64,
    line: String,
    loss: u8,
    node: String,
    speed: u64,
    time: String,
}

#[derive(Debug, Serialize)]
struct CloudflareOutput {
    ipv4: Vec<IpRecord>,
    ipv6: Vec<IpRecord>,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Fetching Cloudflare IP ranges...");

    let ranges = fetch_ranges().await?;

    println!("\nCloudflare IPv4 ranges:");
    for range in &ranges.ipv4_cidrs {
        println!("{}", range);
    }

    println!(
        "Loaded {} IPv4 ranges and {} IPv6 ranges.",
        ranges.ipv4_cidrs.len(),
        ranges.ipv6_cidrs.len()
    );

    let ipv4_candidates = generate_ipv4_candidates(&ranges.ipv4_cidrs)?;
    println!("Generated {} IPv4 candidates.", ipv4_candidates.len());

    let ipv4_results = scan_ipv4(ipv4_candidates).await;

    println!(
        "IPv4: {} candidates passed TCP + TLS + HTTP.",
        ipv4_results.len()
    );

    let ipv4_results = ipv4_results
        .into_iter()
        .take(IPV4_OUTPUT_COUNT)
        .collect::<Vec<_>>();

    if ipv4_results.is_empty() {
        return Err(anyhow!("No working IPv4 addresses found."));
    }

    let ipv6_results = generate_ipv6_candidates(&ranges.ipv6_cidrs)?;
    println!("Generated {} IPv6 addresses.", ipv6_results.len());

    let ipv4_records = ipv4_results
        .iter()
        .map(|result| make_record(result))
        .collect::<Vec<_>>();

    let ipv6_records = ipv6_results
        .iter()
        .map(|ip| make_ipv6_record(*ip))
        .collect::<Vec<_>>();

    write_json("sub/Cf-ipv4.json", &ipv4_records)?;
    write_json("sub/Cf-ipv6.json", &ipv6_records)?;

    let output = CloudflareOutput {
        ipv4: ipv4_records,
        ipv6: ipv6_records,
    };

    write_json("Cloudflare-IPs.json", &output)?;

    println!();
    println!("Cloudflare-IPs.json updated successfully.");
    println!("IPv4: {}", output.ipv4.len());
    println!("IPv6: {}", output.ipv6.len());

    Ok(())
}

async fn fetch_ranges() -> Result<CloudflareRanges> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent("CFScanner/1.0")
        .build()?;

    let response = client.get(CF_API).send().await?;
    let status = response.status();

    if !status.is_success() {
        return Err(anyhow!(
            "Cloudflare IP API returned HTTP {}",
            status
        ));
    }

    let body = response.json::<CloudflareApiResponse>().await?;

    if !body.success {
        return Err(anyhow!("Cloudflare IP API returned success=false"));
    }

    Ok(body.result)
}

fn generate_ipv4_candidates(ranges: &[String]) -> Result<Vec<Ipv4Addr>> {
    let mut rng = rand::thread_rng();
    let mut candidates = HashSet::new();

    for cidr in ranges {
        let (network, prefix) = parse_ipv4_cidr(cidr)?;
        let network = u32::from(network);
        let host_bits = 32u32 - prefix as u32;
        let host_count = 1u64 << host_bits;

        for _ in 0..IPV4_SAMPLES_PER_RANGE {
            let offset = if host_count > 2 {
                rng.gen_range(1..host_count - 1)
            } else {
                0
            };

            let address = network.wrapping_add(offset as u32);
            candidates.insert(Ipv4Addr::from(address));
        }
    }

    Ok(candidates.into_iter().collect())
}

fn generate_ipv6_candidates(ranges: &[String]) -> Result<Vec<Ipv6Addr>> {
    let mut rng = rand::thread_rng();
    let mut candidates = HashSet::new();

    while candidates.len() < IPV6_OUTPUT_COUNT {
        let cidr = &ranges[rng.gen_range(0..ranges.len())];
        let (network, prefix) = parse_ipv6_cidr(cidr)?;

        let base = u128::from(network);
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix as u32)
        };

        let random_bits = rng.gen::<u128>();
        let address = Ipv6Addr::from((base & mask) | (random_bits & !mask));

        candidates.insert(address);
    }

    Ok(candidates.into_iter().collect())
}

async fn scan_ipv4(candidates: Vec<Ipv4Addr>) -> Vec<TestResult> {
    stream::iter(candidates)
        .map(|ip| async move {
            match timeout(TEST_TIMEOUT, test_ipv4(ip)).await {
                Ok(Ok(result)) => Some(result),
                _ => None,
            }
        })
        .buffer_unordered(CONCURRENCY)
        .filter_map(|result| async move { result })
        .collect()
        .await
}

async fn test_ipv4(ip: Ipv4Addr) -> Result<TestResult> {
    let total_start = Instant::now();
    let address = SocketAddr::new(IpAddr::V4(ip), 443);

    let tcp_start = Instant::now();
    let stream = TcpStream::connect(address).await?;
    let tcp_ms = tcp_start.elapsed().as_millis();

    let native_connector = NativeTlsConnector::builder()
        .danger_accept_invalid_certs(false)
        .build()?;

    let connector = TlsConnector::from(native_connector);

    let tls_start = Instant::now();
    let mut stream = connector.connect(CF_HOST, stream).await?;
    let tls_ms = tls_start.elapsed().as_millis();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: CFScanner/1.0\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        CF_PATH, CF_HOST
    );

    stream.write_all(request.as_bytes()).await?;

    let http_start = Instant::now();
    let mut response = Vec::with_capacity(8192);
    stream
        .take(16384)
        .read_to_end(&mut response)
        .await?;
    let http_ms = http_start.elapsed().as_millis();

    let response = String::from_utf8_lossy(&response);

    if !is_successful_http_response(&response) {
        return Err(anyhow!("HTTP validation failed for {}", ip));
    }

    if !response
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("cf-ray:"))
    {
        return Err(anyhow!("Missing CF-Ray header for {}", ip));
    }

    let colo = response
        .split("\r\n\r\n")
        .nth(1)
        .and_then(parse_colo)
        .unwrap_or_else(|| "Default".to_string());

    let total_ms = total_start.elapsed().as_millis() as u64;

    println!(
        "OK {:<15} total={}ms tcp={}ms tls={}ms http={}ms colo={}",
        ip, total_ms, tcp_ms, tls_ms, http_ms, colo
    );

    Ok(TestResult {
        ip: IpAddr::V4(ip),
        latency: total_ms,
        colo,
    })
}

fn is_successful_http_response(response: &str) -> bool {
    let Some(status_line) = response.lines().next() else {
        return false;
    };

    let mut parts = status_line.split_whitespace();

    let _version = parts.next();

    let Some(status) = parts.next() else {
        return false;
    };

    let Ok(status) = status.parse::<u16>() else {
        return false;
    };

    (200..400).contains(&status)
}

fn parse_colo(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("colo="))
        .map(str::trim)
        .filter(|colo| !colo.is_empty())
        .map(ToOwned::to_owned)
}

fn make_record(result: &TestResult) -> IpRecord {
    IpRecord {
        colo: result.colo.clone(),
        ip: result.ip.to_string(),
        latency: result.latency,
        line: "CF".to_string(),
        loss: 0,
        node: "CFScanner".to_string(),
        speed: 0,
        time: current_tehran_time(),
    }
}

fn make_ipv6_record(ip: Ipv6Addr) -> IpRecord {
    IpRecord {
        colo: "Default".to_string(),
        ip: ip.to_string(),
        latency: 0,
        line: "CF".to_string(),
        loss: 0,
        node: "CFScanner".to_string(),
        speed: 0,
        time: current_tehran_time(),
    }
}

fn current_tehran_time() -> String {
    let now: DateTime<Utc> = Utc::now();

    now.with_timezone(&Tehran)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid IPv4 CIDR: {}", cidr))?;

    let address = address.parse::<Ipv4Addr>()?;
    let prefix = prefix.parse::<u8>()?;

    if prefix > 32 {
        return Err(anyhow!("Invalid IPv4 prefix: {}", prefix));
    }

    Ok((address, prefix))
}

fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u8)> {
    let (address, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("Invalid IPv6 CIDR: {}", cidr))?;

    let address = address.parse::<Ipv6Addr>()?;
    let prefix = prefix.parse::<u8>()?;

    if prefix > 128 {
        return Err(anyhow!("Invalid IPv6 prefix: {}", prefix));
    }

    Ok((address, prefix))
}

fn write_json<T: Serialize>(path: &str, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(path, format!("{}\n", json))?;
    Ok(())
}
