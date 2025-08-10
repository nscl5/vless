import fs from 'fs';
import path from 'path';
import net from 'net';
import http from 'http';
import https from 'https';
import { performance } from 'perf_hooks';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const CONFIG = {
  timeout: 5000,
  testUrl: 'https://www.google.com',
  maxRetries: 2,
  delayBetweenRequests: 1000,
  portsToCheck: [80, 443, 8080, 3128, 8888],
};

async function testHttpProxy(proxyHost, proxyPort) {
  return new Promise(resolve => {
    const options = {
      host: proxyHost,
      port: proxyPort,
      path: CONFIG.testUrl,
      timeout: CONFIG.timeout,
    };

    const req = http.get(options, res => {
      resolve({ success: res.statusCode === 200 });
      req.destroy();
    });

    req.on('error', () => resolve({ success: false }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false });
    });
  });
}

async function testHttpsProxy(proxyHost, proxyPort) {
  return new Promise(resolve => {
    const options = {
      host: proxyHost,
      port: proxyPort,
      path: CONFIG.testUrl,
      timeout: CONFIG.timeout,
    };

    const req = https.get(options, res => {
      resolve({ success: res.statusCode === 200 });
      req.destroy();
    });

    req.on('error', () => resolve({ success: false }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false });
    });
  });
}

async function testSocksProxy(proxyHost, proxyPort) {
  return { success: false };
}

async function validateProxy(proxyHost, proxyPort) {
  try {
    const results = await Promise.all([
      testHttpProxy(proxyHost, proxyPort),
      testHttpsProxy(proxyHost, proxyPort),
      testSocksProxy(proxyHost, proxyPort),
    ]);

    return results.some(result => result.success);
  } catch (e) {
    return false;
  }
}

async function getIpInfo(ip) {
  try {
    const services = [
      `http://ip-api.com/json/${ip}?fields=status,country,city,as`,
      `https://ipinfo.io/${ip}/json?token=${process.env.IPINFO_TOKEN || ''}`,
    ];

    for (const url of services) {
      try {
        const response = await fetch(url);
        if (response.ok) {
          const data = await response.json();
          if (data.status === 'success' || data.ip) {
            return {
              status: 'success',
              country: data.country || data.country_name,
              city: data.city,
              as: data.as || data.org,
            };
          }
        }
      } catch (e) {
        continue;
      }
      await new Promise(res => setTimeout(res, 1000));
    }
    return { status: 'fail' };
  } catch (e) {
    return { status: 'fail' };
  }
}

async function main() {
  try {
    const chunkIndex = parseInt(process.env.CHUNK_INDEX, 10);
    const totalChunks = parseInt(process.env.TOTAL_CHUNKS, 10);

    const proxyFilePath = path.join(__dirname, '../sub/country_proxies/02_proxies.csv');
    const rawContent = fs.readFileSync(proxyFilePath, 'utf-8');

    const proxies = [];
    const lines = rawContent.split(/\r?\n/);

    for (const line of lines) {
      if (!line || line.startsWith('IP Address')) continue;
      const parts = line.trim().split(',');
      if (parts.length >= 2) {
        const ip = parts[0].trim();
        const port = parseInt(parts[1].trim(), 10);
        if (ip && !isNaN(port)) {
          proxies.push({ ip, port });
        }
      }
    }

    const chunkSize = Math.ceil(proxies.length / totalChunks);
    const startIndex = chunkIndex * chunkSize;
    const endIndex = startIndex + chunkSize;
    const proxiesToCheck = proxies.slice(startIndex, endIndex);

    console.log(
      `Testing ${proxiesToCheck.length} proxies in chunk ${chunkIndex + 1}/${totalChunks}`,
    );

    const workingProxies = [];
    for (const proxy of proxiesToCheck) {
      for (let attempt = 1; attempt <= CONFIG.maxRetries; attempt++) {
        try {
          const isValid = await validateProxy(proxy.ip, proxy.port);
          if (isValid) {
            const info = await getIpInfo(proxy.ip);
            if (info.status === 'success') {
              workingProxies.push({
                ip: proxy.ip,
                port: proxy.port,
                ...info,
              });
            }
            break;
          }
        } catch (e) {
          console.error(`Error testing ${proxy.ip}:${proxy.port}`, e);
        }
        await new Promise(res => setTimeout(res, CONFIG.delayBetweenRequests));
      }
    }

    console.log(`Found ${workingProxies.length} working proxies in chunk ${chunkIndex + 1}`);

    if (workingProxies.length > 0) {
      const output = workingProxies.map(p => JSON.stringify(p)).join('\n') + '\n';
      fs.writeFileSync('working_proxies_partial.txt', output);
    }
  } catch (error) {
    console.error('Main error:', error);
    process.exit(1);
  }
}

main();
