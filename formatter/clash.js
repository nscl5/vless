import {
  safeFetch,
  isInIgnoredRange,
  generateRandomPath,
  buildMainDomains,
  buildSubscriptionHeaders,
  CONST,
  SENS,
} from "./core.js";

const GENERAL_TEMPLATE = `port: 7890
socks-port: 7891
mixed-port: 10801
ipv6: false
allow-lan: true
mode: rule
log-level: warning
disable-keep-alive: false
keep-alive-idle: 10
keep-alive-interval: 15
unified-delay: true
geo-auto-update: false
external-ui: /path/to/ui/folder/
external-controller-unix: mihomo.sock
external-ui-name: xd
external-controller: 0.0.0.0:9093
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
external-controller-cors:
  allow-origins:
    - '*'
  allow-private-network: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  respect-rules: true
  use-system-hosts: false
  nameserver:
    - https://8.8.8.8/dns-query
    - https://94.140.14.14/dns-query
    - https://208.67.222.222/dns-query
  default-nameserver:
    - 8.8.8.8
    - 223.5.5.5
    - system
  nameserver-policy:
    raw.githubusercontent.com: 8.8.8.8
    time.apple.com: 8.8.8.8
    www.gstatic.com: system
  proxy-server-nameserver:
    - 8.8.8.8
    - 223.5.5.5
  fallback:
    - tls://1.1.1.1
    - tcp://8.8.8.8
    - udp://223.5.5.5
    - tls://dns.quad9.net
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - geosite:private
tun:
  enable: true
  stack: system
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53
  mtu: 9000
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports:
        - 80
        - 8080
        - 8880
        - 2052
        - 2082
        - 2086
        - 2095
    TLS:
      ports:
        - 443
        - 8443
        - 2053
        - 2083
        - 2087
        - 2096
`;

function clashProxyBlock({ name, server, port, uuid, hostName, tls }) {
  const path = generateRandomPath(18);
  const lines = [
    `  - name: ${name}`,
    `    type: ${SENS.vless()}`,
    `    server: ${server}`,
    `    port: ${port}`,
    `    uuid: ${uuid}`,
    `    tls: ${tls}`,
  ];
  if (tls) lines.push(`    servername: ${hostName}`, `    alpn:`, `      - http/1.1`);
  lines.push(
    `    client-fingerprint: chrome`,
    `    network: ${SENS.ws()}`,
    `    ${SENS.wsOpts()}`,
    `      path: ${path}`,
    `      headers:`,
    `        host: ${hostName}`,
    `      max-early-data: ${CONST.ED_PARAMS.ed}`,
    `      ${SENS.edLine()}${CONST.ED_PARAMS.eh}`,
    `    udp: true`,
  );
  if (tls) lines.push(`    skip-cert-verify: true`);
  return lines.join("\n");
}

export async function handleClashConfig(request, userID, hostName, ctx) {
  const url = new URL(request.url);
  const subName = url.searchParams.get("name");
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const isPagesDeployment = hostName.endsWith(".pages.dev");

  const proxies = [];
  const names = [];

  const addPair = (label, server, includeTcp = true) => {
    proxies.push(
      clashProxyBlock({
        name: `${label}-TLS`,
        server,
        port: pick(httpsPorts),
        uuid: userID,
        hostName,
        tls: true,
      }),
    );
    names.push(`${label}-TLS`);
    if (includeTcp && !isPagesDeployment) {
      proxies.push(
        clashProxyBlock({
          name: `${label}-TCP`,
          server,
          port: pick(httpPorts),
          uuid: userID,
          hostName,
          tls: false,
        }),
      );
      names.push(`${label}-TCP`);
    }
  };

  buildMainDomains(hostName).forEach((domain, i) => addPair(`Domain${i + 1}`, domain, false));

  try {
    const cache = caches.default;
    const cacheKey = new Request("https://cf-ip-cache.local");
    let response = await cache.match(cacheKey);
    if (!response) {
      const r = await safeFetch(
        "https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json",
        {},
        4000,
      );
      if (r.ok) {
        response = new Response(await r.text(), {
          headers: { "Cache-Control": "public, max-age=86400" },
        });
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
      }
    }
    if (response) {
      const json = await response.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])]
        .map((x) => x.ip)
        .filter((v) => !isInIgnoredRange(v))
        .slice(0, 20);
      ips.forEach((ip, i) => addPair(`IP${i + 1}`, ip.includes(":") ? `[${ip}]` : ip));
    }
  } catch (e) {
    console.error("Clash IP fetch failed", e);
  }

  const groupList = names.map((n) => `      - ${n}`).join("\n");

  const yaml = `${GENERAL_TEMPLATE}proxies:
${proxies.join("\n")}
proxy-groups:
  - name: ⚪ 0x00
    type: select
    proxies:
      - 🟢 AUTO
      - DIRECT
${groupList}
  - name: 🟢 AUTO
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 180
    tolerance: 50
    proxies:
${groupList}
rules:
  - MATCH,⚪ 0x00
ntp:
  enable: true
  server: time.apple.com
  port: 123
  interval: 30
`;

  return new Response(yaml, {
    headers: {
      "Content-Type": "text/yaml; charset=utf-8",
      ...buildSubscriptionHeaders(subName),
    },
  });
}
