import { connect } from "cloudflare:sockets";
import { processHeader } from "../pkg/zr_wasm.js";
import { CONST, safeFetch } from "./core.js";

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

async function resolveIPv4(hostname) {
  if (IPV4_REGEX.test(hostname)) return hostname;
  try {
    const resp = await safeFetch(
      `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      { headers: { accept: "application/dns-json" } },
      4000,
    );
    const data = await resp.json();
    const answer = (data.Answer || []).find((a) => a.type === 1);
    return answer ? answer.data : null;
  } catch (error) {
    return null;
  }
}

function toNAT64Address(ipv4) {
  if (!ipv4 || !IPV4_REGEX.test(ipv4)) return null;
  const octets = ipv4.split(".").map(Number);
  if (octets.some((n) => n < 0 || n > 255)) return null;
  const hex = octets.map((n) => n.toString(16).padStart(2, "0"));
  return `64:ff9b::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

function parsePathOverrides(url) {
  const overrides = {};
  for (const [rawKey, rawValue] of url.searchParams) {
    const key = rawKey.toLowerCase();
    if (key === "nat64") {
      overrides.nat64 = rawValue.toLowerCase() === "on";
    } else if (key === "proxyip" || key === "proxyips") {
      overrides.proxyPool = rawValue
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return overrides;
}

export function parseHostAndPort(addr, defaultPort = 443) {
  if (!addr) return { host: "", port: defaultPort };
  const str = String(addr).trim();
  if (str.startsWith("[")) {
    const closeBracketIdx = str.indexOf("]");
    if (closeBracketIdx !== -1) {
      const host = str.slice(1, closeBracketIdx);
      const rest = str.slice(closeBracketIdx + 1);
      const port = rest.startsWith(":") ? parseInt(rest.slice(1), 10) || defaultPort : defaultPort;
      return { host, port };
    }
  }
  const lastColon = str.lastIndexOf(":");
  if (lastColon !== -1 && str.indexOf(":") === lastColon) {
    const host = str.slice(0, lastColon);
    const port = parseInt(str.slice(lastColon + 1), 10) || defaultPort;
    return { host, port };
  }
  if (lastColon !== -1) {
    return { host: str, port: defaultPort };
  }
  return { host: str, port: defaultPort };
}

export function formatConnectHost(address) {
  if (!address) return "";
  const host = String(address).trim();
  if (host.includes(":") && !host.startsWith("[")) {
    return `[${host}]`;
  }
  return host;
}

export async function ProtocolOverWSHandler(request, config) {
  const overrides = parsePathOverrides(new URL(request.url));
  config = { ...config, ...overrides };

  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  let udpStreamWriter = null;

  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };

  const earlyDataHeader = request.headers.get(CONST.ED_PARAMS.eh) || "";
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = { value: null };

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWriter) return udpStreamWriter.write(chunk);
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const header = processHeader(new Uint8Array(chunk), config.userID);
          if (header.has_error) throw new Error(header.message);

          address = header.address_remote;
          portWithRandomLog = `${header.port_remote}--${Math.random()} ${header.is_udp ? "udp" : "tcp"} `;
          const vlessResponseHeader = new Uint8Array([header.version, 0]);
          const rawClientData = chunk.slice(header.raw_data_index);

          if (header.is_udp) {
            if (header.port_remote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log);
              udpStreamWriter = dnsPipeline.write;
              udpStreamWriter(rawClientData);
            } else {
              log(`udp:${header.port_remote} not supported (dns-only), closing gently`);
              safeCloseWebSocket(webSocket);
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWapper,
            header.address_remote,
            header.port_remote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
          );
        },
        close() {
          log(`readableWebSocketStream closed`);
        },
        abort(err) {
          log(`readableWebSocketStream aborted`, err);
        },
      }),
    )
    .catch((err) => {
      console.error("Pipeline failed:", err.stack || err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function HandleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
) {
  async function connectAndWrite(address, port) {
    const formattedHost = formatConnectHost(address);
    const tcpSocket = connect({ hostname: formattedHost, port: Number(port) });
    remoteSocket.value = tcpSocket;
    log(`connected to ${formattedHost}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retryWithPool(pool, index) {
    if (index >= pool.length) {
      await retryWithNAT64();
      return;
    }
    const { host: proxyHost, port: proxyPort } = parseHostAndPort(pool[index], 443);
    const tcpSocket = await connectAndWrite(proxyHost, proxyPort);
    tcpSocket.closed
      .catch((error) => console.log("proxy tcpSocket closed error", error))
      .finally(() => safeCloseWebSocket(webSocket));
    RemoteSocketToWS(
      tcpSocket,
      webSocket,
      protocolResponseHeader,
      () => retryWithPool(pool, index + 1),
      log,
    );
  }

  async function retryWithNAT64() {
    if (config.nat64 === false) {
      safeCloseWebSocket(webSocket);
      return;
    }
    const ipv4 = await resolveIPv4(addressRemote);
    const nat64Address = toNAT64Address(ipv4);
    if (!nat64Address) {
      log(`NAT64 fallback failed: could not resolve ${addressRemote}`);
      safeCloseWebSocket(webSocket);
      return;
    }
    log(`falling back to NAT64: ${nat64Address}`);
    const tcpSocket = await connectAndWrite(nat64Address, portRemote);
    tcpSocket.closed
      .catch((error) => console.log("NAT64 tcpSocket closed error", error))
      .finally(() => safeCloseWebSocket(webSocket));
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(
    tcpSocket,
    webSocket,
    protocolResponseHeader,
    () => retryWithPool(config.proxyPool || [], 0),
    log,
  );
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) {},
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let hasIncomingData = false;
  let headerSent = false;

  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error("WebSocket is not open");
          hasIncomingData = true;

          let dataToSend = chunk;
          if (!headerSent && protocolResponseHeader) {
            const merged = new Uint8Array(protocolResponseHeader.length + chunk.byteLength);
            merged.set(protocolResponseHeader, 0);
            merged.set(new Uint8Array(chunk), protocolResponseHeader.length);
            dataToSend = merged.buffer;
            headerSent = true;
          }

          webSocket.send(dataToSend);
        },
        close() {
          log(`Remote connection readable closed.`);
        },
        abort(reason) {
          console.error(`Remote connection readable aborted:`, reason);
        },
      }),
    );
  } catch (error) {
    console.error(`RemoteSocketToWS error:`, error.stack || error);
    safeCloseWebSocket(webSocket);
  }

  if (!hasIncomingData && retry) {
    log(`No incoming data, retrying`);
    await retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, "+").replace(/_/g, "/"));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) view[i] = binaryStr.charCodeAt(i);
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    )
      socket.close();
  } catch (error) {
    console.error("safeCloseWebSocket error:", error);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await safeFetch(
              `https://1.1.1.1/dns-query`,
              {
                method: "POST",
                headers: { "content-type": "application/dns-message" },
                body: chunk,
              },
              4000,
            );
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              if (isHeaderSent) {
                webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              } else {
                webSocket.send(
                  await new Blob([
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsQueryResult,
                  ]).arrayBuffer(),
                );
                isHeaderSent = true;
              }
            }
          } catch (error) {
            log("DNS query error: " + error);
          }
        },
      }),
    )
    .catch((e) => log("DNS stream error: " + e));

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}
