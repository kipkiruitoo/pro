import { s as setResponseStatus, a as send, g as getRequestWebStream, r as readRawBody, b as getProxyRequestHeaders, c as sendProxy, d as getHeader, e as setHeader, f as defineEventHandler, i as isPreflightRequest, h as handleCors, j as getQuery, u as useRuntimeConfig, k as setResponseHeaders } from './nitro/node-server.mjs';
import { jwtVerify, SignJWT } from 'jose';
import 'node:http';
import 'node:https';
import 'fs';
import 'path';
import 'node:fs';
import 'node:url';

async function sendJson(ops) {
  var _a;
  setResponseStatus(ops.event, (_a = ops.status) != null ? _a : 200);
  await send(ops.event, JSON.stringify(ops.data, null, 2), "application/json");
}

const PayloadMethods = /* @__PURE__ */ new Set(["PATCH", "POST", "PUT", "DELETE"]);
function mergeHeaders(defaults, ...inputs) {
  const _inputs = inputs.filter(Boolean);
  if (_inputs.length === 0) {
    return defaults;
  }
  const merged = new Headers(defaults);
  for (const input of _inputs) {
    if (input.entries) {
      for (const [key, value] of input.entries()) {
        if (value !== void 0) {
          merged.set(key, value);
        }
      }
    } else {
      for (const [key, value] of Object.entries(input)) {
        if (value !== void 0) {
          merged.set(key, value);
        }
      }
    }
  }
  return merged;
}
async function specificProxyRequest(event, target, opts = {}) {
  var _a, _b, _c;
  let body;
  let duplex;
  if (PayloadMethods.has(event.method)) {
    if (opts.streamRequest) {
      body = getRequestWebStream(event);
      duplex = "half";
    } else {
      body = await readRawBody(event, false).catch(() => void 0);
    }
  }
  const method = ((_a = opts.fetchOptions) == null ? void 0 : _a.method) || event.method;
  const oldHeaders = getProxyRequestHeaders(event);
  (_b = opts.blacklistedHeaders) == null ? void 0 : _b.forEach((header) => {
    const keys = Object.keys(oldHeaders).filter(
      (v) => v.toLowerCase() === header.toLowerCase()
    );
    keys.forEach((k) => delete oldHeaders[k]);
  });
  const fetchHeaders = mergeHeaders(
    oldHeaders,
    (_c = opts.fetchOptions) == null ? void 0 : _c.headers,
    opts.headers
  );
  const headerObj = Object.fromEntries([...fetchHeaders.entries()]);
  if (process.env.REQ_DEBUG === "true") {
    console.log({
      type: "request",
      method,
      url: target,
      headers: headerObj
    });
  }
  return sendProxy(event, target, {
    ...opts,
    fetchOptions: {
      method,
      body,
      duplex,
      ...opts.fetchOptions,
      headers: fetchHeaders
    }
  });
}

function hasBody(event) {
  const method = event.method.toUpperCase();
  return ["PUT", "POST", "PATCH", "DELETE"].includes(method);
}
async function getBodyBuffer(event) {
  if (!hasBody(event))
    return;
  return await readRawBody(event, false);
}

const headerMap = {
  "X-Cookie": "Cookie",
  "X-Referer": "Referer",
  "X-Origin": "Origin",
  "X-User-Agent": "User-Agent",
  "X-X-Real-Ip": "X-Real-Ip"
};
const blacklistedHeaders = [
  "cf-connecting-ip",
  "cf-worker",
  "cf-ray",
  "cf-visitor",
  "cf-ew-via",
  "cdn-loop",
  "x-amzn-trace-id",
  "cf-ipcountry",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "forwarded",
  "x-real-ip",
  "content-length",
  ...Object.keys(headerMap)
];
function copyHeader(headers, outputHeaders, inputKey, outputKey) {
  var _a;
  if (headers.has(inputKey))
    outputHeaders.set(outputKey, (_a = headers.get(inputKey)) != null ? _a : "");
}
function getProxyHeaders(headers) {
  const output = new Headers();
  output.set(
    "User-Agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0"
  );
  Object.entries(headerMap).forEach((entry) => {
    copyHeader(headers, output, entry[0], entry[1]);
  });
  return output;
}
function getAfterResponseHeaders(headers, finalUrl) {
  var _a;
  if (headers.has("Set-Cookie"))
    (_a = headers.get("Set-Cookie")) != null ? _a : "";
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Expose-Headers": "*",
    Vary: "Origin",
    "X-Final-Destination": finalUrl
  };
}
function getBlacklistedHeaders() {
  return blacklistedHeaders;
}

function getIp(event) {
  const value = getHeader(event, "CF-Connecting-IP");
  if (!value)
    throw new Error(
      "Ip header not found, turnstile only works on cloudflare workers"
    );
  return value;
}

var _a, _b;
const turnstileSecret = (_a = process.env.TURNSTILE_SECRET) != null ? _a : null;
const jwtSecret = (_b = process.env.JWT_SECRET) != null ? _b : null;
const tokenHeader = "X-Token";
const jwtPrefix = "jwt|";
const turnstilePrefix = "turnstile|";
function isTurnstileEnabled() {
  return !!turnstileSecret && !!jwtSecret;
}
async function makeToken(ip) {
  if (!jwtSecret)
    throw new Error("Cannot make token without a secret");
  return await new SignJWT({ ip }).setProtectedHeader({ alg: "HS256" }).setExpirationTime("10m").sign(new TextEncoder().encode(jwtSecret));
}
function setTokenHeader(event, token) {
  setHeader(event, tokenHeader, token);
}
async function createTokenIfNeeded(event) {
  if (!isTurnstileEnabled())
    return null;
  if (!jwtSecret)
    return null;
  const token = event.headers.get(tokenHeader);
  if (!token)
    return null;
  if (!token.startsWith(turnstilePrefix))
    return null;
  return await makeToken(getIp(event));
}
async function isAllowedToMakeRequest(event) {
  if (!isTurnstileEnabled())
    return true;
  const token = event.headers.get(tokenHeader);
  if (!token)
    return false;
  if (!jwtSecret || !turnstileSecret)
    return false;
  if (token.startsWith(jwtPrefix)) {
    const jwtToken = token.slice(jwtPrefix.length);
    let jwtPayload = null;
    try {
      const jwtResult = await jwtVerify(
        jwtToken,
        new TextEncoder().encode(jwtSecret),
        {
          algorithms: ["HS256"]
        }
      );
      jwtPayload = jwtResult.payload;
    } catch {
    }
    if (!jwtPayload)
      return false;
    if (getIp(event) !== jwtPayload.ip)
      return false;
    return true;
  }
  if (token.startsWith(turnstilePrefix)) {
    const turnstileToken = token.slice(turnstilePrefix.length);
    const formData = new FormData();
    formData.append("secret", turnstileSecret);
    formData.append("response", turnstileToken);
    formData.append("remoteip", getIp(event));
    const result = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        body: formData,
        method: "POST"
      }
    );
    const outcome = await result.json();
    return outcome.success;
  }
  return false;
}

const index = defineEventHandler(async (event) => {
  if (isPreflightRequest(event))
    return handleCors(event, {});
  const destination = getQuery(event).destination;
  if (!destination)
    return await sendJson({
      event,
      status: 200,
      data: {
        message: `Proxy is working as expected (v${useRuntimeConfig(event).version})`
      }
    });
  if (!await isAllowedToMakeRequest(event))
    return await sendJson({
      event,
      status: 401,
      data: {
        error: "Invalid or missing token"
      }
    });
  const body = await getBodyBuffer(event);
  const token = await createTokenIfNeeded(event);
  try {
    await specificProxyRequest(event, destination, {
      blacklistedHeaders: getBlacklistedHeaders(),
      fetchOptions: {
        redirect: "follow",
        headers: getProxyHeaders(event.headers),
        body
      },
      onResponse(outputEvent, response) {
        const headers = getAfterResponseHeaders(response.headers, response.url);
        setResponseHeaders(outputEvent, headers);
        if (token)
          setTokenHeader(event, token);
      }
    });
  } catch (e) {
    console.log("Error fetching", e);
    throw e;
  }
});

export { index as default };
//# sourceMappingURL=index.mjs.map
