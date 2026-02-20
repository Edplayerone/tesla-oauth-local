/**
 * Tesla Fleet OAuth + Vehicles Viewer (Node.js / Express)
 *
 * OAuth Flow:
 * 1. User visits / -> redirected to Tesla Fleet OAuth authorize endpoint
 * 2. User authorizes -> Tesla redirects to /auth/callback with authorization code
 * 3. Server exchanges code for access_token + refresh_token
 * 4. Access token is a JWT containing scopes and user info
 * 5. Refresh token is used to obtain new access tokens when they expire
 *
 * Required Scopes:
 * - openid: OpenID Connect authentication
 * - offline_access: Refresh token for long-lived sessions
 * - vehicle_device_data: Read vehicle telemetry
 * - vehicle_cmds: Send vehicle commands
 * - vehicle_charging_cmds: Control EV charging
 * - energy_device_data: Read energy site data (solar/Powerwall)
 *
 * Endpoints:
 * - GET /                  -> shows "Login with Tesla" until tokens exist, then lists vehicles
 * - GET /auth/callback     -> OAuth callback, exchanges code for tokens
 * - GET /auth/token-info   -> Debug endpoint to inspect JWT token claims
 * - GET /vehicle/:vid      -> wakes vehicle if needed, then renders vehicle_data as HTML table
 * - GET /energy/:siteId/live -> returns energy site live status data
 * - GET /.well-known/appspecific/:filename -> serves public key file(s) for Tesla verification
 *
 * Notes:
 * - This uses in-memory token storage (single user, single session).
 * - For SaaS/real use, store tokens per-user in a DB and encrypt refresh tokens.
 * - OAuth state is generated once at startup (for production, use per-session state).
 *
 * Setup:
 * 1) npm i express node-fetch dotenv jsonwebtoken
 * 2) Create .env with CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SCOPES
 * 3) node server.js
 * 4) If using ngrok: ngrok http 8080, set REDIRECT_URI to https://<ngrok>/auth/callback
 */

// ============================================================================
// Imports
// ============================================================================

import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";

dotenv.config();

// ============================================================================
// Configuration
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8080);
const CLIENT_ID = process.env.CLIENT_ID || "9bf3e8c49c96-4d67-93fd-9a315163c7a6";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "ta-secret.l5ooh5vPYoBdeqeD";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "https://mouldiest-phillis-nonspurious.ngrok-free.dev/auth/callback";
/**
 * Tesla Fleet API OAuth Scopes
 * 
 * Required scopes for this application:
 * - openid: OpenID Connect authentication
 * - offline_access: Allows obtaining refresh tokens for long-lived sessions
 * - vehicle_device_data: Read vehicle telemetry (battery level, charging state, etc.)
 * - vehicle_cmds: Send vehicle commands (wake up, etc.)
 * - vehicle_charging_cmds: Control EV charging (stop, set amps)
 * - energy_device_data: Read energy site data (solar, Powerwall, grid status)
 * 
 * These scopes provide both vehicle and energy access as required.
 */
const SCOPES =
  process.env.SCOPES ||
  "openid offline_access vehicle_device_data vehicle_cmds vehicle_charging_cmds energy_device_data";

// Tesla API endpoints
const AUTH_BASE = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3";
const API_BASE = "https://fleet-api.prd.na.vn.cloud.tesla.com";

// OAuth state (for real SaaS: per-session/user)
const STATE = crypto.randomBytes(32).toString("base64url");

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();

app.use(
  "/.well-known/appspecific",
  express.static(path.join(process.cwd(), ".well-known", "appspecific"))
);

// ============================================================================
// TeslaAPI Class
// ============================================================================

class TeslaAPI {
  constructor({ clientId, clientSecret, redirectUri, scopes, state }) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.scopes = scopes;
    this.tokens = null; // {access_token, refresh_token, expires_in, obtained_at, ...}
    this.state = state;
  }

  valid() {
    if (!this.tokens) return false;
    const now = Math.floor(Date.now() / 1000);
    const obtainedAt = this.tokens.obtained_at || 0;
    const expiresIn = this.tokens.expires_in || 0;
    // Consider token invalid within 60s of expiry
    return now - obtainedAt < expiresIn - 60;
  }

  async refresh() {
    if (!this.tokens?.refresh_token) {
      throw new Error("No refresh_token available. Re-login.");
    }

    console.log("[TeslaAPI] Refreshing access token...");

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: this.tokens.refresh_token,
    });

    const resp = await fetch(`${AUTH_BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const json = await resp.json();
    if (!resp.ok) {
      console.error("[TeslaAPI] Token refresh failed:", resp.status, json);
      throw new Error(`Refresh failed: ${resp.status} ${JSON.stringify(json)}`);
    }

    json.obtained_at = Math.floor(Date.now() / 1000);
    this.tokens = { ...this.tokens, ...json };

    // Log new token claims
    if (json.access_token) {
      const claims = decodeTokenClaims(json.access_token);
      console.log("[TeslaAPI] Token refreshed successfully");
      console.log("[TeslaAPI] New token expires at:", claims?.expiresAt || "unknown");
    }
  }

  async ensureValid() {
    if (!this.valid()) {
      await this.refresh();
    }
  }

  async apiGet(pathname) {
    await this.ensureValid();
    const resp = await fetch(`${API_BASE}${pathname}`, {
      headers: { Authorization: `Bearer ${this.tokens.access_token}` },
    });
    return resp;
  }

  async apiPost(pathname, body) {
    await this.ensureValid();
    const headers = { Authorization: `Bearer ${this.tokens.access_token}` };
    const options = { method: "POST", headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const resp = await fetch(`${API_BASE}${pathname}`, options);
    return resp;
  }

  // Vehicle methods
  async getVehicles() {
    const resp = await this.apiGet("/api/1/vehicles");
    try {
      const json = await resp.json();
      return json?.response || [];
    } catch {
      return [];
    }
  }

  async getVehicleState(vid) {
    const vehicles = await this.getVehicles();
    const v = vehicles.find((x) => String(x?.id) === String(vid));
    return v?.state ?? null;
  }

  async wakeUpVehicle(vid) {
    return this.apiPost(`/api/1/vehicles/${vid}/wake_up`);
  }

  async getVehicleData(vid) {
    return this.apiGet(`/api/1/vehicles/${vid}/vehicle_data`);
  }

  async getVehicleDataJson(vid) {
    const resp = await this.getVehicleData(vid);
    const text = await resp.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`Error parsing vehicle_data JSON: ${text.slice(0, 500)}`);
    }
    if (!resp.ok) {
      const error = json?.error || "";
      const isUnavailable =
        resp.status === 408 ||
        (typeof error === "string" && error.toLowerCase().includes("vehicle unavailable"));

      if (isUnavailable) {
        return {
          _unavailable: {
            status: resp.status,
            error,
            error_description: json?.error_description ?? "",
          },
        };
      }

      throw new Error(
        `vehicle_data failed with status ${resp.status}: ${JSON.stringify(json).slice(0, 500)}`
      );
    }
    return json?.response || null;
  }

  async chargeStop(vid) {
    return this.apiPost(`/api/1/vehicles/${vid}/command/charge_stop`);
  }

  async setChargingAmps(vid, amps) {
    const charging_amps = Number(amps);
    return this.apiPost(`/api/1/vehicles/${vid}/command/set_charging_amps`, {
      charging_amps,
    });
  }

  // Energy site methods
  async getEnergySites() {
    const resp = await this.apiGet("/api/1/products");
    try {
      const json = await resp.json();
      return (
        json?.response.filter(
          (s) => s.device_type === "energy" && s.resource_type === "battery"
        ) || []
      );
    } catch {
      return [];
    }
  }

  async getEnergyLiveStatus(energy_site_id) {
    const resp = await this.apiGet(`/api/1/energy_sites/${energy_site_id}/live_status`);
    const json = await resp.json();
    return json?.response;
  }

  async getEnergySiteInfo(energy_site_id) {
    const resp = await this.apiGet(`/api/1/energy_sites/${energy_site_id}/site_info`);
    const json = await resp.json();
    return json?.response;
  }
}

const teslaApi = new TeslaAPI({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
  scopes: SCOPES,
  state: STATE,
});

// ============================================================================
// Routes
// ============================================================================

app.get("/", async (req, res) => {
  try {
    if (!teslaApi.tokens) {
      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: SCOPES,
        state: teslaApi.state,
      });

      const url = `${AUTH_BASE}/authorize?${params.toString()}`;

      res.type("html").send(`
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8" />
          <title>Tesla Fleet OAuth</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 2em auto; padding: 1em; }
            h1 { color: #333; }
            .info { background: #f0f0f0; padding: 1em; border-radius: 4px; margin: 1em 0; }
            .info code { background: #fff; padding: 2px 4px; border-radius: 2px; }
            a { color: #e31937; text-decoration: none; font-weight: bold; }
            a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <h1>Tesla Fleet OAuth</h1>
          <p><a href="${url}">Login with Tesla</a></p>
          <div class="info">
            <p><strong>OAuth Configuration:</strong></p>
            <p>Redirect URI: <code>${REDIRECT_URI}</code></p>
            <p>Scopes: <code>${SCOPES}</code></p>
            <p>State (CSRF protection): <code>${teslaApi.state}</code></p>
          </div>
          <p><small>After login, visit <a href="/auth/token-info">/auth/token-info</a> to inspect token claims.</small></p>
        </body>
        </html>
      `);
      return;
    }

    const cars = await teslaApi.getVehicles();
    const sites = await teslaApi.getEnergySites();

    const listHtml = cars
      .map(
        (c) =>
          `<p><a href="/vehicle/${c.id}">${escapeHtml(c.display_name || "Vehicle")} (${escapeHtml(
            c.vin || ""
          )})</a></p>`
      )
      .join("");

    const siteHtml = sites
      .map(
        (s) =>
          `<p>Site ID: ${s.id} - Energy Site ID: <a href="/energy/${s.energy_site_id}/live">${s.energy_site_id}</a> | <a href="/energy/${s.energy_site_id}/site_info">Site Info</a></p>`
      )
      .join("");

    // Get token info for display
    const tokenClaims = teslaApi.tokens?.access_token
      ? decodeTokenClaims(teslaApi.tokens.access_token)
      : null;
    const tokenInfoHtml = tokenClaims
      ? `
        <div style="background:#e8f5e9;padding:1em;border-radius:4px;margin:1em 0;">
          <p><strong>Authentication Status:</strong> ✓ Authenticated</p>
          <p>Token expires: ${tokenClaims.expiresAt || "unknown"}</p>
          <p>Scopes: <code>${tokenClaims.scopes?.join(", ") || "none"}</code></p>
          <p><a href="/auth/token-info">View full token info</a></p>
        </div>
      `
      : "";

    res.type("html").send(`
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8" />
        <title>Your Tesla Account</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 2em auto; padding: 1em; }
          h1 { color: #333; }
          code { background: #f0f0f0; padding: 2px 4px; border-radius: 2px; }
        </style>
      </head>
      <body>
        ${tokenInfoHtml}
        <h1>Your Vehicles</h1>
        ${listHtml || "<p>No vehicles found.</p>"}
        <h1>Energy Sites</h1>
        ${siteHtml || "<p>No energy sites found.</p>"}
      </body>
      </html>
    `);
  } catch (e) {
    res.status(500).type("html").send(`<h1>Error</h1><pre>${escapeHtml(String(e))}</pre>`);
  }
});

app.get("/auth/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res
        .status(400)
        .type("html")
        .send(`<h1>Tesla OAuth Error</h1><pre>${escapeHtml(JSON.stringify(req.query, null, 2))}</pre>`);
    }

    const state = String(req.query.state || "");
    if (state !== teslaApi.state) {
      return res.status(400).type("html").send("<h1>Invalid state parameter (possible CSRF)</h1>");
    }

    const code = req.query.code ? String(req.query.code) : "";
    if (!code) {
      return res.status(400).type("html").send(`<pre>${escapeHtml(JSON.stringify(req.query))}</pre>`);
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: REDIRECT_URI,
    });

    const tokenResp = await fetch(`${AUTH_BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const text = await tokenResp.text();
    let tokenJson;
    try {
      tokenJson = JSON.parse(text);
    } catch {
      tokenJson = null;
    }

    if (!tokenResp.ok) {
      return res
        .status(400)
        .type("html")
        .send(`<h1>Token Exchange Failed</h1><pre>${escapeHtml(text)}</pre>`);
    }

    tokenJson.obtained_at = Math.floor(Date.now() / 1000);
    teslaApi.tokens = { ...(teslaApi.tokens || {}), ...tokenJson };

    // Decode and log token claims for debugging
    if (tokenJson.access_token) {
      const claims = decodeTokenClaims(tokenJson.access_token);
      console.log("[auth/callback] Token obtained successfully");
      console.log("[auth/callback] Token claims:", JSON.stringify(claims, null, 2));
      
      // Verify required scopes are present
      if (claims?.scopes) {
        const requiredScopes = ["vehicle_device_data", "vehicle_cmds", "vehicle_charging_cmds", "energy_device_data"];
        const missingScopes = requiredScopes.filter(
          (scope) => !claims.scopes.includes(scope)
        );
        if (missingScopes.length > 0) {
          console.warn(
            `[auth/callback] WARNING: Missing scopes: ${missingScopes.join(", ")}`
          );
        } else {
          console.log("[auth/callback] All required scopes present ✓");
        }
      }
    }

    return res.redirect("/");
  } catch (e) {
    res.status(500).type("html").send(`<h1>Error</h1><pre>${escapeHtml(String(e))}</pre>`);
  }
});

app.get("/vehicle/:vid", async (req, res) => {
  const vid = req.params.vid;

  try {
    // Check vehicle exists and state
    const state = await teslaApi.getVehicleState(vid);
    if (state == null) {
      return res.status(404).type("html").send("<h2>Vehicle not found in account.</h2>");
    }

    // Wake vehicle if needed
    if (state !== "online") {
      const wakeResp = await teslaApi.wakeUpVehicle(vid);
      let wakeDataText = await wakeResp.text();
      let wakeData;
      try {
        wakeData = JSON.parse(wakeDataText);
      } catch {
        wakeData = wakeDataText;
      }

      // Poll for online status up to 5 times
      let online = false;
      for (let attempt = 0; attempt < 5; attempt++) {
        await sleep(2000);
        const pollState = await teslaApi.getVehicleState(vid);
        if (pollState === "online") {
          online = true;
          break;
        }
      }

      if (!online) {
        return res
          .status(500)
          .type("html")
          .send(
            `<h2>Vehicle did not wake up after several attempts.</h2><pre>${escapeHtml(
              JSON.stringify(wakeData, null, 2)
            )}</pre>`
          );
      }
    }

    // Fetch vehicle data
    const dataResp = await teslaApi.getVehicleData(vid);
    const raw = await dataResp.text();
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return res
        .status(500)
        .type("html")
        .send(`<h2>Error parsing vehicle data response:</h2><pre>${escapeHtml(raw)}</pre>`);
    }

    const vehicleInfo = data?.response || {};
    const tableRows = renderDict(vehicleInfo);

    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Vehicle Data</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f8f8f8; }
    table { border-collapse: collapse; width: 80%; margin: 2em auto; background: #fff; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; }
    th { background: #eee; }
    tr:nth-child(even) { background: #f2f2f2; }
    h2 { text-align: center; }
    .top { width:80%; margin: 0 auto; color:#555; }
  </style>
</head>
<body>
  <div class="top">
    <p><a href="/">← Back</a></p>
  </div>
  <h2>Vehicle Data</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    ${tableRows.join("")}
  </table>
</body>
</html>`;

    res.type("html").send(html);
  } catch (e) {
    res.status(500).type("html").send(`<h2>Error</h2><pre>${escapeHtml(String(e))}</pre>`);
  }
});

app.get("/energy/:siteId/live", async (req, res) => {
  try {
    const data = await teslaApi.getEnergyLiveStatus(req.params.siteId);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get("/energy/:siteId/site_info", async (req, res) => {
  try {
    const data = await teslaApi.getEnergySiteInfo(req.params.siteId);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/**
 * Debug endpoint to inspect current access token claims
 * GET /auth/token-info
 * 
 * Returns JWT header, payload, scopes, expiration, and other useful info
 */
app.get("/auth/token-info", (req, res) => {
  if (!teslaApi.tokens?.access_token) {
    return res.status(401).json({
      error: "Not authenticated",
      message: "Visit / to login with Tesla first",
    });
  }

  const claims = decodeTokenClaims(teslaApi.tokens.access_token);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = teslaApi.tokens.obtained_at + teslaApi.tokens.expires_in;
  const expiresIn = expiresAt - now;

  res.json({
    hasToken: true,
    tokenExpiresIn: expiresIn,
    tokenExpiresAt: new Date(expiresAt * 1000).toISOString(),
    tokenObtainedAt: new Date(teslaApi.tokens.obtained_at * 1000).toISOString(),
    tokenValid: teslaApi.valid(),
    claims,
    configuredScopes: SCOPES.split(" "),
  });
});

app.get("/vehicle/:vid/stop", async (req, res) => {
  const vid = req.params.vid;
  try {
    const resp = await teslaApi.chargeStop(vid);
    const text = await resp.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    res.status(resp.ok ? 200 : resp.status).json({
      ok: resp.ok,
      status: resp.status,
      body,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ============================================================================
// Live Snapshot Helper (shared by debug + rule engine)
// ============================================================================

async function buildLiveSnapshot({ requestedVid, requestedSiteId }) {
  const [vehicles, sites] = await Promise.all([
    teslaApi.getVehicles(),
    teslaApi.getEnergySites(),
  ]);

  if (!vehicles.length) {
    throw new Error("No vehicles found for this account.");
  }

  if (!sites.length) {
    throw new Error("No energy sites with resource_type=battery found for this account.");
  }

  const vehicle =
    (requestedVid &&
      vehicles.find(
        (v) => String(v.id) === String(requestedVid) || String(v.vin) === String(requestedVid)
      )) ||
    vehicles[0];

  const site =
    (requestedSiteId &&
      sites.find(
        (s) =>
          String(s.id) === String(requestedSiteId) ||
          String(s.energy_site_id) === String(requestedSiteId)
      )) ||
    sites[0];

  const [energyLive, vehicleInfo] = await Promise.all([
    teslaApi.getEnergyLiveStatus(site.energy_site_id),
    teslaApi.getVehicleDataJson(vehicle.id),
  ]);

  const vehicleUnavailable =
    vehicleInfo && typeof vehicleInfo === "object" && "_unavailable" in vehicleInfo
      ? vehicleInfo._unavailable
      : null;

  const chargeState =
    !vehicleUnavailable && vehicleInfo && typeof vehicleInfo === "object"
      ? vehicleInfo.charge_state || {}
      : {};

  return {
    vehicle: {
      id: vehicle.id,
      vin: vehicle.vin,
      display_name: vehicle.display_name,
      unavailable: vehicleUnavailable,
    },
    energy_site: {
      id: site.id,
      energy_site_id: site.energy_site_id,
      site_name: site.site_name,
    },
    metrics: {
      soc: chargeState.battery_level ?? null,
      solar_power: energyLive?.solar_power ?? null,
      load_power: energyLive?.load_power ?? null,
      battery_power: energyLive?.battery_power ?? null,
      grid_power: energyLive?.grid_power ?? null,
      percentage_charged: energyLive?.percentage_charged ?? null,
      charging_state: chargeState.charging_state ?? null,
      charger_power: chargeState.charger_power ?? null,
      charger_actual_current: chargeState.charger_actual_current ?? null,
      charger_voltage: chargeState.charger_voltage ?? null,
    },
  };
}

app.get("/debug/live", async (req, res) => {
  if (!teslaApi.tokens) {
    return res.status(401).json({ error: "Not authenticated. Visit / to login with Tesla first." });
  }

  try {
    const requestedVid = req.query.vid || req.query.vehicleId;
    const requestedSiteId = req.query.siteId || req.query.energy_site_id;

    const snapshot = await buildLiveSnapshot({ requestedVid, requestedSiteId });
    res.json(snapshot);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get("/vehicle/:vid/set_amps/:amps", async (req, res) => {
  const vid = req.params.vid;
  const rawAmps = Number(req.params.amps);
  if (!Number.isFinite(rawAmps)) {
    return res.status(400).json({ ok: false, error: "Invalid amps value" });
  }

  const minAmps = 5;
  const maxAmps = 32;
  const targetAmps = Math.max(minAmps, Math.min(maxAmps, Math.round(rawAmps)));

  try {
    const resp = await teslaApi.setChargingAmps(vid, targetAmps);
    const text = await resp.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    res.status(resp.ok ? 200 : resp.status).json({
      ok: resp.ok,
      status: resp.status,
      requested_amps: rawAmps,
      applied_amps: targetAmps,
      body,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ============================================================================
// SOC + TOU Rule Engine
// ============================================================================

const RULE_DEFAULTS = {
  reserveOffPeak: 40,
  reservePeak: 70,
  peakStartHour: 16,
  peakEndHour: 21,
  minAmps: 5,
  maxAmps: 32,
  minSurplusWatts: 500,
  voltage: 240,
};

function currentReserveSoc(now = new Date(), options = {}) {
  const cfg = { ...RULE_DEFAULTS, ...options };
  const hour = now.getHours();
  const inPeak = hour >= cfg.peakStartHour && hour < cfg.peakEndHour;
  return inPeak ? cfg.reservePeak : cfg.reserveOffPeak;
}

function wattsToAmps(surplusW, voltage) {
  if (!Number.isFinite(surplusW) || !Number.isFinite(voltage) || voltage <= 0) {
    return 0;
  }
  return surplusW / voltage;
}

function decideChargingActionFromSnapshot(snapshot, now = new Date(), options = {}) {
  const cfg = { ...RULE_DEFAULTS, ...options };
  const m = snapshot?.metrics || {};

  const soc = typeof m.soc === "number" ? m.soc : null;
  const solar = typeof m.solar_power === "number" ? m.solar_power : null;
  const load = typeof m.load_power === "number" ? m.load_power : null;
  const batteryPower = typeof m.battery_power === "number" ? m.battery_power : null;

  const reserve = currentReserveSoc(now, cfg);

  // If vehicle is unavailable, play it safe and stop charging.
  if (snapshot?.vehicle?.unavailable) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW: null,
      reason: "Vehicle unavailable; issuing charge_stop to be safe.",
    };
  }

  // If we are missing critical telemetry, choose safe default: stop charging.
  if (soc == null || solar == null || load == null || batteryPower == null) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW: null,
      reason: "Missing critical telemetry (SOC/solar/load/battery); issuing charge_stop.",
    };
  }

  const surplusW = Math.max(0, solar - load);

  // Rule 1: Protect Powerwall reserve SOC
  if (soc < reserve) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW,
      reason: `SOC ${soc}% is below reserve ${reserve}%; stopping EV charge.`,
    };
  }

  // Rule 2: Do not allow EV to drain Powerwall (battery discharging)
  // When batteryPower < 0, the Powerwall is discharging (providing power).
  // This happens when solar production < house load, meaning there isn't enough
  // solar to cover current energy use. The Powerwall is making up the shortfall.
  // If we allowed EV charging in this situation, it would add more load and
  // further drain the Powerwall, reducing the battery reserve we need for
  // peak hours (4-9pm). Therefore, we stop EV charging to preserve the Powerwall.
  if (batteryPower < 0) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW,
      reason: `Battery power ${batteryPower}W < 0 (discharging); stopping EV charge to avoid draining Powerwall.`,
    };
  }

  // Rule 3: Require meaningful solar surplus
  if (surplusW < cfg.minSurplusWatts) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW,
      reason: `Solar surplus ${surplusW}W is below minimum ${cfg.minSurplusWatts}W; stopping EV charge.`,
    };
  }

  // Rule 4: Use surplus to set charging amps
  const rawAmps = wattsToAmps(surplusW, cfg.voltage);
  const targetAmps = Math.max(cfg.minAmps, Math.min(cfg.maxAmps, Math.round(rawAmps)));

  return {
    action: "set_amps",
    targetAmps,
    reserveSoc: reserve,
    surplusW,
    reason: `Using solar surplus ${surplusW}W (~${rawAmps.toFixed(
      1
    )}A) to set charging to ${targetAmps}A.`,
  };
}

async function runChargingRuleOnce({ requestedVid, requestedSiteId, now = new Date(), options = {} }) {
  if (!teslaApi.tokens) {
    throw new Error("Not authenticated. Visit / to login with Tesla first.");
  }

  const snapshot = await buildLiveSnapshot({ requestedVid, requestedSiteId });
  const decision = decideChargingActionFromSnapshot(snapshot, now, options);

  let commandResult = null;

  try {
    if (decision.action === "charge_stop") {
      const resp = await teslaApi.chargeStop(snapshot.vehicle.id);
      const text = await resp.text();
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      commandResult = { ok: resp.ok, status: resp.status, body };
    } else if (decision.action === "set_amps" && decision.targetAmps != null) {
      const resp = await teslaApi.setChargingAmps(snapshot.vehicle.id, decision.targetAmps);
      const text = await resp.text();
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      commandResult = {
        ok: resp.ok,
        status: resp.status,
        requested_amps: decision.targetAmps,
        body,
      };
    }
  } catch (e) {
    commandResult = { ok: false, error: String(e) };
  }

  console.log(
    "[soc-tou-rule-engine]",
    JSON.stringify(
      {
        vehicle_id: snapshot.vehicle.id,
        energy_site_id: snapshot.energy_site.energy_site_id,
        decision,
        commandResult,
      },
      null,
      2
    )
  );

  return { snapshot, decision, commandResult };
}

// One-shot endpoint to exercise the rule engine manually.
app.get("/rules/run-once", async (req, res) => {
  try {
    const requestedVid = req.query.vid || req.query.vehicleId;
    const requestedSiteId = req.query.siteId || req.query.energy_site_id;
    const { snapshot, decision, commandResult } = await runChargingRuleOnce({
      requestedVid,
      requestedSiteId,
    });
    res.json({ snapshot, decision, commandResult });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ============================================================================
// JWT Token Decoding
// ============================================================================

/**
 * Decode and inspect JWT access token claims (without verification)
 * Useful for debugging and confirming scopes/permissions
 */
function decodeTokenClaims(accessToken) {
  if (!accessToken || typeof accessToken !== "string") {
    return null;
  }

  try {
    // Decode without verification (we just want to inspect claims)
    const decoded = jwt.decode(accessToken, { complete: true });
    if (!decoded) {
      return null;
    }

    return {
      header: decoded.header,
      payload: decoded.payload,
      // Extract useful fields
      scopes: decoded.payload?.scope?.split(" ") || [],
      expiresAt: decoded.payload?.exp
        ? new Date(decoded.payload.exp * 1000).toISOString()
        : null,
      issuedAt: decoded.payload?.iat
        ? new Date(decoded.payload.iat * 1000).toISOString()
        : null,
      subject: decoded.payload?.sub || null,
    };
  } catch (e) {
    console.error("[decodeTokenClaims] Error:", e);
    return { error: String(e) };
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function escapeHtml(str) {
  return str
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderDict(obj, parentKey = "") {
  const rows = [];
  if (!obj || typeof obj !== "object") return rows;

  for (const [k, v] of Object.entries(obj)) {
    const key = parentKey ? `${parentKey}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      rows.push(...renderDict(v, key));
    } else {
      const val = Array.isArray(v) ? JSON.stringify(v) : String(v);
      rows.push(`<tr><td>${escapeHtml(key)}</td><td>${escapeHtml(val)}</td></tr>`);
    }
  }
  return rows;
}

// ============================================================================
// Server Startup
// ============================================================================

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Open: http://localhost:${PORT}/ (or your ngrok URL)`);
});
