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
import {
  RULE_DEFAULTS,
  currentReserveSoc,
  decideChargingActionFromSnapshot,
} from "./ruleEngine.js";

dotenv.config();

// ============================================================================
// Configuration
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8080);
const WEATHER_LAT = process.env.WEATHER_LAT || "37.77";
const WEATHER_LON = process.env.WEATHER_LON || "-122.42";
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
  "openid offline_access vehicle_device_data vehicle_cmds vehicle_charging_cmds energy_device_data energy_cmds";

// Tesla API endpoints
const AUTH_BASE = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3";
const API_BASE = "https://fleet-api.prd.na.vn.cloud.tesla.com";

// OAuth state (for real SaaS: per-session/user)
const STATE = crypto.randomBytes(32).toString("base64url");

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();

app.use(express.json());
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

  /** POST /api/1/vehicles/{id|vin}/command/charge_start */
  async chargeStart(vid) {
    return this.apiPost(`/api/1/vehicles/${vid}/command/charge_start`);
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

  /**
   * Set energy site mode (requires energy_cmds scope).
   * POST /api/1/energy_sites/{id}/operation
   * @param {string} energy_site_id
   * @param {'autonomous'|'self_consumption'} mode - autonomous = Time-Based (TOU), self_consumption = Self-Powered
   */
  async setEnergySiteOperation(energy_site_id, mode) {
    const body = { default_real_mode: mode };
    return this.apiPost(`/api/1/energy_sites/${energy_site_id}/operation`, body);
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

// Public landing page (no auth) for early beta & marketing
app.get("/landing", (req, res) => {
  res.type("html").send(`
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tesla Solar Match — Protect your Powerwall, match EV to solar</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
    .container { max-width: 640px; margin: 0 auto; padding: 2rem 1rem; }
    h1 { font-size: 1.75rem; color: #e31937; margin-bottom: 1rem; }
    h2 { font-size: 1.2rem; color: #555; margin: 1.5rem 0 0.75rem; }
    p { margin-bottom: 1rem; }
    .card { background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }
    .promise { font-size: 1.1rem; font-weight: 600; color: #1b5e20; background: #e8f5e9; padding: 1rem; border-radius: 6px; margin: 1rem 0; }
    .cta { display: inline-block; background: #e31937; color: #fff; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 0.5rem; }
    .cta:hover { opacity: 0.9; }
    .demo-note { font-size: 0.9rem; color: #666; margin-top: 1rem; }
    .footer { margin-top: 2rem; font-size: 0.85rem; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>⚡ Tesla Solar Match</h1>
      <p><strong>The problem:</strong> With Tesla Solar + Powerwall + an EV, your car can drain the battery before peak (4–9pm), or you export solar at low value. You end up buying expensive grid power when you wanted to run on stored solar.</p>
      <p class="promise">Protect your Powerwall and match EV charging to real solar surplus.</p>
      <p>This app uses Tesla Fleet API to read live solar, load, and Powerwall SOC, then automatically stops or throttles your EV charging so you keep enough reserve for peak and only charge the car when there’s real surplus.</p>
    </div>
    <div class="card">
      <h2>See it in action</h2>
      <p>Dashboard shows live SOC, solar, load, and last action (e.g. “Solar surplus 2.2kW → charging at 9A”). Toggle automation on/off and adjust reserves.</p>
      <p class="demo-note">Demo: <a href="/">Log in with Tesla</a> → open Dashboard. (You’ll need a Tesla account with Powerwall + vehicle linked.)</p>
    </div>
    <div class="card">
      <h2>Closed beta</h2>
      <p>We’re looking for 3–5 Powerwall + Tesla vehicle owners to try this for a few weeks and give feedback.</p>
      <a href="/" class="cta">Log in with Tesla → Try the dashboard</a>
    </div>
    <p class="footer">Post in r/TeslaSolar or Tesla Motors Club to offer early access. Onboard beta users via OAuth; set their vehicle/site and reserves manually at first.</p>
  </div>
</body>
</html>
  `);
});

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
          <p><small><a href="/landing">What is this? (Landing page)</a></small></p>
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

app.post("/energy/:siteId/operation", async (req, res) => {
  const siteId = req.params.siteId;
  const mode = req.body?.mode;
  if (mode !== "autonomous" && mode !== "self_consumption") {
    return res.status(400).json({
      error: "Invalid or missing mode",
      required: "mode must be 'autonomous' (Time-Based/TOU) or 'self_consumption' (Self-Powered)",
    });
  }
  try {
    const resp = await teslaApi.setEnergySiteOperation(siteId, mode);
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
      mode,
      body,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
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

async function handleChargeStart(req, res) {
  const vid = req.params.vid;
  try {
    const resp = await teslaApi.chargeStart(vid);
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
}

app.get("/vehicle/:vid/charge_start", handleChargeStart);
app.post("/vehicle/:vid/charge_start", handleChargeStart);

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
      charge_amps: chargeState.charge_amps ?? null,
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

// Rule engine is in ruleEngine.js (decideChargingActionFromSnapshot, RULE_DEFAULTS, currentReserveSoc).

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
      const chargingState = snapshot?.metrics?.charging_state ?? "";
      if (String(chargingState) !== "Charging") {
        const startResp = await teslaApi.chargeStart(snapshot.vehicle.id);
        const startOk = startResp.ok;
        if (!startOk) {
          const startText = await startResp.text();
          commandResult = { ok: false, error: `charge_start failed: ${startText}` };
        } else {
          await new Promise((r) => setTimeout(r, 1500));
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
            charge_started: true,
          };
        }
      } else {
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

    // Extract scopes - Tesla uses 'scp' (array) in JWT payload, fallback to 'scope' (string)
    const scopesArray =
      Array.isArray(decoded.payload?.scp)
        ? decoded.payload.scp
        : decoded.payload?.scope
          ? decoded.payload.scope.split(" ")
          : [];

    return {
      header: decoded.header,
      payload: decoded.payload,
      // Extract useful fields
      scopes: scopesArray,
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
// Scheduler + Rule State Management
// ============================================================================

/**
 * In-memory rule state (for MVP - later move to DB)
 * Tracks enabled state, vehicle/site IDs, reserve settings, and last action
 */
const rule = {
  enabled: false,
  vehicleId: null,
  siteId: null,
  reserveOffPeak: RULE_DEFAULTS.reserveOffPeak,
  reservePeak: RULE_DEFAULTS.reservePeak,
  lastAmps: null,
  lastCommandAt: 0,
  lastAction: "none",
  lastReason: "",
  lastRunAt: 0,
  lastSnapshot: null,
  lastDecision: null,
  lastCommandResult: null,
  errorCount: 0,
  lastError: null,
};

/**
 * Scheduler loop: runs every 60 seconds when rule.enabled is true
 * Applies SOC + TOU rules with guardrails (deadband, throttle, error handling)
 */
let schedulerInterval = null;

async function schedulerLoop() {
  if (!rule.enabled || !teslaApi.tokens) {
    return;
  }

  const now = Date.now();
  rule.lastRunAt = now;

  try {
    // Build live snapshot
    const snapshot = await buildLiveSnapshot({
      requestedVid: rule.vehicleId,
      requestedSiteId: rule.siteId,
    });

    // Decide action using rule engine
    const decision = decideChargingActionFromSnapshot(snapshot, new Date(), {
      reserveOffPeak: rule.reserveOffPeak,
      reservePeak: rule.reservePeak,
      peakStartHour: RULE_DEFAULTS.peakStartHour,
      peakEndHour: RULE_DEFAULTS.peakEndHour,
      minAmps: RULE_DEFAULTS.minAmps,
      maxAmps: RULE_DEFAULTS.maxAmps,
      minSurplusWatts: RULE_DEFAULTS.minSurplusWatts,
      minSolarWatts: RULE_DEFAULTS.minSolarWatts,
      solarHoursStart: RULE_DEFAULTS.solarHoursStart,
      solarHoursEnd: RULE_DEFAULTS.solarHoursEnd,
      voltage: RULE_DEFAULTS.voltage,
    });

    rule.lastSnapshot = snapshot;
    rule.lastDecision = decision;

    // Guardrail 1: Command throttle - don't send commands more than once per minute
    const timeSinceLastCommand = now - rule.lastCommandAt;
    const canSendCommand = timeSinceLastCommand >= 60_000;

    if (!canSendCommand && decision.action === "set_amps") {
      console.log(
        `[scheduler] Skipping command (throttled): last command was ${Math.round(
          timeSinceLastCommand / 1000
        )}s ago`
      );
      rule.lastAction = "throttled";
      rule.lastReason = decision.reason + " (throttled - waiting 60s between commands)";
      return;
    }

    // Guardrail 2: Deadband for set_amps - only change if difference >= 2A
    if (decision.action === "set_amps" && decision.targetAmps != null) {
      if (rule.lastAmps != null && Math.abs(decision.targetAmps - rule.lastAmps) < 2) {
        console.log(
          `[scheduler] Skipping set_amps (deadband): target ${decision.targetAmps}A vs last ${rule.lastAmps}A (diff < 2A)`
        );
        rule.lastAction = "deadband";
        rule.lastReason = decision.reason + " (deadband - change < 2A)";
        return;
      }
    }

    // Execute command
    let commandResult = null;

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
      rule.lastAmps = null;
    } else if (decision.action === "set_amps" && decision.targetAmps != null) {
      const chargingState = snapshot?.metrics?.charging_state ?? "";
      if (String(chargingState) !== "Charging") {
        const startResp = await teslaApi.chargeStart(snapshot.vehicle.id);
        if (!startResp.ok) {
          const startText = await startResp.text();
          commandResult = { ok: false, error: `charge_start failed: ${startText}` };
          rule.lastAction = "error";
          rule.lastReason = `Start charging failed: ${startText}`;
          rule.lastCommandResult = commandResult;
          return;
        }
        await new Promise((r) => setTimeout(r, 1500));
      }
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
      rule.lastAmps = decision.targetAmps;
    }

    rule.lastCommandAt = now;
    rule.lastAction = decision.action;
    rule.lastReason = decision.reason;
    rule.lastCommandResult = commandResult;
    rule.errorCount = 0;
    rule.lastError = null;

    console.log(
      `[scheduler] ${decision.action}: ${decision.reason} | Command result: ${commandResult?.ok ? "OK" : "FAILED"}`
    );
  } catch (e) {
    rule.errorCount++;
    rule.lastError = String(e);
    rule.lastAction = "error";
    rule.lastReason = `Error: ${String(e)}`;
    console.error(`[scheduler] Error in loop:`, e);
  }
}

function startScheduler() {
  if (schedulerInterval) {
    return; // Already running
  }
  console.log("[scheduler] Starting 60s loop...");
  schedulerInterval = setInterval(schedulerLoop, 60_000);
  // Run once immediately
  schedulerLoop();
}

function stopScheduler() {
  if (schedulerInterval) {
    clearInterval(schedulerInterval);
    schedulerInterval = null;
    console.log("[scheduler] Stopped");
  }
}

// ============================================================================
// Rule Management Endpoints
// ============================================================================

app.post("/rules/enable", async (req, res) => {
  try {
    const { vehicleId, siteId, reserveOffPeak, reservePeak } = req.body;

    if (!vehicleId || !siteId) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["vehicleId", "siteId"],
      });
    }

    // Validate vehicle and site exist
    const [vehicles, sites] = await Promise.all([
      teslaApi.getVehicles(),
      teslaApi.getEnergySites(),
    ]);

    const vehicle = vehicles.find(
      (v) => String(v.id) === String(vehicleId) || String(v.vin) === String(vehicleId)
    );
    if (!vehicle) {
      return res.status(404).json({ error: `Vehicle ${vehicleId} not found` });
    }

    const site = sites.find(
      (s) =>
        String(s.id) === String(siteId) ||
        String(s.energy_site_id) === String(siteId)
    );
    if (!site) {
      return res.status(404).json({ error: `Energy site ${siteId} not found` });
    }

    // Update rule state
    rule.enabled = true;
    rule.vehicleId = String(vehicle.id);
    rule.siteId = String(site.energy_site_id);
    if (typeof reserveOffPeak === "number" && reserveOffPeak >= 0 && reserveOffPeak <= 100) {
      rule.reserveOffPeak = reserveOffPeak;
    }
    if (typeof reservePeak === "number" && reservePeak >= 0 && reservePeak <= 100) {
      rule.reservePeak = reservePeak;
    }

    // Reset state
    rule.lastAmps = null;
    rule.lastCommandAt = 0;
    rule.lastAction = "none";
    rule.lastReason = "";
    rule.errorCount = 0;
    rule.lastError = null;

    startScheduler();

    res.json({
      success: true,
      rule: {
        enabled: rule.enabled,
        vehicleId: rule.vehicleId,
        siteId: rule.siteId,
        reserveOffPeak: rule.reserveOffPeak,
        reservePeak: rule.reservePeak,
      },
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.post("/rules/disable", (req, res) => {
  rule.enabled = false;
  stopScheduler();
  res.json({
    success: true,
    message: "Rule disabled and scheduler stopped",
    rule: {
      enabled: rule.enabled,
    },
  });
});

app.get("/rules/status", async (req, res) => {
  try {
    const currentReserve = currentReserveSoc(new Date(), {
      reserveOffPeak: rule.reserveOffPeak,
      reservePeak: rule.reservePeak,
      peakStartHour: RULE_DEFAULTS.peakStartHour,
      peakEndHour: RULE_DEFAULTS.peakEndHour,
    });

    const status = {
      rule: {
        enabled: rule.enabled,
        vehicleId: rule.vehicleId,
        siteId: rule.siteId,
        reserveOffPeak: rule.reserveOffPeak,
        reservePeak: rule.reservePeak,
        currentReserve,
        lastAmps: rule.lastAmps,
        lastAction: rule.lastAction,
        lastReason: rule.lastReason,
        lastRunAt: rule.lastRunAt ? new Date(rule.lastRunAt).toISOString() : null,
        lastCommandAt: rule.lastCommandAt ? new Date(rule.lastCommandAt).toISOString() : null,
        errorCount: rule.errorCount,
        lastError: rule.lastError,
      },
      snapshot: rule.lastSnapshot,
      decision: rule.lastDecision,
      commandResult: rule.lastCommandResult,
    };

    res.json(status);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ============================================================================
// Tomorrow's weather (for Self-Powered vs TOU recommendation)
// ============================================================================

const WEATHER_CACHE_MS = 60 * 60 * 1000; // 1 hour
let weatherCache = { at: 0, data: null };

/**
 * Fetch tomorrow's weather from Open-Meteo (free, no API key).
 * Returns { sunny, summary, recommendation } for NEM 3 strategy:
 * - Sunny tomorrow → use Self-Powered overnight (drain battery; we'll recharge).
 * - Rainy tomorrow → after peak, switch to TOU to conserve battery for the next day.
 */
async function getTomorrowWeather() {
  if (weatherCache.data && Date.now() - weatherCache.at < WEATHER_CACHE_MS) {
    return weatherCache.data;
  }
  try {
    const url = new URL("https://api.open-meteo.com/v1/forecast");
    url.searchParams.set("latitude", WEATHER_LAT);
    url.searchParams.set("longitude", WEATHER_LON);
    url.searchParams.set("daily", "weathercode,precipitation_probability_max");
    url.searchParams.set("timezone", "America/Los_Angeles");
    url.searchParams.set("forecast_days", "2");
    const resp = await fetch(url.toString());
    if (!resp.ok) return { sunny: null, summary: "Unknown", recommendation: "Check weather manually." };
    const json = await resp.json();
    const daily = json.daily;
    if (!daily || !daily.time || daily.time.length < 2) return { sunny: null, summary: "Unknown", recommendation: "Check weather manually." };
    const tomorrowCode = daily.weathercode[1];
    const tomorrowPop = daily.precipitation_probability_max?.[1] ?? 0;
    // WMO codes: 0 clear, 1-3 partly cloudy, 45-48 fog, 51-67 rain/drizzle, 71-77 snow, 80-82 showers, 95-99 thunder
    const rainyCodes = (c) => (c >= 51 && c <= 67) || (c >= 71 && c <= 82) || (c >= 95 && c <= 99);
    const sunny = !rainyCodes(tomorrowCode) && tomorrowPop < 50;
    const summary = sunny ? "Sunny / clear" : rainyCodes(tomorrowCode) ? "Rain or precipitation" : "Cloudy / possible rain";
    const recommendation = sunny
      ? "Use Self-Powered overnight — tomorrow will recharge the battery."
      : "After peak hours, switch to TOU to conserve battery for tomorrow.";
    const data = { sunny, summary, recommendation, weathercode: tomorrowCode, pop: tomorrowPop };
    weatherCache = { at: Date.now(), data };
    return data;
  } catch (e) {
    console.error("[weather]", e);
    return { sunny: null, summary: "Error", recommendation: "Check weather manually." };
  }
}

app.get("/weather/tomorrow", async (req, res) => {
  try {
    const data = await getTomorrowWeather();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get("/dashboard", async (req, res) => {
  if (!teslaApi.tokens) {
    return res.redirect("/");
  }

  try {
    const tomorrowWeather = await getTomorrowWeather();

    // Get current status
    const currentReserve = currentReserveSoc(new Date(), {
      reserveOffPeak: rule.reserveOffPeak,
      reservePeak: rule.reservePeak,
      peakStartHour: RULE_DEFAULTS.peakStartHour,
      peakEndHour: RULE_DEFAULTS.peakEndHour,
    });

    const now = new Date();
    const hour = now.getHours();
    const inPeak = hour >= RULE_DEFAULTS.peakStartHour && hour < RULE_DEFAULTS.peakEndHour;

    // Get latest snapshot (for display and for default vehicle/site when enabling rule)
    let snapshot = rule.lastSnapshot;
    if (!snapshot) {
      try {
        snapshot = await buildLiveSnapshot({
          requestedVid: rule.vehicleId || undefined,
          requestedSiteId: rule.siteId || undefined,
        });
      } catch (e) {
        console.error("[dashboard] Error fetching snapshot:", e);
      }
    }

    const defaultVehicleId = snapshot?.vehicle?.id ?? rule.vehicleId ?? "";
    const defaultSiteId = snapshot?.energy_site?.energy_site_id ?? rule.siteId ?? "";

    const m = snapshot?.metrics || {};
    const soc = m.percentage_charged ?? m.soc ?? null;
    const solarW = m.solar_power ?? null;
    const loadW = m.load_power ?? null;
    const batteryW = m.battery_power ?? null;
    const gridW = m.grid_power ?? null;
    const chargingState = m.charging_state ?? null;
    const chargerAmps = m.charger_actual_current ?? null;

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Tesla Solar Match Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #f5f5f5;
      color: #333;
      line-height: 1.6;
      padding: 1rem;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
    }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 1rem;
      color: #e31937;
    }
    .card {
      background: white;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .card h2 {
      font-size: 1.1rem;
      margin-bottom: 1rem;
      color: #555;
      border-bottom: 2px solid #e31937;
      padding-bottom: 0.5rem;
    }
    .toggle-section {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }
    .toggle-btn {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .toggle-btn.enabled {
      background: #e31937;
      color: white;
    }
    .toggle-btn.disabled {
      background: #ccc;
      color: #666;
    }
    .toggle-btn:hover {
      opacity: 0.9;
      transform: scale(1.02);
    }
    .status-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-top: 1rem;
    }
    .stat {
      text-align: center;
    }
    .stat-label {
      font-size: 0.85rem;
      color: #666;
      margin-bottom: 0.25rem;
    }
    .stat-value {
      font-size: 1.5rem;
      font-weight: 600;
      color: #333;
    }
    .stat-value.good { color: #4caf50; }
    .stat-value.warning { color: #ff9800; }
    .stat-value.danger { color: #f44336; }
    .last-action {
      background: #f9f9f9;
      padding: 1rem;
      border-radius: 6px;
      margin-top: 1rem;
      border-left: 4px solid #e31937;
    }
    .last-action-label {
      font-size: 0.85rem;
      color: #666;
      margin-bottom: 0.5rem;
    }
    .last-action-reason {
      font-size: 0.95rem;
      color: #333;
      line-height: 1.5;
    }
    .config-section {
      margin-top: 1rem;
    }
    .config-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    .config-label {
      font-size: 0.9rem;
      color: #666;
    }
    .config-value {
      font-weight: 600;
      color: #333;
    }
    .peak-badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 12px;
      font-size: 0.8rem;
      font-weight: 600;
      margin-left: 0.5rem;
    }
    .peak-badge.active {
      background: #ff9800;
      color: white;
    }
    .peak-badge.inactive {
      background: #e0e0e0;
      color: #666;
    }
    .error {
      background: #ffebee;
      color: #c62828;
      padding: 1rem;
      border-radius: 6px;
      margin-top: 1rem;
    }
    .link {
      color: #e31937;
      text-decoration: none;
      font-size: 0.9rem;
    }
    .link:hover { text-decoration: underline; }
    @media (max-width: 480px) {
      .status-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ Tesla Solar Match</h1>
    <div class="poll-timer" style="text-align: center; margin-bottom: 1rem; font-size: 0.9rem; color: #666;">
      Next refresh in <strong id="pollCountdown">30</strong>s
    </div>

    <div class="card">
      <h2>Control</h2>
      <div class="toggle-section">
        <span>Automation Status:</span>
        <button id="toggleBtn" class="toggle-btn ${rule.enabled ? "enabled" : "disabled"}" onclick="toggleRule()">
          ${rule.enabled ? "ON" : "OFF"}
        </button>
      </div>
      ${rule.enabled && rule.vehicleId && rule.siteId ? `
        <div class="config-section">
          <div class="config-row">
            <span class="config-label">Vehicle ID:</span>
            <span class="config-value">${escapeHtml(rule.vehicleId)}</span>
          </div>
          <div class="config-row">
            <span class="config-label">Site ID:</span>
            <span class="config-value">${escapeHtml(rule.siteId)}</span>
          </div>
        </div>
      ` : `
        <p style="color: #666; font-size: 0.9rem; margin-top: 1rem;">
          Enable automation and configure vehicle/site via API: <code>POST /rules/enable</code>
        </p>
      `}
    </div>

    <div class="card">
      <h2>Tomorrow's weather</h2>
      <p style="font-size: 0.95rem; color: #555; margin-bottom: 0.5rem;">
        <strong>${tomorrowWeather.summary}</strong>
        ${tomorrowWeather.sunny === true ? " ☀️" : tomorrowWeather.sunny === false ? " 🌧️" : ""}
      </p>
      <p style="font-size: 0.9rem; color: #333; line-height: 1.5; padding: 0.75rem; background: #f5f5f5; border-radius: 6px;">
        ${escapeHtml(tomorrowWeather.recommendation)}
      </p>
    </div>

    <div class="card">
      <h2>Powerwall Status</h2>
      <div class="status-grid">
        <div class="stat">
          <div class="stat-label">SOC</div>
          <div class="stat-value ${soc != null ? (soc < currentReserve ? "danger" : soc < currentReserve + 10 ? "warning" : "good") : ""}">
            ${soc != null ? `${soc.toFixed(1)}%` : "—"}
          </div>
        </div>
        <div class="stat">
          <div class="stat-label">Reserve</div>
          <div class="stat-value">
            ${currentReserve}%
            <span class="peak-badge ${inPeak ? "active" : "inactive"}">
              ${inPeak ? "PEAK" : "OFF-PEAK"}
            </span>
          </div>
        </div>
        <div class="stat">
          <div class="stat-label">Solar</div>
          <div class="stat-value">${solarW != null ? `${(solarW / 1000).toFixed(2)} kW` : "—"}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Load</div>
          <div class="stat-value">${loadW != null ? `${(loadW / 1000).toFixed(2)} kW` : "—"}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Battery</div>
          <div class="stat-value ${batteryW != null ? (batteryW < 0 ? "good" : "danger") : ""}">
            ${batteryW != null ? `${(batteryW / 1000).toFixed(2)} kW` : "—"}
            ${batteryW != null ? (batteryW < 0 ? " (charging)" : batteryW > 0 ? " (discharging)" : "") : ""}
          </div>
        </div>
        <div class="stat">
          <div class="stat-label">Grid</div>
          <div class="stat-value ${gridW != null ? (gridW > 0 ? "danger" : gridW < 0 ? "good" : "") : ""}">
            ${gridW != null ? `${(gridW / 1000).toFixed(2)} kW` : "—"}
            ${gridW != null ? (gridW > 0 ? " (importing)" : gridW < 0 ? " (exporting)" : "") : ""}
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>EV Charging</h2>
      <div class="status-grid">
        <div class="stat">
          <div class="stat-label">State</div>
          <div class="stat-value">${chargingState ? escapeHtml(chargingState) : "—"}</div>
        </div>
        <div class="stat">
          <div class="stat-label">Current Amps</div>
          <div class="stat-value">${chargerAmps != null ? `${chargerAmps}A` : "—"}</div>
        </div>
      </div>
      ${rule.lastAmps != null ? `
        <div style="margin-top: 1rem; padding: 0.75rem; background: #e8f5e9; border-radius: 6px;">
          <strong>Last Set:</strong> ${rule.lastAmps}A
        </div>
      ` : ""}
    </div>

    <div class="card">
      <h2>Last Action</h2>
      <div class="last-action">
        <div class="last-action-label">Action: <strong>${rule.lastAction || "none"}</strong></div>
        <div class="last-action-reason">${rule.lastReason || "No actions taken yet."}</div>
      </div>
      ${rule.lastRunAt ? `
        <div style="margin-top: 0.75rem; font-size: 0.85rem; color: #666;">
          Last run: ${new Date(rule.lastRunAt).toLocaleString()}
        </div>
      ` : ""}
      ${rule.errorCount > 0 ? `
        <div class="error" style="margin-top: 1rem;">
          <strong>Errors:</strong> ${rule.errorCount}
          ${rule.lastError ? `<br><small>${escapeHtml(rule.lastError)}</small>` : ""}
        </div>
      ` : ""}
    </div>

    <div class="card">
      <h2>Configuration</h2>
      <div class="config-section">
        <div class="config-row">
          <span class="config-label">Off-Peak Reserve:</span>
          <span class="config-value">${rule.reserveOffPeak}%</span>
        </div>
        <div class="config-row">
          <span class="config-label">Peak Reserve:</span>
          <span class="config-value">${rule.reservePeak}%</span>
        </div>
        <div class="config-row">
          <span class="config-label">Peak Hours:</span>
          <span class="config-value">${RULE_DEFAULTS.peakStartHour}:00 - ${RULE_DEFAULTS.peakEndHour}:00</span>
        </div>
      </div>
    </div>

    <div style="text-align: center; margin-top: 2rem; padding: 1rem;">
      <a href="/" class="link">← Back to Account</a> |
      <a href="/rules/status" class="link">JSON Status</a>
    </div>
  </div>

  <script>
    const RULE_CONFIG = {
      vehicleId: ${JSON.stringify(rule.vehicleId || defaultVehicleId)},
      siteId: ${JSON.stringify(rule.siteId || defaultSiteId)},
    };

    async function toggleRule() {
      const btn = document.getElementById('toggleBtn');
      const isEnabled = btn.classList.contains('enabled');
      const vehicleId = RULE_CONFIG.vehicleId || '';
      const siteId = RULE_CONFIG.siteId || '';
      if (!isEnabled && (!vehicleId || !siteId)) {
        alert('Cannot enable: no vehicle or energy site selected. Refresh the page to load defaults.');
        return;
      }

      try {
        const response = await fetch(isEnabled ? '/rules/disable' : '/rules/enable', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            vehicleId,
            siteId,
          }),
        });

        const data = await response.json();
        if (data.success || data.error) {
          setTimeout(() => window.location.reload(), 500);
        } else if (!response.ok) {
          alert(data.error || 'Request failed');
        }
      } catch (e) {
        alert('Error toggling rule: ' + e.message);
      }
    }

    // Polling: countdown timer and refresh every 30 seconds
    const POLL_INTERVAL_SEC = 30;
    let secondsLeft = POLL_INTERVAL_SEC;
    const countdownEl = document.getElementById('pollCountdown');
    const pollTimer = setInterval(() => {
      secondsLeft--;
      if (countdownEl) countdownEl.textContent = Math.max(0, secondsLeft);
      if (secondsLeft <= 0) {
        clearInterval(pollTimer);
        window.location.reload();
      }
    }, 1000);
  </script>
</body>
</html>`;

    res.type("html").send(html);
  } catch (e) {
    res.status(500).type("html").send(`<h1>Error</h1><pre>${escapeHtml(String(e))}</pre>`);
  }
});

// ============================================================================
// Server Startup
// ============================================================================

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Open: http://localhost:${PORT}/ (or your ngrok URL)`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard`);
});
