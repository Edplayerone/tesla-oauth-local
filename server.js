/**
 * Tesla Fleet OAuth + Vehicles Viewer (Node.js / Express)
 *
 * What this does:
 * - GET /                  -> shows "Login with Tesla" until tokens exist, then lists vehicles
 * - GET /auth/callback     -> OAuth callback, exchanges code for tokens
 * - GET /vehicle/:vid      -> wakes vehicle if needed, then renders vehicle_data as HTML table
 * - GET /energy/:siteId/live -> returns energy site live status data
 * - GET /.well-known/appspecific/:filename -> serves public key file(s) for Tesla verification
 *
 * Notes:
 * - This is a straight port of your Flask example (in-memory token storage).
 * - For SaaS/real use, store tokens per-user in a DB and encrypt refresh tokens.
 *
 * Setup:
 * 1) npm i express node-fetch dotenv
 * 2) Create .env (see template below)
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

dotenv.config();

// ============================================================================
// Configuration
// ============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8080);
const CLIENT_ID = process.env.CLIENT_ID || "9bf3e8c49c96-4d67-93fd-9a315163c7a6-tesla-client-id";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "ta-secret.l5ooh5vPYoBdeqeD";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "https://mouldiest-phillis-nonspurious.ngrok-free.dev/auth/callback";
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
      throw new Error(`Refresh failed: ${resp.status} ${JSON.stringify(json)}`);
    }

    json.obtained_at = Math.floor(Date.now() / 1000);
    this.tokens = { ...this.tokens, ...json };
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

  async apiPost(pathname) {
    await this.ensureValid();
    const resp = await fetch(`${API_BASE}${pathname}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.tokens.access_token}` },
    });
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

  // Energy site methods
  async getEnergySites() {
    const resp = await this.apiGet("/api/1/products");
    try {
      const json = await resp.json();
      return json?.response.filter((s) => s.device_type === "energy") || [];
    } catch {
      return [];
    }
  }

  async getEnergyLiveStatus(energy_site_id) {
    const resp = await this.apiGet(`/api/1/energy_sites/${energy_site_id}/live_status`);
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
        <h1>Tesla Fleet</h1>
        <p><a href="${url}">Login with Tesla</a></p>
        <p style="color:#666;font-family:Arial">State (debug): ${teslaApi.state}</p>
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
          `<p>Site ID: ${s.id} - Energy Site ID: <a href="/energy/${s.energy_site_id}/live">${s.energy_site_id}</a></p>`
      )
      .join("");

    res.type("html").send(`
      <h1>Your Vehicles</h1>
      ${listHtml || "<p>No vehicles found.</p>"}
      <h1>Energy Sites</h1>
      ${siteHtml || "<p>No energy sites found.</p>"}
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
