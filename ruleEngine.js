/**
 * SOC + TOU rule engine: decides EV charging action from solar/load/Powerwall snapshot.
 * Pure logic, no I/O. Used by server.js and by tests.
 */

export const RULE_DEFAULTS = {
  reserveOffPeak: 40,
  reservePeak: 40,
  peakStartHour: 16,
  peakEndHour: 21,
  minAmps: 5,
  maxAmps: 32,
  minAmpsWhenSurplus: 1,
  minSurplusWatts: 500,
  minSolarWatts: 100,
  solarHoursStart: 6,
  solarHoursEnd: 20,
  voltage: 240,
};

export function currentReserveSoc(now = new Date(), options = {}) {
  const cfg = { ...RULE_DEFAULTS, ...options };
  const hour = now.getHours();
  const inPeak = hour >= cfg.peakStartHour && hour < cfg.peakEndHour;
  return inPeak ? cfg.reservePeak : cfg.reserveOffPeak;
}

export function wattsToAmps(surplusW, voltage) {
  if (!Number.isFinite(surplusW) || !Number.isFinite(voltage) || voltage <= 0) {
    return 0;
  }
  return surplusW / voltage;
}

/**
 * @param {object} snapshot - { vehicle: { id, unavailable? }, metrics: { percentage_charged, solar_power, load_power, charge_amps?, charger_actual_current?, charging_state? } }
 * @param {Date} [now]
 * @param {object} [options] - override RULE_DEFAULTS
 * @returns {{ action: 'charge_stop'|'set_amps', targetAmps: number|null, reserveSoc: number, surplusW: number|null, deficitW: number|null, reason: string }}
 */
export function decideChargingActionFromSnapshot(snapshot, now = new Date(), options = {}) {
  const cfg = { ...RULE_DEFAULTS, ...options };
  const m = snapshot?.metrics || {};

  const percentageCharged = typeof m.percentage_charged === "number" ? m.percentage_charged : null;
  const solar = typeof m.solar_power === "number" ? m.solar_power : null;
  const load = typeof m.load_power === "number" ? m.load_power : null;

  const reserve = currentReserveSoc(now, cfg);

  if (snapshot?.vehicle?.unavailable) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW: null,
      deficitW: null,
      reason: "Vehicle unavailable; issuing charge_stop to be safe.",
    };
  }

  if (percentageCharged == null || solar == null || load == null) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW: null,
      deficitW: null,
      reason: "Missing critical telemetry (percentage_charged/solar/load); issuing charge_stop.",
    };
  }

  const isLikelyKw = solar < 1000 && load < 1000 && (solar > 0 || load > 0);
  const solarW = isLikelyKw ? solar * 1000 : solar;
  const loadW = isLikelyKw ? load * 1000 : load;
  const surplusW = solarW - loadW;
  const deficitW = Math.max(0, loadW - solarW);

  const currentChargeAmps =
    typeof m.charge_amps === "number" ? m.charge_amps
    : typeof m.charger_actual_current === "number" ? m.charger_actual_current
    : null;

  if (percentageCharged < reserve) {
    return {
      action: "charge_stop",
      targetAmps: null,
      reserveSoc: reserve,
      surplusW,
      deficitW: deficitW || null,
      reason: `Powerwall ${percentageCharged}% is below reserve ${reserve}%; stopping EV charge.`,
    };
  }

  let targetAmps;
  let reason;

  if (surplusW >= 0) {
    const rawAmps = wattsToAmps(surplusW, cfg.voltage);
    const minA = typeof cfg.minAmpsWhenSurplus === "number" ? cfg.minAmpsWhenSurplus : cfg.minAmps;
    targetAmps = Math.max(minA, Math.min(cfg.maxAmps, Math.round(rawAmps)));
    reason = `Solar surplus ${Math.round(surplusW)}W → charging at ${targetAmps}A.`;
  } else {
    const offsetAmps = wattsToAmps(deficitW, cfg.voltage);
    const fromAmps = currentChargeAmps != null ? currentChargeAmps : cfg.maxAmps;
    const allowedAmps = Math.max(0, Math.round(fromAmps - offsetAmps));
    if (allowedAmps < cfg.minAmps) {
      return {
        action: "charge_stop",
        targetAmps: null,
        reserveSoc: reserve,
        surplusW,
        deficitW,
        reason: `Load (${Math.round(loadW)}W) > solar (${Math.round(solarW)}W) by ${Math.round(deficitW)}W (~${offsetAmps.toFixed(1)}A); bringing down from ${fromAmps}A → stop.`,
      };
    }
    targetAmps = allowedAmps;
    reason = `Load > solar by ${Math.round(deficitW)}W; reducing from ${fromAmps}A by ~${offsetAmps.toFixed(1)}A → ${targetAmps}A.`;
  }

  return {
    action: "set_amps",
    targetAmps,
    reserveSoc: reserve,
    surplusW,
    deficitW: deficitW || null,
    reason,
  };
}
