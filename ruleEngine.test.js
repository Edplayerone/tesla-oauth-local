/**
 * Tests for decideChargingActionFromSnapshot (rule engine).
 * Run: npm test
 */

import assert from "node:assert";
import { describe, it } from "node:test";
import { decideChargingActionFromSnapshot, RULE_DEFAULTS } from "./ruleEngine.js";

function snapshot(overrides = {}) {
  return {
    vehicle: { id: "123", unavailable: false },
    metrics: {
      percentage_charged: 50,
      solar_power: 6,
      load_power: 4,
      charge_amps: 5,
      charging_state: "Charging",
      ...overrides.metrics,
    },
    ...overrides,
  };
}

describe("decideChargingActionFromSnapshot", () => {
  it("solar 6kW, load 4kW, charging_state Charging, charge_amps 5 → set_amps with targetAmps 6", () => {
    const sn = snapshot({
      metrics: {
        percentage_charged: 50,
        solar_power: 6,
        load_power: 4,
        charge_amps: 5,
        charging_state: "Charging",
      },
    });
    // 6kW - 4kW = 2kW surplus. To get targetAmps 6: 2000/voltage = 6 → voltage ≈ 333
    const decision = decideChargingActionFromSnapshot(sn, new Date(), {
      ...RULE_DEFAULTS,
      voltage: 2000 / 6,
    });
    assert.strictEqual(decision.action, "set_amps");
    assert.strictEqual(decision.targetAmps, 6);
    assert.ok(decision.reason.includes("Solar surplus 2000W"));
  });

  it("solar 6kW, load 4kW with default 240V → set_amps targetAmps 8", () => {
    const sn = snapshot({ metrics: { solar_power: 6, load_power: 4, percentage_charged: 50 } });
    const decision = decideChargingActionFromSnapshot(sn);
    assert.strictEqual(decision.action, "set_amps");
    assert.strictEqual(decision.targetAmps, 8); // 2000/240 ≈ 8.33 → 8
  });

  it("missing telemetry → charge_stop", () => {
    const decision = decideChargingActionFromSnapshot(
      snapshot({ metrics: { percentage_charged: null, solar_power: 6, load_power: 4 } })
    );
    assert.strictEqual(decision.action, "charge_stop");
    assert.ok(decision.reason.includes("Missing critical telemetry"));
  });

  it("Powerwall below reserve → charge_stop", () => {
    const decision = decideChargingActionFromSnapshot(
      snapshot({ metrics: { percentage_charged: 30, solar_power: 6, load_power: 4 } }),
      new Date(),
      { reserveOffPeak: 40 }
    );
    assert.strictEqual(decision.action, "charge_stop");
    assert.ok(decision.reason.includes("below reserve"));
  });

  it("load > solar (deficit) → reduces amps or charge_stop", () => {
    const sn = snapshot({
      metrics: { percentage_charged: 50, solar_power: 4, load_power: 6, charge_amps: 10 },
    });
    const decision = decideChargingActionFromSnapshot(sn);
    assert.ok(decision.action === "set_amps" || decision.action === "charge_stop");
    if (decision.action === "set_amps") {
      assert.ok(decision.targetAmps <= 10);
      assert.ok(decision.reason.includes("Load > solar"));
    }
  });
});
