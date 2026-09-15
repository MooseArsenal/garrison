import type { Scenario, Tier } from '../engine/types';
import { TIER_ORDER } from '../engine/types';
import { SD1_SCENARIOS } from './sd1';
import { SD2_SCENARIOS } from './sd2';
import { SOC1_SCENARIOS } from './soc1';
import { SOC2_SCENARIOS } from './soc2';
import { CIRT_SCENARIOS } from './cirt';

export const ALL_SCENARIOS: Scenario[] = [
  ...SD1_SCENARIOS, ...SD2_SCENARIOS, ...SOC1_SCENARIOS, ...SOC2_SCENARIOS, ...CIRT_SCENARIOS,
];

export const SCENARIOS_BY_TIER: Record<Tier, Scenario[]> = {
  sd1: SD1_SCENARIOS, sd2: SD2_SCENARIOS, soc1: SOC1_SCENARIOS, soc2: SOC2_SCENARIOS, cirt: CIRT_SCENARIOS,
};

export const SCENARIO_IDS_BY_TIER: Record<Tier, string[]> = Object.fromEntries(
  TIER_ORDER.map((t) => [t, SCENARIOS_BY_TIER[t].map((s) => s.id)]),
) as Record<Tier, string[]>;

export function getScenario(id: string): Scenario | undefined {
  return ALL_SCENARIOS.find((s) => s.id === id);
}
