import type { Scenario, Tier } from '../engine/types';
import { TIER_ORDER } from '../engine/types';
import { SD1_SCENARIOS } from './sd1';
import { SD1_SCENARIOS_B } from './sd1b';
import { SD1_SCENARIOS_C } from './sd1c';
import { SD2_SCENARIOS } from './sd2';
import { SD2_SCENARIOS_B } from './sd2b';
import { SD2_SCENARIOS_C } from './sd2c';
import { SOC1_SCENARIOS } from './soc1';
import { SOC1_SCENARIOS_B } from './soc1b';
import { SOC1_SCENARIOS_C } from './soc1c';
import { SOC2_SCENARIOS } from './soc2';
import { SOC2_SCENARIOS_B } from './soc2b';
import { SOC2_SCENARIOS_C } from './soc2c';
import { CIRT_SCENARIOS } from './cirt';
import { CIRT_SCENARIOS_B } from './cirtb';
import { CIRT_SCENARIOS_C } from './cirtc';

const SD1_ALL = [...SD1_SCENARIOS, ...SD1_SCENARIOS_B, ...SD1_SCENARIOS_C];
const SD2_ALL = [...SD2_SCENARIOS, ...SD2_SCENARIOS_B, ...SD2_SCENARIOS_C];
const SOC1_ALL = [...SOC1_SCENARIOS, ...SOC1_SCENARIOS_B, ...SOC1_SCENARIOS_C];
const SOC2_ALL = [...SOC2_SCENARIOS, ...SOC2_SCENARIOS_B, ...SOC2_SCENARIOS_C];
const CIRT_ALL = [...CIRT_SCENARIOS, ...CIRT_SCENARIOS_B, ...CIRT_SCENARIOS_C];

export const ALL_SCENARIOS: Scenario[] = [
  ...SD1_ALL, ...SD2_ALL, ...SOC1_ALL, ...SOC2_ALL, ...CIRT_ALL,
];

export const SCENARIOS_BY_TIER: Record<Tier, Scenario[]> = {
  sd1: SD1_ALL, sd2: SD2_ALL, soc1: SOC1_ALL, soc2: SOC2_ALL, cirt: CIRT_ALL,
};

export const SCENARIO_IDS_BY_TIER: Record<Tier, string[]> = Object.fromEntries(
  TIER_ORDER.map((t) => [t, SCENARIOS_BY_TIER[t].map((s) => s.id)]),
) as Record<Tier, string[]>;

export function getScenario(id: string): Scenario | undefined {
  return ALL_SCENARIOS.find((s) => s.id === id);
}
