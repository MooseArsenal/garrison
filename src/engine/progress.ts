import type { ScenarioProgress, Tier, Skill } from './types';
import { TIER_ORDER } from './types';

const KEY = 'garrison.progress.v1';
const SETTINGS_KEY = 'garrison.settings.v1';

export interface Settings {
  unlockAll: boolean;
  hintsEnabled: boolean;
  playerName: string;
}

export interface ProgressStore {
  scenarios: Record<string, ScenarioProgress>;
  history: { scenarioId: string; score: number; at: string; skills: Partial<Record<Skill, number>> }[];
  lessons: Record<string, boolean>; // learning-path lesson steps completed, keyed "pathId#stepIndex"
}

function safeParse<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try { return { ...fallback, ...JSON.parse(raw) }; } catch { return fallback; }
}

export function loadProgress(): ProgressStore {
  return safeParse<ProgressStore>(localStorage.getItem(KEY), { scenarios: {}, history: [], lessons: {} });
}

export function markLesson(key: string): ProgressStore {
  const p = loadProgress();
  if (!p.lessons) p.lessons = {};
  p.lessons[key] = true;
  saveProgress(p);
  return p;
}

export function saveProgress(p: ProgressStore): void {
  localStorage.setItem(KEY, JSON.stringify(p));
}

export function recordResult(scenarioId: string, score: number, skills: Partial<Record<Skill, number>>): ProgressStore {
  const p = loadProgress();
  const prev = p.scenarios[scenarioId];
  p.scenarios[scenarioId] = {
    scenarioId,
    best: Math.max(prev?.best ?? 0, score),
    attempts: (prev?.attempts ?? 0) + 1,
    lastPlayed: new Date().toISOString(),
    passed: (prev?.passed ?? false) || score >= 70,
  };
  p.history.push({ scenarioId, score, at: new Date().toISOString(), skills });
  if (p.history.length > 500) p.history = p.history.slice(-500);
  saveProgress(p);
  return p;
}

export function resetProgress(): void {
  localStorage.removeItem(KEY);
}

export function loadSettings(): Settings {
  return safeParse<Settings>(localStorage.getItem(SETTINGS_KEY), { unlockAll: false, hintsEnabled: true, playerName: 'Analyst' });
}
export function saveSettings(s: Settings): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

/** A tier unlocks when >= 75% of the previous tier's scenarios are passed. */
export function tierUnlocked(tier: Tier, scenarioIdsByTier: Record<Tier, string[]>, p: ProgressStore, settings: Settings): boolean {
  if (settings.unlockAll) return true;
  const idx = TIER_ORDER.indexOf(tier);
  if (idx === 0) return true;
  const prev = TIER_ORDER[idx - 1];
  const ids = scenarioIdsByTier[prev];
  if (!ids.length) return true;
  const passed = ids.filter((id) => p.scenarios[id]?.passed).length;
  return passed / ids.length >= 0.75;
}
