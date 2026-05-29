export const LOG_BUFFER_MAX = 500;

export type LogEntry = {
  id: number;
  ts: number;
  level: string;
  message: string;
};

let nextLogId = 0;

/**
 * Reset the monotonic id counter back to 0. Call this whenever the visible
 * log buffer is cleared so the next batch of entries starts from a clean
 * id sequence (keeps the keyed {#each} from accumulating stale ids and
 * keeps the counter from drifting unboundedly across long sessions).
 */
export function resetLogIds(): void {
  nextLogId = 0;
}

// Exported for tests so a deterministic id sequence can be asserted.
// Kept as an alias so existing test imports keep working — both paths
// share the same underlying counter.
export const _resetLogIdForTest = resetLogIds;

/**
 * Append `entry` to `logs`, returning a new array whose length never exceeds
 * `max`. When at capacity, the oldest entries are dropped from the front so
 * the newest `max` entries are kept. The returned entries carry a strictly
 * monotonic `id` so a Svelte {#each ... (id)} keyed block doesn't have to
 * fall back to ts (which can collide at millisecond resolution).
 */
export function appendLog(
  logs: LogEntry[],
  entry: Omit<LogEntry, "id">,
  max: number = LOG_BUFFER_MAX,
): LogEntry[] {
  const withId: LogEntry = { id: nextLogId++, ...entry };
  if (logs.length >= max) {
    return [...logs.slice(logs.length - (max - 1)), withId];
  }
  return [...logs, withId];
}
