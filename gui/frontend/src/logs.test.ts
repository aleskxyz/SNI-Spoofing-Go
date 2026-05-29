import { describe, it, expect, beforeEach } from "vitest";
import {
  appendLog,
  resetLogIds,
  _resetLogIdForTest,
  LOG_BUFFER_MAX,
  type LogEntry,
} from "./logs";

beforeEach(() => {
  resetLogIds();
});

const sample = (i: number): Omit<LogEntry, "id"> => ({
  ts: 1_700_000_000_000 + i,
  level: "info",
  message: `msg-${i}`,
});

describe("appendLog", () => {
  it("appends below capacity without trimming", () => {
    let logs: LogEntry[] = [];
    for (let i = 0; i < 5; i++) {
      logs = appendLog(logs, sample(i), 10);
    }
    expect(logs).toHaveLength(5);
    expect(logs.map((l) => l.message)).toEqual([
      "msg-0",
      "msg-1",
      "msg-2",
      "msg-3",
      "msg-4",
    ]);
  });

  it("assigns strictly monotonic ids", () => {
    let logs: LogEntry[] = [];
    for (let i = 0; i < 4; i++) {
      logs = appendLog(logs, sample(i), 10);
    }
    expect(logs.map((l) => l.id)).toEqual([0, 1, 2, 3]);
  });

  it("at exactly max: keeps max entries, drops the oldest", () => {
    let logs: LogEntry[] = [];
    for (let i = 0; i < 5; i++) {
      logs = appendLog(logs, sample(i), 5);
    }
    expect(logs).toHaveLength(5);
    // Pushing one more triggers the trim.
    logs = appendLog(logs, sample(5), 5);
    expect(logs).toHaveLength(5);
    expect(logs.map((l) => l.message)).toEqual([
      "msg-1",
      "msg-2",
      "msg-3",
      "msg-4",
      "msg-5",
    ]);
    expect(logs[logs.length - 1].id).toBe(5);
  });

  it("one over: identical to the at-max case", () => {
    let logs: LogEntry[] = Array.from({ length: 5 }, (_, i) => ({
      id: i,
      ...sample(i),
    }));
    _resetLogIdForTest();
    // Pretend we just hit max — push one entry, should drop the oldest.
    const next = appendLog(logs, sample(99), 5);
    expect(next).toHaveLength(5);
    expect(next[0].message).toBe("msg-1");
    expect(next[next.length - 1].message).toBe("msg-99");
  });

  it("many over: caps to max even if the input array is already too large", () => {
    // Defensive path: caller somehow built a long array; appendLog still bounds it.
    const oversized: LogEntry[] = Array.from({ length: 12 }, (_, i) => ({
      id: i,
      ...sample(i),
    }));
    _resetLogIdForTest();
    const next = appendLog(oversized, sample(100), 5);
    expect(next).toHaveLength(5);
    expect(next[next.length - 1].message).toBe("msg-100");
    // Should have kept the *newest* (max-1) of the input + the new entry.
    expect(next.map((l) => l.message)).toEqual([
      "msg-8",
      "msg-9",
      "msg-10",
      "msg-11",
      "msg-100",
    ]);
  });

  it("defaults to LOG_BUFFER_MAX when max is omitted", () => {
    let logs: LogEntry[] = [];
    for (let i = 0; i < LOG_BUFFER_MAX + 10; i++) {
      logs = appendLog(logs, sample(i));
    }
    expect(logs).toHaveLength(LOG_BUFFER_MAX);
    expect(logs[logs.length - 1].message).toBe(`msg-${LOG_BUFFER_MAX + 9}`);
  });

  it("resetLogIds restarts the id sequence at 0 (same path as the test-only reset)", () => {
    // Both the public reset (used by clearLogs in the UI) and the
    // test-only alias must drive the same underlying counter — otherwise
    // the UI-side reset could drift away from what tests pin down.
    let logs: LogEntry[] = [];
    logs = appendLog(logs, sample(0), 10);
    logs = appendLog(logs, sample(1), 10);
    expect(logs.map((l) => l.id)).toEqual([0, 1]);

    resetLogIds();
    let afterPublic: LogEntry[] = [];
    afterPublic = appendLog(afterPublic, sample(2), 10);
    expect(afterPublic[0].id).toBe(0);

    _resetLogIdForTest();
    let afterTestAlias: LogEntry[] = [];
    afterTestAlias = appendLog(afterTestAlias, sample(3), 10);
    expect(afterTestAlias[0].id).toBe(0);

    // And the test-only export is literally the same function reference,
    // confirming there is only one counter to keep in sync.
    expect(_resetLogIdForTest).toBe(resetLogIds);
  });
});
