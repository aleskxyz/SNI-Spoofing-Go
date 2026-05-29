<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { _, locale } from "svelte-i18n";
  import {
    GetDefaultConfig,
    UTLSPresets,
    InjectorModes,
    Start,
    Stop,
    Status,
    RunTest,
    Privileged,
  } from "../wailsjs/go/main/App.js";
  import { EventsOn, EventsOff } from "../wailsjs/runtime/runtime.js";
  import type { main } from "../wailsjs/go/models";

  import { appendLog, resetLogIds, type LogEntry } from "./logs";

  type ProxyConfig = main.ProxyConfig;
  type ProxyStatus = main.ProxyStatus;
  type TestResult = main.TestResult;
  type TestSummary = main.TestSummary;
  type PrivilegeStatus = main.PrivilegeStatus;

  let cfg: ProxyConfig | null = null;
  let utlsList: string[] = [];
  let injectorList: string[] = [];
  let status: ProxyStatus = { running: false, testing: false, listenAddr: "" };
  let priv: PrivilegeStatus = { elevated: true, hint: "", platform: "" };
  let logs: LogEntry[] = [];
  let testResults: TestResult[] = [];
  let testSummary: TestSummary | null = null;
  let busy = false;

  function pushLog(entry: Omit<LogEntry, "id">) {
    logs = appendLog(logs, entry);
  }

  onMount(async () => {
    cfg = await GetDefaultConfig();
    utlsList = await UTLSPresets();
    injectorList = await InjectorModes();
    status = await Status();
    priv = await Privileged();
    EventsOn("log", (e: { level: string; message: string }) => {
      pushLog({ ts: Date.now(), level: e.level, message: e.message });
    });
    EventsOn("status", (s: ProxyStatus) => {
      status = s;
    });
    EventsOn("test_result", (row: TestResult) => {
      testResults = [...testResults, row];
    });
  });

  onDestroy(() => {
    EventsOff("log");
    EventsOff("status");
    EventsOff("test_result");
  });

  function pushError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    pushLog({ ts: Date.now(), level: "error", message: msg });
  }

  async function onStart() {
    if (!cfg) return;
    busy = true;
    try {
      await Start(cfg);
    } catch (err) {
      pushError(err);
    } finally {
      busy = false;
    }
  }

  async function onStop() {
    busy = true;
    try {
      await Stop();
    } catch (err) {
      pushError(err);
    } finally {
      busy = false;
    }
  }

  async function onRunTest() {
    if (!cfg) return;
    busy = true;
    // Clear any prior table up-front so re-running surfaces incremental
    // rows from the "test_result" event stream as they arrive, rather
    // than holding the old table on screen until RunTest resolves.
    testResults = [];
    testSummary = null;
    try {
      testSummary = await RunTest(cfg);
      // If the event stream missed anything (e.g. listener attached late),
      // the final summary is still the source of truth for the row set.
      if (testSummary.results && testSummary.results.length > testResults.length) {
        testResults = testSummary.results;
      }
    } catch (err) {
      pushError(err);
      testSummary = null;
      testResults = [];
    } finally {
      busy = false;
    }
  }

  function onLocaleChange(ev: Event) {
    const sel = ev.target as HTMLSelectElement;
    locale.set(sel.value);
  }

  function clearLogs() {
    resetLogIds();
    logs = [];
  }

  // Reactive: rebuild the formatter whenever the active i18n locale changes
  // so log timestamps follow the same locale as the rest of the UI (Persian
  // digits in fa mode, etc.).
  $: timeFormatter = new Intl.DateTimeFormat($locale || "en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  function formatTime(ts: number): string {
    return timeFormatter.format(new Date(ts));
  }

  // Auto-scroll the log panel will be re-added with a Svelte 5-correct
  // pattern (likely a tick-based effect inside onMount) — the prior $: form
  // silently aborted component mount in Svelte 5 dev mode.
</script>

<header class="topbar">
  <div class="brand">
    <div class="brand-title">{$_("app.title")}</div>
    <div class="brand-subtitle">{$_("app.subtitle")}</div>
  </div>
  <div class="topbar-spacer"></div>
  <div class="status-pill" class:running={status.running} class:testing={status.testing}>
    <span class="dot"></span>
    {#if status.testing}
      {$_("status.testing")}
    {:else if status.running}
      {$_("status.running")}
    {:else}
      {$_("status.stopped")}
    {/if}
    {#if status.running && status.listenAddr}
      <span class="status-detail">{status.listenAddr}</span>
    {/if}
  </div>
  <div class="lang-switch">
    <label for="lang">{$_("lang.label")}</label>
    <select
      id="lang"
      value={$locale}
      on:change={onLocaleChange}
    >
      <option value="en">English</option>
      <option value="fa">فارسی</option>
    </select>
  </div>
</header>

<main class="layout">
  <section class="panel">
    {#if !priv.elevated}
      <div class="privilege-banner" role="alert">
        <span class="privilege-icon">⚠</span>
        <span>
          {$_(`privilege.banner_${priv.platform || "windows"}`)}
        </span>
      </div>
    {/if}
    {#if cfg}
      <div class="section-title">{$_("form.section_connection")}</div>
      <div class="grid-2">
        <label>
          <span>{$_("form.listen")}</span>
          <input type="text" bind:value={cfg.listen} placeholder="127.0.0.1:40443" />
          <small>{$_("form.listen_help")}</small>
        </label>
        <label>
          <span>{$_("form.connect")}</span>
          <input type="text" bind:value={cfg.connect} placeholder="host:443" />
          <small>{$_("form.connect_help")}</small>
        </label>
        <label>
          <span>{$_("form.fake_sni")}</span>
          <input type="text" bind:value={cfg.fakeSni} placeholder="hcaptcha.com" />
          <small>{$_("form.fake_sni_help")}</small>
        </label>
        <label>
          <span>{$_("form.utls")}</span>
          <select bind:value={cfg.utls}>
            {#each utlsList as p}
              <option value={p}>{p}</option>
            {/each}
          </select>
        </label>
      </div>

      <div class="section-title">{$_("form.section_injection")}</div>
      <div class="grid-2">
        <label>
          <span>{$_("form.injector")}</span>
          <select bind:value={cfg.injector}>
            {#each injectorList as m}
              <option value={m}>{m}</option>
            {/each}
          </select>
        </label>
        <label>
          <span>{$_("form.fake_repeat")}</span>
          <input type="number" min="1" bind:value={cfg.fakeRepeat} />
        </label>
        <label>
          <span>{$_("form.fake_delay")}</span>
          <input type="number" min="0" bind:value={cfg.fakeDelayMs} />
        </label>
        <label>
          <span>{$_("form.ack_timeout")}</span>
          <input type="number" min="1" bind:value={cfg.ackTimeoutMs} />
        </label>
      </div>

      <div class="section-title">{$_("form.section_fragmentation")}</div>
      <div class="grid-2">
        <label class="checkbox-row">
          <input type="checkbox" bind:checked={cfg.enableFragment} />
          <span>{$_("form.enable_fragment")}</span>
        </label>
        <span></span>
        <label>
          <span>{$_("form.fragment_delay")}</span>
          <input
            type="number"
            min="0"
            bind:value={cfg.fragmentDelayMs}
            disabled={!cfg.enableFragment}
          />
        </label>
        <label>
          <span>{$_("form.sni_chunk")}</span>
          <input
            type="number"
            min="0"
            bind:value={cfg.sniChunk}
            disabled={!cfg.enableFragment}
          />
        </label>
      </div>

      <div class="actions">
        {#if status.running || status.testing}
          <button class="btn danger" on:click={onStop} disabled={busy && !status.testing}>
            {status.testing ? $_("actions.cancel_test") : $_("actions.stop")}
          </button>
        {:else}
          <button class="btn primary" on:click={onStart} disabled={busy}>
            {$_("actions.start")}
          </button>
        {/if}
        <button
          class="btn"
          on:click={onRunTest}
          disabled={busy || status.running || status.testing}
        >
          {$_("actions.test")}
        </button>
      </div>
    {/if}
  </section>

  <section class="panel logs">
    <div class="panel-header">
      <div class="section-title compact">{$_("logs.title")}</div>
      <button class="btn-link" on:click={clearLogs}>{$_("actions.clear_logs")}</button>
    </div>
    <div class="log-list">
      {#if logs.length === 0}
        <div class="empty">{$_("logs.empty")}</div>
      {:else}
        {#each logs as line (line.id)}
          <div class="log-line log-{line.level}">
            <span class="log-time">{formatTime(line.ts)}</span>
            <span class="log-msg">{line.message}</span>
          </div>
        {/each}
      {/if}
    </div>

    {#if testSummary}
      <div class="section-title compact spaced">{$_("test.title")}</div>
      <div class="test-preflight">
        {#if testSummary.preflight.externalIp}
          <span>{$_("test.external_ip")}: {testSummary.preflight.externalIp}</span>
        {/if}
        {#if testSummary.preflight.internalIp}
          <span>{$_("test.internal_ip")}: {testSummary.preflight.internalIp}</span>
        {/if}
        {#if testSummary.preflight.warning}
          <span class="test-preflight-note">{testSummary.preflight.warning}</span>
        {/if}
        <span class="test-summary-counts">
          {$_("test.pass")}: {testSummary.passed} / {$_("test.fail")}: {testSummary.failed}
        </span>
      </div>
      <table class="test-table">
        <thead>
          <tr>
            <th>{$_("test.col_utls")}</th>
            <th>{$_("test.col_repeat")}</th>
            <th>{$_("test.col_fragment")}</th>
            <th>{$_("test.col_result")}</th>
          </tr>
        </thead>
        <tbody>
          {#each testResults as r}
            <tr>
              <td>{r.utls}</td>
              <td>{r.fakeRepeat}</td>
              <td>{r.enableFragment ? $_("test.on") : $_("test.off")}</td>
              <td class:pass={r.pass} class:fail={!r.pass}>
                {r.pass ? $_("test.pass") : $_("test.fail")}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</main>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding-inline: 20px;
    padding-block: 14px;
    border-block-end: 1px solid var(--border);
    background: var(--panel);
  }
  .brand-title {
    font-weight: 700;
    font-size: 16px;
  }
  .brand-subtitle {
    color: var(--muted);
    font-size: 12px;
  }
  .topbar-spacer {
    flex: 1;
  }
  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding-inline: 12px;
    padding-block: 6px;
    border-radius: 999px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    font-size: 13px;
  }
  .status-pill .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--muted);
  }
  .status-pill.running .dot {
    background: var(--ok);
    box-shadow: 0 0 0 3px rgba(61, 220, 151, 0.18);
  }
  .status-pill.testing .dot {
    background: var(--warn);
    box-shadow: 0 0 0 3px rgba(255, 214, 107, 0.18);
  }
  .status-detail {
    color: var(--muted);
    margin-inline-start: 6px;
  }
  .lang-switch {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .lang-switch label {
    color: var(--muted);
    font-size: 12px;
  }
  .lang-switch select {
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding-inline: 10px;
    padding-block: 6px;
  }

  .layout {
    display: grid;
    grid-template-columns: minmax(380px, 1fr) minmax(360px, 1fr);
    gap: 16px;
    padding: 16px;
    flex: 1;
    min-height: 0;
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px;
    overflow: auto;
  }
  .panel.logs {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-block-end: 8px;
  }

  .section-title {
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 11px;
    margin-block: 14px 8px;
  }
  .section-title.compact {
    margin-block: 0 0;
  }
  .section-title.spaced {
    margin-block-start: 16px;
  }

  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px 16px;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13px;
  }
  label > span {
    color: var(--muted);
    font-size: 12px;
  }
  label small {
    color: var(--muted);
    font-size: 11px;
  }
  input[type="text"],
  input[type="number"],
  select {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding-inline: 10px;
    padding-block: 8px;
    color: var(--text);
    outline: none;
  }
  input:focus,
  select:focus {
    border-color: var(--accent);
  }
  input:disabled {
    opacity: 0.5;
  }
  .checkbox-row {
    flex-direction: row;
    align-items: center;
    gap: 8px;
  }

  .actions {
    display: flex;
    gap: 10px;
    margin-block-start: 18px;
  }
  .btn {
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding-inline: 14px;
    padding-block: 8px;
    font-weight: 600;
  }
  .btn:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn.primary {
    background: var(--accent-strong);
    border-color: var(--accent-strong);
    color: white;
  }
  .btn.danger {
    background: #5a2030;
    border-color: #7a2a40;
    color: #ffd0d0;
  }
  .btn-link {
    background: transparent;
    border: none;
    color: var(--accent);
    font-size: 12px;
    padding: 0;
  }

  .log-list {
    flex: 1;
    overflow-y: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono",
      monospace;
    font-size: 12px;
  }
  .empty {
    color: var(--muted);
    text-align: center;
    padding-block: 12px;
  }
  .log-line {
    display: flex;
    gap: 10px;
    padding-block: 2px;
  }
  .log-time {
    color: var(--muted);
    flex-shrink: 0;
  }
  .log-info .log-msg {
    color: var(--text);
  }
  .log-error .log-msg {
    color: var(--err);
  }
  .log-warn .log-msg {
    color: var(--warn);
  }
  .log-debug .log-msg {
    color: var(--muted);
  }

  .privilege-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    padding-inline: 12px;
    padding-block: 10px;
    margin-block-end: 12px;
    border-radius: var(--radius);
    background: rgba(255, 214, 107, 0.08);
    border: 1px solid rgba(255, 214, 107, 0.35);
    color: var(--warn);
    font-size: 13px;
  }
  .privilege-icon {
    font-size: 16px;
    line-height: 1;
  }

  .test-preflight {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 16px;
    font-size: 12px;
    color: var(--muted);
    margin-block: 8px;
  }
  .test-preflight-note {
    color: var(--warn);
  }
  .test-summary-counts {
    margin-inline-start: auto;
    color: var(--text);
  }

  .test-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .test-table th,
  .test-table td {
    text-align: start;
    padding: 6px 8px;
    border-block-end: 1px solid var(--border);
  }
  .test-table th {
    color: var(--muted);
    font-weight: 600;
  }
  td.pass {
    color: var(--ok);
    font-weight: 600;
  }
  td.fail {
    color: var(--err);
    font-weight: 600;
  }
</style>
