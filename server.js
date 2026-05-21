import { execFile } from "node:child_process";
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs/promises";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "public");
const dataDir = path.join(__dirname, "data");
const integrityBaselinePath = path.join(dataDir, "file-integrity-baseline.json");
const blockedLogonIpsPath = path.join(dataDir, "blocked-logon-ips.json");
const alertConfigPath = path.join(dataDir, "alerts-config.json");
const alertLogPath = path.join(dataDir, "alerts.jsonl");
const historyPath = path.join(dataDir, "history.jsonl");
const configPath = path.join(__dirname, "masterhud.config.json");
const profilesDir = path.join(__dirname, "profiles");
const activeProfilePath = path.join(dataDir, "active-profile.json");
const port = Number(process.env.PORT || 3927);
const sampleMs = Number(process.env.SAMPLE_MS || 5000);
const slowSecurityMs = Number(process.env.SLOW_SECURITY_MS || 10 * 60 * 1000);
const powerShellExe = process.env.MASTERHUD_POWERSHELL || "powershell.exe";

const defaultConfig = {
  publicUrls: [],
  expectedWorkloads: [],
  managedServices: [],
  requiredServices: [],
  requiredPorts: [80, 443],
  appRoot: "",
  healthUrl: "",
  caddyConfigPath: "",
  caddyCandidates: [
    "C:\\Program Files\\Caddy\\caddy.exe",
    "C:\\caddy\\caddy.exe"
  ],
  wingetPath: "winget.exe",
  versionCommands: [
    { name: "Node.js", command: "node --version" },
    { name: "npm", command: "npm --version" },
    { name: "Git", command: "git --version" },
    { name: "Caddy", command: "caddy version" }
  ],
  updateChecks: {
    windows: true,
    winget: true,
    npm: true,
    git: true,
    versions: true
  },
  readinessCommands: [],
  tabletReadinessCommand: "",
  quickLinks: []
};

function validProfileName(value) {
  return typeof value === "string" && /^[a-zA-Z0-9._-]{1,80}$/.test(value) && !value.includes("..");
}

function profileConfigPath(profileName) {
  if (!validProfileName(profileName)) return null;
  return path.join(profilesDir, `${profileName}.json`);
}

async function readOptionalJson(filePath, fallback = null) {
  try {
    return JSON.parse((await fs.readFile(filePath, "utf8")).replace(/^\uFEFF/, ""));
  } catch {
    return fallback;
  }
}

async function getSelectedProfileName(baseConfig = {}) {
  if (validProfileName(process.env.MASTERHUD_PROFILE)) return process.env.MASTERHUD_PROFILE;
  const active = await readOptionalJson(activeProfilePath, {});
  if (validProfileName(active?.profile)) return active.profile;
  if (validProfileName(baseConfig.activeProfile)) return baseConfig.activeProfile;
  return "";
}

async function loadConfig() {
  const baseConfig = await readOptionalJson(configPath, {});
  const selectedProfile = await getSelectedProfileName(baseConfig);
  const profilePath = profileConfigPath(selectedProfile);
  const profileConfig = profilePath ? await readOptionalJson(profilePath, {}) : {};
  const loaded = { ...defaultConfig, ...baseConfig, ...profileConfig };
  loaded.profile = {
    active: selectedProfile,
    label: loaded.label || selectedProfile || "Default",
    source: profilePath && Object.keys(profileConfig).length ? profilePath : (Object.keys(baseConfig).length ? configPath : "defaults")
  };
  return loaded;
}

async function listProfiles() {
  let entries = [];
  try {
    entries = await fs.readdir(profilesDir, { withFileTypes: true });
  } catch {}
  const profiles = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const name = entry.name.replace(/\.json$/i, "");
    if (!validProfileName(name)) continue;
    const filePath = path.join(profilesDir, entry.name);
    const profile = await readOptionalJson(filePath, {});
    profiles.push({
      name,
      label: profile.label || name,
      source: filePath,
      example: entry.name.endsWith(".example.json")
    });
  }
  return profiles.sort((a, b) => a.label.localeCompare(b.label));
}

let config = await loadConfig();

async function reloadConfig() {
  config = await loadConfig();
  return config;
}

let previousCpu = os.cpus();
let previousNet = null;
let previousDisk = null;
let latest = null;
let clients = new Set();
let collecting = false;
let lastHistoryAt = 0;
const alertDedup = new Map();
let slowSecurity = {
  capturedAt: null,
  running: false,
  findings: [],
  coverage: [],
  fileIntegrity: null,
  logAnomalies: null,
  uptime: null,
  sysmon: null,
  backups: null,
  dependencyAudit: null
};

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"]
]);

function runPowerShell(script, timeout = 30000) {
  return new Promise((resolve) => {
    execFile(
      powerShellExe,
      ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
      { timeout, windowsHide: true, maxBuffer: 1024 * 1024 * 8 },
      (error, stdout, stderr) => {
        if (error) {
          resolve({ ok: false, error: String(stderr || error.message).trim() });
          return;
        }
        try {
          resolve({ ok: true, data: JSON.parse(stdout || "{}") });
        } catch (parseError) {
          resolve({ ok: false, error: `PowerShell JSON parse failed: ${parseError.message}` });
        }
      }
    );
  });
}

function cpuSnapshot() {
  const current = os.cpus();
  const cores = current.map((cpu, index) => {
    const prev = previousCpu[index] || cpu;
    const idle = cpu.times.idle - prev.times.idle;
    const total = Object.keys(cpu.times).reduce((sum, key) => sum + cpu.times[key] - prev.times[key], 0);
    return total > 0 ? Math.max(0, Math.min(100, 100 - (idle / total) * 100)) : 0;
  });
  previousCpu = current;
  const usage = cores.reduce((sum, value) => sum + value, 0) / Math.max(cores.length, 1);
  return { usage, cores, model: current[0]?.model || "Unknown CPU", load: os.loadavg() };
}

function memorySnapshot() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  return { total, free, used, usage: total ? (used / total) * 100 : 0 };
}

function normalizeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJsonFile(filePath, fallback) {
  try {
    return JSON.parse((await fs.readFile(filePath, "utf8")).replace(/^\uFEFF/, ""));
  } catch {
    return fallback;
  }
}

async function writeJsonFile(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}

async function updateBlockedIpState(ip, blocked) {
  const state = await readJsonFile(blockedLogonIpsPath, { blocked: [] });
  const entries = normalizeArray(state.blocked).filter((entry) => entry?.ip !== ip);
  if (blocked) {
    entries.push({
      ip,
      count: "manual",
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      source: "manual"
    });
  }
  await writeJsonFile(blockedLogonIpsPath, { blocked: entries });
}

async function readTextFile(filePath, fallback = "") {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return fallback;
  }
}

async function appendJsonl(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, `${JSON.stringify(data)}\n`);
}

async function readJsonlTail(filePath, limit = 80) {
  const text = await readTail(filePath, 768 * 1024);
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-limit)
    .map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    })
    .filter(Boolean)
    .reverse();
}

async function alertConfig() {
  const defaults = {
    enabled: false,
    webhookUrl: "",
    minSeverity: "hot",
    cooldownMinutes: 30
  };
  const config = await readJsonFile(alertConfigPath, null);
  if (!config) {
    await writeJsonFile(alertConfigPath, defaults);
    return defaults;
  }
  return { ...defaults, ...config };
}

function severityRank(severity) {
  return { cool: 0, info: 0, warm: 1, hot: 2, bad: 2 }[String(severity || "").toLowerCase()] ?? 0;
}

function postWebhook(url, payload) {
  return new Promise((resolve) => {
    try {
      const target = new URL(url);
      const body = JSON.stringify(payload);
      const transport = target.protocol === "http:" ? http : https;
      const req = transport.request(target, {
        method: "POST",
        timeout: 9000,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body)
        }
      }, (response) => {
        response.resume();
        resolve({ ok: response.statusCode >= 200 && response.statusCode < 300, statusCode: response.statusCode });
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", (error) => resolve({ ok: false, error: error.message }));
      req.end(body);
    } catch (error) {
      resolve({ ok: false, error: error.message });
    }
  });
}

async function publishAlerts(data) {
  const config = await alertConfig();
  const minRank = severityRank(config.minSeverity);
  const cooldownMs = Math.max(1, Number(config.cooldownMinutes || 30)) * 60000;
  const signals = [
    ...normalizeArray(data.windows?.security?.findings).map((item) => ({
      source: "security",
      severity: String(item.Severity || "info").toLowerCase(),
      title: item.Title,
      detail: item.Detail
    })),
    ...normalizeArray(data.recommendations).map((item) => ({
      source: "optimization",
      severity: String(item.severity || "info").toLowerCase(),
      title: item.title,
      detail: item.detail
    })),
    ...normalizeArray(data.windows?.rebootReadiness?.checks).map((item) => ({
      source: "reboot-readiness",
      severity: item.Status === "bad" ? "hot" : item.Status === "warn" ? "warm" : "cool",
      title: item.Name,
      detail: item.Detail
    }))
  ].filter((item) => item.title && severityRank(item.severity) >= minRank);

  for (const signal of signals) {
    const key = crypto.createHash("sha256").update(`${signal.source}|${signal.severity}|${signal.title}|${signal.detail}`).digest("hex");
    const lastAt = alertDedup.get(key) || 0;
    if (Date.now() - lastAt < cooldownMs) continue;
    alertDedup.set(key, Date.now());
    const alert = { ...signal, key, capturedAt: data.capturedAt, host: data.host?.hostname };
    if (config.enabled && config.webhookUrl) {
      alert.delivery = await postWebhook(config.webhookUrl, alert);
    } else {
      alert.delivery = { ok: true, mode: "local-log" };
    }
    await appendJsonl(alertLogPath, alert);
  }
}

async function appendHistory(data) {
  if (Date.now() - lastHistoryAt < 60000) return;
  lastHistoryAt = Date.now();
  const findings = normalizeArray(data.windows?.security?.findings);
  const workloads = normalizeArray(data.windows?.workloads);
  const volumes = normalizeArray(data.windows?.volumes);
  await appendJsonl(historyPath, {
    capturedAt: data.capturedAt,
    cpu: Number(data.cpu?.usage || 0),
    memory: Number(data.memory?.usage || 0),
    diskRead: Number(data.rates?.disk?.read || 0),
    diskWrite: Number(data.rates?.disk?.write || 0),
    netRx: Number(data.rates?.network?.rx || 0),
    netTx: Number(data.rates?.network?.tx || 0),
    hot: findings.filter((item) => item.Severity === "hot").length,
    warm: findings.filter((item) => item.Severity === "warm").length,
    drift: workloads.filter((item) => item.Health === "drift" || item.Health === "down").length,
    autoBlocked: normalizeArray(data.windows?.security?.autoBlockedIps).length,
    lowVolumes: volumes.filter((v) => Number(v.Size) > 0 && Number(v.FreeSpace) / Number(v.Size) < 0.15).length,
    openPorts: normalizeArray(data.windows?.ports).length
  });
}

async function mergeAlertAndHistoryState(data) {
  if (!data.windows.security) data.windows.security = {};
  data.windows.security.alertLog = await readJsonlTail(alertLogPath, 60);
  data.history = await readJsonlTail(historyPath, 180);
  return data;
}

async function sha256File(filePath) {
  const buffer = await fs.readFile(filePath);
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function runCommand(file, args, cwd, timeout = 60000) {
  return new Promise((resolve) => {
    try {
      execFile(file, args, { cwd, timeout, windowsHide: true, maxBuffer: 1024 * 1024 * 8 }, (error, stdout, stderr) => {
        resolve({ ok: !error, stdout, stderr, error: error?.message || "" });
      });
    } catch (error) {
      resolve({ ok: false, stdout: "", stderr: "", error: error.message });
    }
  });
}

async function readTail(filePath, maxBytes = 512 * 1024) {
  try {
    const handle = await fs.open(filePath, "r");
    try {
      const stat = await handle.stat();
      const length = Math.min(stat.size, maxBytes);
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, Math.max(0, stat.size - length));
      return buffer.toString("utf8");
    } finally {
      await handle.close();
    }
  } catch {
    return "";
  }
}

function appWorkloads(windows = {}) {
  return (windows.workloads || []).filter((workload) => workload.AppDirectory);
}

function workloadAnchorFiles(windows = {}) {
  const files = new Map();
  for (const workload of appWorkloads(windows)) {
    for (const check of normalizeArray(workload.Checks)) {
      if (check?.Type === "File" && check?.Path && check?.Status === "ok") {
        files.set(check.Path.toLowerCase(), { path: check.Path, workload: workload.DisplayName || workload.Name, label: check.Label });
      }
    }
  }
  return [...files.values()];
}

async function monitorFileIntegrity(windows) {
  const anchors = workloadAnchorFiles(windows);
  const current = {};
  for (const anchor of anchors) {
    try {
      current[anchor.path] = {
        hash: await sha256File(anchor.path),
        workload: anchor.workload,
        label: anchor.label
      };
    } catch {}
  }

  const existing = await readJsonFile(integrityBaselinePath, null);
  if (!existing || !existing.files) {
    await writeJsonFile(integrityBaselinePath, { createdAt: new Date().toISOString(), files: current });
    return {
      status: "active",
      baselineCreated: true,
      checked: Object.keys(current).length,
      changed: [],
      missing: []
    };
  }

  const changed = [];
  const missing = [];
  for (const [filePath, baseline] of Object.entries(existing.files)) {
    if (!current[filePath]) {
      missing.push({ path: filePath, workload: baseline.workload, label: baseline.label });
    } else if (current[filePath].hash !== baseline.hash) {
      changed.push({ path: filePath, workload: baseline.workload, label: baseline.label });
    }
  }
  return { status: "active", baselineCreated: false, checked: Object.keys(current).length, changed, missing };
}

async function monitorLogAnomalies(windows) {
  const logPaths = new Set();
  for (const workload of appWorkloads(windows)) {
    for (const candidate of [workload.Stdout, workload.Stderr]) {
      if (candidate) logPaths.add(candidate);
    }
    if (workload.AppDirectory) {
      logPaths.add(path.join(workload.AppDirectory, "caddy-access.log"));
      logPaths.add(path.join(workload.AppDirectory, "backend", "caddy-access.log"));
    }
  }
  const suspiciousNeedles = [".env", ".git", "wp-admin", "phpmyadmin", "xmlrpc.php", "server-status", "admin-local", "../", "%2e%2e", "cmd.exe", "powershell"];
  const results = [];
  for (const logPath of logPaths) {
    if (!(await pathExists(logPath))) continue;
    const tail = await readTail(logPath);
    const lines = tail.split(/\r?\n/).filter(Boolean).slice(-1500);
    let suspicious = 0;
    let serverErrors = 0;
    let authOrForbidden = 0;
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (suspiciousNeedles.some((needle) => lower.includes(needle))) suspicious += 1;
      if (/\s5\d\d\s/.test(line) || /status[=:]"?5\d\d/.test(lower)) serverErrors += 1;
      if (/\s(401|403)\s/.test(line) || /status[=:]"?(401|403)/.test(lower)) authOrForbidden += 1;
    }
    results.push({ path: logPath, lines: lines.length, suspicious, serverErrors, authOrForbidden });
  }
  return { status: results.length ? "active" : "limited", logs: results };
}

function httpsCheck(url) {
  return new Promise((resolve) => {
    const started = Date.now();
    const req = https.request(url, { method: "HEAD", timeout: 9000 }, (res) => {
      res.resume();
      resolve({ url, ok: res.statusCode < 500, statusCode: res.statusCode, ms: Date.now() - started });
    });
    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });
    req.on("error", (error) => resolve({ url, ok: false, error: error.message, ms: Date.now() - started }));
    req.end();
  });
}

function tlsExpiry(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 9000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      const validTo = cert?.valid_to ? new Date(cert.valid_to) : null;
      resolve({ hostname, validTo: validTo?.toISOString() || null, daysRemaining: validTo ? Math.round((validTo - Date.now()) / 86400000) : null });
    });
    socket.on("timeout", () => {
      socket.destroy(new Error("timeout"));
    });
    socket.on("error", (error) => resolve({ hostname, error: error.message }));
  });
}

async function monitorUptimeAndTls() {
  const urls = normalizeArray(config.publicUrls).filter(Boolean);
  if (!urls.length) return { status: "limited", vantage: "local-server", uptime: [], tls: [] };
  const uptime = await Promise.all(urls.map(httpsCheck));
  const tls = await Promise.all(urls.map((url) => tlsExpiry(new URL(url).hostname)));
  return { status: "active", vantage: "local-server", uptime, tls };
}

async function monitorSysmonOrEdr() {
  const script = String.raw`
$ErrorActionPreference = "SilentlyContinue"
$services = Get-Service -Name Sysmon,Sysmon64,Sense -ErrorAction SilentlyContinue |
  Select-Object Name, DisplayName, Status
$sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName
[pscustomobject]@{ services=$services; sysmonEvents=$sysmonEvents } | ConvertTo-Json -Depth 4 -Compress
`;
  const result = await runPowerShell(script, 12000);
  if (!result.ok) return { status: "missing", error: result.error, services: [], sysmonEvents: [] };
  const services = normalizeArray(result.data.services);
  const running = services.filter((service) => String(service.Status) === "Running" || Number(service.Status) === 4);
  return {
    status: running.length ? "active" : "missing",
    services,
    sysmonEvents: normalizeArray(result.data.sysmonEvents)
  };
}

async function monitorBackups(windows) {
  const roots = new Set();
  for (const workload of appWorkloads(windows)) {
    if (workload.AppDirectory) roots.add(path.join(workload.AppDirectory, "backups"));
  }
  const results = [];
  for (const root of roots) {
    try {
      const entries = await fs.readdir(root, { withFileTypes: true });
      const files = [];
      for (const entry of entries) {
        const entryPath = path.join(root, entry.name);
        if (entry.isFile()) files.push(entryPath);
        if (entry.isDirectory()) {
          try {
            const nested = await fs.readdir(entryPath, { withFileTypes: true });
            for (const nestedEntry of nested) if (nestedEntry.isFile()) files.push(path.join(entryPath, nestedEntry.name));
          } catch {}
        }
      }
      let newest = null;
      for (const file of files) {
        const stat = await fs.stat(file);
        if (!newest || stat.mtime > newest.mtime) newest = { path: file, mtime: stat.mtime, size: stat.size };
      }
      results.push({ root, exists: true, files: files.length, newest: newest ? { path: newest.path, lastWriteTime: newest.mtime.toISOString(), ageHours: Math.round((Date.now() - newest.mtime) / 3600000), size: newest.size } : null });
    } catch {
      results.push({ root, exists: false, files: 0, newest: null });
    }
  }
  return { status: results.some((result) => result.newest) ? "active" : "limited", roots: results };
}

async function monitorDependencyAudit(windows) {
  const audits = [];
  for (const workload of appWorkloads(windows)) {
    if (!workload.AppDirectory || !(await pathExists(path.join(workload.AppDirectory, "package.json")))) continue;
    const result = process.platform === "win32"
      ? await runCommand("cmd.exe", ["/d", "/s", "/c", "npm audit --omit=dev --json"], workload.AppDirectory, 90000)
      : await runCommand("npm", ["audit", "--omit=dev", "--json"], workload.AppDirectory, 90000);
    let parsed = null;
    try {
      parsed = JSON.parse(result.stdout || "{}");
    } catch {}
    audits.push({
      workload: workload.DisplayName || workload.Name,
      directory: workload.AppDirectory,
      ok: result.ok,
      error: parsed ? null : (result.stderr || result.error || "audit output was not JSON"),
      vulnerabilities: parsed?.metadata?.vulnerabilities || null
    });
  }
  return { status: audits.length ? "active" : "limited", audits };
}

async function monitorNpmSupplyChain(windows) {
  const checks = [];
  const userNpmrcPath = path.join(os.homedir(), ".npmrc");
  const userNpmrc = await readTextFile(userNpmrcPath, "");
  const userIgnoreScripts = /^\s*ignore-scripts\s*=\s*true\s*$/im.test(userNpmrc);
  const userToken = /^\s*\/\/.*:_authToken\s*=/im.test(userNpmrc);
  const tokenEnvNames = ["NPM_TOKEN", "NODE_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"].filter((name) => !!process.env[name]);

  const workloadMap = new Map();
  for (const workload of appWorkloads(windows)) {
    if (workload.AppDirectory) workloadMap.set(String(workload.AppDirectory).toLowerCase(), workload);
  }
  for (const fallback of [
    ...normalizeArray(config.expectedWorkloads),
    { DisplayName: "MasterHUD", Name: "MasterHUD", AppDirectory: __dirname }
  ]) {
    if (await pathExists(path.join(fallback.AppDirectory, "package.json"))) {
      workloadMap.set(String(fallback.AppDirectory).toLowerCase(), fallback);
    }
  }

  for (const workload of workloadMap.values()) {
    if (!workload.AppDirectory || !(await pathExists(path.join(workload.AppDirectory, "package.json")))) continue;
    const npmrcPath = path.join(workload.AppDirectory, ".npmrc");
    const packageJsonPath = path.join(workload.AppDirectory, "package.json");
    const packageLockPath = path.join(workload.AppDirectory, "package-lock.json");
    const workflowDir = path.join(workload.AppDirectory, ".github", "workflows");
    const npmrc = await readTextFile(npmrcPath, "");
    const packageJsonText = await readTextFile(packageJsonPath, "");
    const packageLockText = await readTextFile(packageLockPath, "");
    const hasProjectNpmrc = npmrc.length > 0;
    const projectIgnoreScripts = /^\s*ignore-scripts\s*=\s*true\s*$/im.test(npmrc);
    const projectToken = /^\s*\/\/.*:_authToken\s*=/im.test(npmrc);
    const lifecycleScripts = [];
    try {
      const pkg = JSON.parse(packageJsonText || "{}");
      for (const name of ["preinstall", "install", "postinstall", "prepare"]) {
        if (pkg.scripts && Object.prototype.hasOwnProperty.call(pkg.scripts, name)) lifecycleScripts.push(name);
      }
    } catch {}

    let workflowIndicators = [];
    try {
      const workflowFiles = await fs.readdir(workflowDir, { withFileTypes: true });
      for (const entry of workflowFiles) {
        if (!entry.isFile()) continue;
        const filePath = path.join(workflowDir, entry.name);
        const text = await readTextFile(filePath, "");
        if (/shai-hulud|router_init|filev2\.getsession\.org|seed[123]\.getsession\.org/i.test(text)) {
          workflowIndicators.push(entry.name);
        }
      }
    } catch {}

    const watchedPackages = [];
    for (const pattern of ['"axios"', '"plain-crypto-js"', '"crypto-js"', '"@tanstack/']) {
      if (packageLockText.includes(pattern)) watchedPackages.push(pattern.replaceAll('"', ""));
    }

    checks.push({
      workload: workload.DisplayName || workload.Name,
      directory: workload.AppDirectory,
      hasProjectNpmrc,
      projectIgnoreScripts,
      userIgnoreScripts,
      projectToken,
      userToken,
      tokenEnvNames,
      lifecycleScripts,
      workflowIndicators,
      watchedPackages
    });
  }

  return { status: checks.length ? "active" : "limited", checks };
}

function updateChecksEnabled(name) {
  const checks = config.updateChecks || {};
  return checks[name] !== false;
}

function configuredWorkloads(windows) {
  const workloads = new Map();
  for (const workload of appWorkloads(windows)) {
    if (workload.AppDirectory) workloads.set(String(workload.AppDirectory).toLowerCase(), workload);
  }
  for (const fallback of [
    ...normalizeArray(config.expectedWorkloads),
    { DisplayName: "MasterHUD", Name: "MasterHUD", AppDirectory: __dirname }
  ]) {
    if (fallback?.AppDirectory) workloads.set(String(fallback.AppDirectory).toLowerCase(), fallback);
  }
  return [...workloads.values()];
}

function parseWingetUpgrades(output) {
  const lines = String(output || "")
    .split(/\r?\n/)
    .map((line) => line.replace(/\x1b\[[0-9;]*m/g, "").trim());
  const upgrades = [];
  for (const line of lines) {
    if (!line.trim() || /\d+\s+upgrades?\s+available/i.test(line) || /^-+$/.test(line.trim())) continue;
    if (/^Name\s+Id\s+Version\s+Available\s+Source/i.test(line)) continue;
    if (!/\swinget$/i.test(line)) continue;
    const tokens = line.split(/\s+/).filter(Boolean);
    if (tokens.length < 5) continue;
    const source = tokens.pop();
    const available = tokens.pop();
    let version = tokens.pop();
    if (tokens.at(-1) === "<" || tokens.at(-1) === ">") version = `${tokens.pop()} ${version}`;
    const id = tokens.pop();
    const item = {
      name: tokens.join(" ").trim(),
      id,
      version,
      available,
      source
    };
    if (item.name && item.id && item.available && item.source) upgrades.push(item);
  }
  return upgrades;
}

async function monitorWindowsUpdates() {
  if (!updateChecksEnabled("windows")) return { status: "disabled", count: 0, updates: [] };
  const script = String.raw`
$ErrorActionPreference = "Stop"
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
$updates = @()
foreach ($update in $result.Updates) {
  $updates += [pscustomobject]@{
    title = $update.Title
    isDownloaded = $update.IsDownloaded
    rebootRequired = $update.RebootRequired
    kbArticleIds = @($update.KBArticleIDs)
    msrcSeverity = $update.MsrcSeverity
    supportUrl = $update.SupportUrl
    categories = @($update.Categories | ForEach-Object { $_.Name })
  }
}
[pscustomobject]@{ count=$result.Updates.Count; updates=$updates } | ConvertTo-Json -Depth 5 -Compress
`;
  const result = await runPowerShell(script, 90000);
  if (!result.ok) return { status: "limited", count: 0, updates: [], error: result.error };
  return { status: "active", count: Number(result.data.count || 0), updates: normalizeArray(result.data.updates) };
}

async function monitorWingetUpdates() {
  if (!updateChecksEnabled("winget")) return { status: "disabled", upgrades: [] };
  const configuredWinget = config.wingetPath || "winget.exe";
  const discovered = await runPowerShell(String.raw`
$path = Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe' -ErrorAction SilentlyContinue |
  Sort-Object FullName -Descending |
  Select-Object -First 1 -ExpandProperty FullName
[pscustomobject]@{ path=$path } | ConvertTo-Json -Compress
`, 10000);
  const candidates = [...new Set([configuredWinget, discovered.data?.path, "winget.exe"].filter(Boolean))];
  let result = null;
  let winget = configuredWinget;
  for (const candidate of candidates) {
    winget = candidate;
    result = await runCommand(candidate, ["upgrade", "--accept-source-agreements", "--disable-interactivity"], __dirname, 120000);
    if (result.ok || result.stdout) break;
  }
  if (!result?.ok && !result?.stdout) return { status: "limited", upgrades: [], error: result?.stderr || result?.error || "winget failed", winget };
  return {
    status: "active",
    winget,
    upgrades: parseWingetUpgrades(result.stdout),
    rawSummary: String(result.stdout || "").split(/\r?\n/).map((line) => line.trim()).filter((line) => /\d+\s+upgrades?\s+available/i.test(line)).at(-1) || ""
  };
}

async function monitorNpmOutdated(windows) {
  if (!updateChecksEnabled("npm")) return { status: "disabled", workloads: [] };
  const workloads = [];
  for (const workload of configuredWorkloads(windows)) {
    if (!workload.AppDirectory || !(await pathExists(path.join(workload.AppDirectory, "package.json")))) continue;
    const result = process.platform === "win32"
      ? await runCommand("cmd.exe", ["/d", "/s", "/c", "npm outdated --json"], workload.AppDirectory, 90000)
      : await runCommand("npm", ["outdated", "--json"], workload.AppDirectory, 90000);
    let parsed = {};
    try {
      parsed = JSON.parse(result.stdout || "{}");
    } catch {}
    workloads.push({
      workload: workload.DisplayName || workload.Name,
      directory: workload.AppDirectory,
      ok: result.ok || !!result.stdout,
      error: result.stdout ? "" : (result.stderr || result.error || ""),
      packages: Object.entries(parsed).map(([name, info]) => ({
        name,
        current: info.current,
        wanted: info.wanted,
        latest: info.latest,
        type: info.type || ""
      }))
    });
  }
  return { status: workloads.length ? "active" : "limited", workloads };
}

async function monitorGitDrift(windows) {
  if (!updateChecksEnabled("git")) return { status: "disabled", repos: [] };
  const repos = [];
  for (const workload of configuredWorkloads(windows)) {
    if (!workload.AppDirectory || !(await pathExists(path.join(workload.AppDirectory, ".git")))) continue;
    const safeDir = `safe.directory=${workload.AppDirectory.replaceAll("\\", "/")}`;
    const status = await runCommand("git", ["-c", safeDir, "status", "--short", "--branch"], workload.AppDirectory, 30000);
    const head = await runCommand("git", ["-c", safeDir, "rev-parse", "--short", "HEAD"], workload.AppDirectory, 30000);
    const branch = await runCommand("git", ["-c", safeDir, "branch", "--show-current"], workload.AppDirectory, 30000);
    repos.push({
      workload: workload.DisplayName || workload.Name,
      directory: workload.AppDirectory,
      ok: status.ok,
      branch: String(branch.stdout || "").trim(),
      head: String(head.stdout || "").trim(),
      status: String(status.stdout || status.stderr || status.error || "").trim()
    });
  }
  return { status: repos.length ? "active" : "limited", repos };
}

async function monitorRuntimeVersions() {
  if (!updateChecksEnabled("versions")) return { status: "disabled", commands: [] };
  const commands = [];
  for (const item of normalizeArray(config.versionCommands)) {
    if (!item?.name || !item?.command) continue;
    const result = await runCommand("cmd.exe", ["/d", "/c", item.command], currentAppRoot(), 30000);
    commands.push({
      name: item.name,
      command: item.command,
      ok: result.ok,
      output: String(result.stdout || "").trim(),
      error: String(result.stderr || result.error || "").trim()
    });
  }
  return { status: commands.length ? "active" : "limited", commands };
}

async function monitorUpdateWatch(windows) {
  const [windowsUpdates, winget, npmOutdated, gitDrift, versions] = await Promise.all([
    safeSlowMonitor("windows updates", monitorWindowsUpdates, { count: 0, updates: [] }),
    safeSlowMonitor("winget updates", monitorWingetUpdates, { upgrades: [] }),
    safeSlowMonitor("npm outdated", () => monitorNpmOutdated(windows), { workloads: [] }),
    safeSlowMonitor("git drift", () => monitorGitDrift(windows), { repos: [] }),
    safeSlowMonitor("runtime versions", monitorRuntimeVersions, { commands: [] })
  ]);
  return {
    status: "active",
    capturedAt: new Date().toISOString(),
    windows: windowsUpdates,
    winget,
    npmOutdated,
    gitDrift,
    versions
  };
}

const riskOrder = { low: 0, medium: 1, high: 2 };

function maxRisk(...levels) {
  return levels.reduce((winner, level) => (riskOrder[level] > riskOrder[winner] ? level : winner), "low");
}

function versionTriplet(value) {
  const match = String(value || "").match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

function versionChangeRisk(current, available) {
  const from = versionTriplet(current);
  const to = versionTriplet(available);
  if (!from || !to) return { level: "medium", reason: "version format needs manual review" };
  if (to.major > from.major) return { level: "high", reason: "major version change" };
  if (to.minor > from.minor) return { level: "medium", reason: "minor version change" };
  if (to.patch > from.patch) return { level: "low", reason: "patch version change" };
  return { level: "low", reason: "same major/minor/patch family" };
}

function npmPackageUrl(name) {
  return `https://www.npmjs.com/package/${encodeURIComponent(name).replace(/%2F/g, "/")}`;
}

function windowsUpdateRisk(update) {
  const text = `${update.title || ""} ${normalizeArray(update.categories).join(" ")} ${update.msrcSeverity || ""}`.toLowerCase();
  let level = /defender|security intelligence/.test(text) ? "low" : "medium";
  const reasons = [];
  if (/defender|security intelligence/.test(text)) {
    reasons.push("Defender intelligence updates are usually low app-break risk");
  }
  if (/cumulative|servicing stack|\.net|framework|visual c\+\+|runtime/.test(text)) {
    level = maxRisk(level, "medium");
    reasons.push("system/runtime update can affect services or require reboot");
  }
  if (/driver|firmware|guest|virtio/.test(text)) {
    level = maxRisk(level, "high");
    reasons.push("driver or VM guest tooling update");
  }
  if (update.rebootRequired) reasons.push("reboot required");
  return { level, reason: reasons.join("; ") || "review KB/support notes before install" };
}

function wingetUpdateRisk(item) {
  const text = `${item.name || ""} ${item.id || ""}`.toLowerCase();
  let level = "medium";
  const reasons = [];
  if (/postgres|postgresql|caddy|node|nodejs|git|nssm|openssl|tailscale/.test(text)) {
    level = maxRisk(level, "high");
    reasons.push("core runtime or infrastructure tool");
  }
  if (/virtio|driver|guest|vmware|hyper-v/.test(text)) {
    level = maxRisk(level, "high");
    reasons.push("VM guest/driver tooling");
  }
  if (/visual c\+\+|redistributable|runtime|\.net/.test(text)) {
    level = maxRisk(level, "medium");
    reasons.push("shared Windows runtime dependency");
  }
  return { level, reason: reasons.join("; ") || "third-party package update" };
}

function npmUpdateRisk(pkg) {
  const versionRisk = versionChangeRisk(pkg.current, pkg.latest || pkg.wanted);
  const text = `${pkg.name || ""} ${pkg.type || ""}`.toLowerCase();
  let level = versionRisk.level;
  const reasons = [versionRisk.reason];
  if (/pg|postgres|mysql|mssql|sqlite|sequelize|prisma|typeorm/.test(text)) {
    level = maxRisk(level, "high");
    reasons.push("database driver or database access package");
  } else if (/express|fastify|koa|passport|jsonwebtoken|bcrypt|cookie|session|auth|caddy|sharp/.test(text)) {
    level = maxRisk(level, "medium");
    reasons.push("server/auth/media package");
  }
  if (/dependencies|prod|production/.test(text)) {
    level = maxRisk(level, "medium");
    reasons.push("production dependency");
  }
  return { level, reason: reasons.join("; ") };
}

function updateSection(title, rows, emptyText) {
  const lines = [``, title];
  if (!rows.length) {
    lines.push(`- ${emptyText}`);
    return lines;
  }
  return lines.concat(rows);
}

function buildUpdateBrief(watch = {}) {
  const windowsUpdates = normalizeArray(watch.windows?.updates);
  const winget = normalizeArray(watch.winget?.upgrades);
  const npmWorkloads = normalizeArray(watch.npmOutdated?.workloads);
  const npmPackages = npmWorkloads.flatMap((workload) => normalizeArray(workload.packages).map((pkg) => ({ workload: workload.workload, directory: workload.directory, ...pkg })));
  const repos = normalizeArray(watch.gitDrift?.repos);
  const versions = normalizeArray(watch.versions?.commands);
  const pending = windowsUpdates.length + winget.length + npmPackages.length + repos.filter((repo) => /\bbehind\b|\[ahead|\?\?|^\s*M|^\s*A|^\s*D/im.test(repo.status || "")).length;
  const lines = [
    "UPDATE BRIEF - read-only",
    `Profile: ${config.profile?.label || config.profile?.active || "Default"}`,
    `Captured: ${watch.capturedAt || new Date().toISOString()}`,
    `Pending update signals: ${pending}`,
    "Nothing was installed, upgraded, restarted, or changed."
  ];

  if (versions.length) {
    lines.push("", "CURRENT RUNTIME VERSIONS");
    for (const item of versions) {
      lines.push(`- ${item.name}: ${item.output || item.error || "unknown"}${item.ok ? "" : " (check failed)"}`);
    }
  }

  lines.push(...updateSection("WINDOWS UPDATE", windowsUpdates.map((update) => {
    const risk = windowsUpdateRisk(update);
    const kb = normalizeArray(update.kbArticleIds).filter(Boolean).map((id) => `KB${id}`).join(", ") || "KB not reported";
    const categories = normalizeArray(update.categories).filter(Boolean).join(", ") || "no category reported";
    return [
      `- [${risk.level.toUpperCase()}] ${update.title || "Pending Windows update"}`,
      `  current: installed Windows baseline | available: ${kb}`,
      `  reboot: ${update.rebootRequired ? "yes" : "not reported"} | categories: ${categories}`,
      `  look ahead: ${update.supportUrl || "review the KB/support notes in Windows Update"} | ${risk.reason}`
    ].join("\n");
  }), "No pending Windows updates detected."));

  lines.push(...updateSection("WINGET PACKAGES", winget.map((item) => {
    const risk = wingetUpdateRisk(item);
    return [
      `- [${risk.level.toUpperCase()}] ${item.name || item.id || "winget package"}`,
      `  id: ${item.id || "unknown"} | source: ${item.source || "unknown"}`,
      `  current: ${item.version || "unknown"} | available: ${item.available || "unknown"}`,
      `  look ahead: winget show --id ${item.id || "<package-id>"} --accept-source-agreements | ${risk.reason}`
    ].join("\n");
  }), "No winget package upgrades detected."));

  lines.push(...updateSection("NPM PACKAGES", npmPackages.map((pkg) => {
    const risk = npmUpdateRisk(pkg);
    return [
      `- [${risk.level.toUpperCase()}] ${pkg.workload || "workload"} / ${pkg.name}`,
      `  current: ${pkg.current || "unknown"} | wanted: ${pkg.wanted || "unknown"} | latest: ${pkg.latest || "unknown"} | type: ${pkg.type || "unknown"}`,
      `  look ahead: ${npmPackageUrl(pkg.name)} | npm view ${pkg.name} version time repository homepage`,
      `  test before install: npm ci --ignore-scripts, app health, tablet readiness, and service restart on a branch`,
      `  risk note: ${risk.reason}`
    ].join("\n");
  }), "No npm package updates detected."));

  lines.push(...updateSection("GIT REPOS", repos.map((repo) => [
    `- ${repo.workload || "repo"}: ${repo.status || "unknown"}`,
    `  branch: ${repo.branch || "unknown"} | head: ${repo.head || "unknown"}`,
    `  directory: ${repo.directory || "unknown"}`
  ].join("\n")), "No Git repositories configured."));

  lines.push(
    "",
    "LOOK-AHEAD RULES BEFORE INSTALL",
    "- Read release notes or KB notes first, especially for database drivers, Node/Caddy/PostgreSQL, VM guest tools, and Windows runtime updates.",
    "- Take/confirm backups before app/runtime/database updates. For VM driver or Windows runtime updates, use a maintenance window and keep console access available.",
    "- Update one class at a time: app npm packages, Windows Update, winget runtime tools. Do not bundle risky changes together.",
    "- After installing: verify app health, Caddy validate, tablet readiness, public HTTPS, DB counts, and service restart state."
  );

  return lines.join("\n");
}

async function safeSlowMonitor(name, fn, fallback) {
  try {
    return await fn();
  } catch (error) {
    return { status: "limited", monitor: name, error: error.message, ...fallback };
  }
}

function slowFinding(severity, title, detail) {
  return { Severity: severity, Title: title, Detail: detail };
}

function coverageItem(name, status, detail) {
  return { Name: name, Status: status, Detail: detail };
}

function summarizeSlowSecurity(monitors) {
  const findings = [];
  const coverage = [];

  const integrity = monitors.fileIntegrity;
  coverage.push(coverageItem("File integrity hashing", integrity?.status || "limited", integrity?.baselineCreated ? "Baseline created for workload anchor files." : `Checked ${integrity?.checked || 0} workload anchor file(s).`));
  for (const item of integrity?.changed || []) findings.push(slowFinding("hot", "File hash changed", `${item.workload}: ${item.label} changed at ${item.path}.`));
  for (const item of integrity?.missing || []) findings.push(slowFinding("hot", "Baseline file missing", `${item.workload}: ${item.label} missing at ${item.path}.`));

  const logs = monitors.logAnomalies;
  coverage.push(coverageItem("Caddy/app log anomaly parsing", logs?.status || "limited", `${logs?.logs?.length || 0} log file(s) parsed for probes and error bursts.`));
  for (const log of logs?.logs || []) {
    if (log.suspicious >= 5) findings.push(slowFinding("warm", "Suspicious web probes", `${log.suspicious} suspicious probe line(s) in ${log.path}.`));
    if (log.serverErrors >= 10) findings.push(slowFinding("warm", "HTTP 5xx burst", `${log.serverErrors} server-error line(s) in ${log.path}.`));
    if (log.authOrForbidden >= 25) findings.push(slowFinding("warm", "Auth/forbidden burst", `${log.authOrForbidden} 401/403 line(s) in ${log.path}.`));
  }

  const uptime = monitors.uptime;
  coverage.push(coverageItem("External uptime and TLS checks", uptime?.status || "limited", "Checks public HTTPS endpoints and certificate expiry from this server."));
  for (const check of uptime?.uptime || []) if (!check.ok) findings.push(slowFinding("hot", "Public site check failed", `${check.url} failed: ${check.error || check.statusCode}.`));
  for (const cert of uptime?.tls || []) if (cert.daysRemaining != null && cert.daysRemaining < 21) findings.push(slowFinding("hot", "TLS certificate expiring", `${cert.hostname} expires in ${cert.daysRemaining} day(s).`));

  const sysmon = monitors.sysmon;
  coverage.push(coverageItem("Sysmon or EDR telemetry", sysmon?.status || "missing", sysmon?.status === "active" ? "Sysmon or Defender for Endpoint style service is running." : "No running Sysmon/EDR service was detected."));
  if (sysmon?.status !== "active") findings.push(slowFinding("warm", "Sysmon/EDR not active", "Install Sysmon or enable EDR for richer compromise forensics."));

  const backups = monitors.backups;
  coverage.push(coverageItem("Backup restore verification", backups?.status || "limited", `${backups?.roots?.length || 0} backup root(s) checked for freshness. Restore drills still need explicit report files.`));
  for (const root of backups?.roots || []) {
    if (!root.exists) findings.push(slowFinding("warm", "Backup folder missing", `${root.root} does not exist.`));
    else if (!root.newest) findings.push(slowFinding("warm", "No backup files found", `${root.root} has no backup files.`));
    else if (root.newest.ageHours > 72) findings.push(slowFinding("warm", "Backup stale", `${root.root} newest backup is ${root.newest.ageHours} hours old.`));
  }

  const audits = monitors.dependencyAudit;
  coverage.push(coverageItem("Dependency audit monitoring", audits?.status || "limited", `${audits?.audits?.length || 0} production dependency audit(s) checked.`));
  for (const audit of audits?.audits || []) {
    const vulns = audit.vulnerabilities;
    if (!vulns) findings.push(slowFinding("warm", "Dependency audit failed", `${audit.workload}: ${audit.error || "audit failed"}.`));
    else if ((vulns.critical || 0) + (vulns.high || 0) > 0) findings.push(slowFinding("hot", "High dependency vulnerabilities", `${audit.workload}: ${vulns.critical || 0} critical, ${vulns.high || 0} high.`));
    else if ((vulns.moderate || 0) + (vulns.low || 0) > 0) findings.push(slowFinding("warm", "Dependency vulnerabilities", `${audit.workload}: ${vulns.moderate || 0} moderate, ${vulns.low || 0} low.`));
  }

  const npmSupplyChain = monitors.npmSupplyChain;
  coverage.push(coverageItem("npm supply-chain guardrails", npmSupplyChain?.status || "limited", `${npmSupplyChain?.checks?.length || 0} npm workload(s) checked for install-script policy, tokens, and known campaign indicators.`));
  for (const check of npmSupplyChain?.checks || []) {
    if (!check.hasProjectNpmrc) findings.push(slowFinding("warm", "npm policy missing", `${check.workload}: project .npmrc is missing.`));
    if (!check.projectIgnoreScripts) findings.push(slowFinding("hot", "npm install scripts enabled", `${check.workload}: project .npmrc does not enforce ignore-scripts=true.`));
    if (!check.userIgnoreScripts) findings.push(slowFinding("hot", "npm user install scripts enabled", `${check.workload}: user .npmrc does not enforce ignore-scripts=true.`));
    if (check.projectToken || check.userToken || check.tokenEnvNames?.length) findings.push(slowFinding("hot", "npm/GitHub token exposed to install host", `${check.workload}: token material is visible in npm config or environment.`));
    if (check.lifecycleScripts?.length) findings.push(slowFinding("hot", "Root npm lifecycle scripts", `${check.workload}: package.json defines ${check.lifecycleScripts.join(", ")}.`));
    if (check.workflowIndicators?.length) findings.push(slowFinding("hot", "npm campaign workflow indicator", `${check.workload}: suspicious indicator(s) in ${check.workflowIndicators.join(", ")}.`));
    if (check.watchedPackages?.length) findings.push(slowFinding("warm", "Watched npm package present", `${check.workload}: lockfile contains ${check.watchedPackages.join(", ")}; verify pinned clean versions before installing.`));
  }

  const updateWatch = monitors.updateWatch;
  const windowsUpdateCount = Number(updateWatch?.windows?.count || 0);
  const wingetCount = normalizeArray(updateWatch?.winget?.upgrades).length;
  const npmOutdatedCount = normalizeArray(updateWatch?.npmOutdated?.workloads).reduce((sum, workload) => sum + normalizeArray(workload.packages).length, 0);
  const gitBehind = normalizeArray(updateWatch?.gitDrift?.repos).filter((repo) => /\bbehind\b/i.test(repo.status || "")).length;
  coverage.push(coverageItem("Update watch", updateWatch?.status || "limited", `${windowsUpdateCount} Windows update(s), ${wingetCount} winget upgrade(s), ${npmOutdatedCount} npm outdated package(s), ${gitBehind} repo(s) behind.`));
  if (windowsUpdateCount) {
    const securityUpdates = normalizeArray(updateWatch.windows.updates).filter((update) => /security|defender|malicious|cumulative/i.test(update.title || ""));
    findings.push(slowFinding(securityUpdates.length ? "hot" : "warm", "Windows updates pending", `${windowsUpdateCount} Windows update(s) pending${securityUpdates.length ? ", including security-related updates" : ""}.`));
  }
  if (wingetCount) findings.push(slowFinding("warm", "winget upgrades available", `${wingetCount} package upgrade(s) available through winget.`));
  if (npmOutdatedCount) findings.push(slowFinding("warm", "npm packages outdated", `${npmOutdatedCount} npm package(s) are behind wanted/latest versions.`));
  if (gitBehind) findings.push(slowFinding("warm", "Git repos behind upstream", `${gitBehind} repo(s) report being behind their upstream branch.`));

  return { findings, coverage };
}

async function runSlowSecurityMonitors(windows, force = false) {
  if (slowSecurity.running) return slowSecurity;
  if (!force && slowSecurity.capturedAt && Date.now() - Date.parse(slowSecurity.capturedAt) < slowSecurityMs) return slowSecurity;
  slowSecurity.running = true;
  try {
    const monitors = {
      fileIntegrity: await safeSlowMonitor("file integrity", () => monitorFileIntegrity(windows), { checked: 0, changed: [], missing: [] }),
      logAnomalies: await safeSlowMonitor("log anomalies", () => monitorLogAnomalies(windows), { logs: [] }),
      uptime: await safeSlowMonitor("uptime and TLS", monitorUptimeAndTls, { uptime: [], tls: [] }),
      sysmon: await safeSlowMonitor("sysmon", monitorSysmonOrEdr, { services: [], sysmonEvents: [] }),
      backups: await safeSlowMonitor("backups", () => monitorBackups(windows), { roots: [] }),
      dependencyAudit: await safeSlowMonitor("dependency audit", () => monitorDependencyAudit(windows), { audits: [] }),
      npmSupplyChain: await safeSlowMonitor("npm supply chain", () => monitorNpmSupplyChain(windows), { checks: [] }),
      updateWatch: await safeSlowMonitor("update watch", () => monitorUpdateWatch(windows), {})
    };
    const summary = summarizeSlowSecurity(monitors);
    slowSecurity = {
      capturedAt: new Date().toISOString(),
      running: false,
      ...monitors,
      findings: summary.findings,
      coverage: summary.coverage
    };
  } catch (error) {
    slowSecurity = {
      ...slowSecurity,
      capturedAt: new Date().toISOString(),
      running: false,
      findings: [slowFinding("warm", "Slow security monitors failed", error.message)],
      coverage: [coverageItem("Slow security monitors", "limited", error.message)]
    };
  }
  return slowSecurity;
}

async function windowsSnapshot() {
  const script = String.raw`
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$nics = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface |
  Where-Object { $_.Name -notmatch "Loopback|isatap|Teredo" } |
  Select-Object Name, BytesReceivedPersec, BytesSentPersec, PacketsReceivedErrors, PacketsOutboundErrors

$disks = Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk |
  Where-Object { $_.Name -ne "_Total" } |
  Select-Object Name, PercentFreeSpace, FreeMegabytes, DiskReadBytesPersec, DiskWriteBytesPersec, CurrentDiskQueueLength

$volumes = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
  Select-Object DeviceID, VolumeName, Size, FreeSpace

$servicesAll = Get-CimInstance Win32_Service |
  Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName

$procRuntime = @{}
Get-Process | ForEach-Object { $procRuntime[$_.Id] = $_ }
$procCim = @{}
Get-CimInstance Win32_Process | ForEach-Object { $procCim[[int]$_.ProcessId] = $_ }

function Get-ProcessIdentity($Name, $Path, $CommandLine, $OriginReason, $ServiceNames, $ParentServiceNames) {
  $text = "$Name $Path $CommandLine $ServiceNames $ParentServiceNames"
  if ($ServiceNames -match "Microsoft Defender" -or $Name -eq "MsMpEng") {
    return [pscustomobject]@{ Label="Microsoft Defender"; Role="endpoint protection"; Trust="system" }
  }
  if ($ServiceNames -match "Remote Desktop" -or $CommandLine -match "TermService") {
    return [pscustomobject]@{ Label="Remote Desktop Services"; Role="remote administration"; Trust="management" }
  }
  if ($ServiceNames -match "Windows Management Instrumentation" -or $Name -eq "WmiPrvSE") {
    return [pscustomobject]@{ Label="Windows Management Instrumentation"; Role="system telemetry"; Trust="system" }
  }
  if ($ServiceNames -match "IDrive" -or $Name -match "^id_") {
    return [pscustomobject]@{ Label="IDrive backup agent"; Role="backup/sync"; Trust="third-party" }
  }
  if ($text -match "CaddyProxy|caddy.exe|Caddyfile") {
    return [pscustomobject]@{ Label="Caddy reverse proxy"; Role="public web ingress"; Trust="app" }
  }
  if ($Name -match "postgres|pg_ctl" -or $text -match "PostgreSQL") {
    return [pscustomobject]@{ Label="PostgreSQL database"; Role="database"; Trust="app" }
  }
  if ($Name -eq "GoogleDriveFS") {
    return [pscustomobject]@{ Label="Google Drive sync"; Role="cloud file sync"; Trust="third-party" }
  }
  if ($Name -eq "Code") {
    return [pscustomobject]@{ Label="Visual Studio Code"; Role="developer tool"; Trust="user" }
  }
  if ($Name -eq "codex") {
    return [pscustomobject]@{ Label="OpenAI Codex extension helper"; Role="developer assistant"; Trust="user" }
  }
  if ($Name -eq "pythonw" -and $text -match "Anki") {
    return [pscustomobject]@{ Label="Anki desktop"; Role="local desktop app"; Trust="user" }
  }
  if ($Name -eq "Taskmgr") {
    return [pscustomobject]@{ Label="Task Manager"; Role="system inspection"; Trust="system" }
  }
  if ($Name -match "svchost|lsass|csrss|dwm|wininit|services|spoolsv|explorer|System") {
    return [pscustomobject]@{ Label="Windows $Name"; Role="Windows component"; Trust="system" }
  }
  if ($OriginReason -eq "Windows service") {
    return [pscustomobject]@{ Label=if ($ServiceNames) { $ServiceNames } else { "$Name service" }; Role="Windows service"; Trust="service" }
  }
  if ($OriginReason -eq "User profile app") {
    return [pscustomobject]@{ Label="$Name user app"; Role="interactive/user process"; Trust="user" }
  }
  if ($OriginReason -eq "Installed application") {
    return [pscustomobject]@{ Label="$Name installed app"; Role="installed software"; Trust="third-party" }
  }
  return [pscustomobject]@{ Label=$Name; Role=$OriginReason; Trust="unknown" }
}

$procs = Get-Process |
  Sort-Object CPU -Descending |
  Select-Object -First 120 |
  ForEach-Object {
  $runtime = $_
  $processId = [int]$runtime.Id
  $cim = $procCim[$processId]
  $ownedServices = @($servicesAll | Where-Object { [int]$_.ProcessId -eq $processId })
  $parent = if ($cim) { $procRuntime[[int]$cim.ParentProcessId] } else { $null }
  $parentServices = if ($cim -and [int]$cim.ParentProcessId -gt 0) { @($servicesAll | Where-Object { [int]$_.ProcessId -eq [int]$cim.ParentProcessId }) } else { @() }
  $version = $null
  $exePath = if ($cim -and $cim.ExecutablePath) { $cim.ExecutablePath } elseif ($runtime.Path) { $runtime.Path } else { $null }
  if ($exePath -and (Test-Path -LiteralPath $exePath)) {
    $version = (Get-Item -LiteralPath $exePath).VersionInfo
  }
  $reason = "Process"
  if ($ownedServices.Count -gt 0) { $reason = "Windows service" }
  elseif ($exePath -match "\\Windows\\System32\\|\\Windows\\SysWOW64\\") { $reason = "Windows component" }
  elseif ($exePath -match "\\Program Files\\|\\Program Files \(x86\)\\") { $reason = "Installed application" }
  elseif ($exePath -match "\\Users\\") { $reason = "User profile app" }
  $serviceNames = (@($ownedServices | ForEach-Object { $_.DisplayName }) -join ", ")
  $parentServiceNames = (@($parentServices | ForEach-Object { $_.DisplayName }) -join ", ")
  $identity = Get-ProcessIdentity $runtime.ProcessName $exePath $(if ($cim) { $cim.CommandLine } else { $null }) $reason $serviceNames $parentServiceNames
  [pscustomobject]@{
    Id = $processId
    ProcessName = $runtime.ProcessName
    FriendlyName = $identity.Label
    Role = $identity.Role
    Trust = $identity.Trust
    CPU = $runtime.CPU
    PM = $runtime.PM
    WS = $runtime.WS
    Handles = $runtime.Handles
    Threads = $runtime.Threads.Count
    Path = $exePath
    CommandLine = if ($cim) { $cim.CommandLine } else { $null }
    ParentProcessId = if ($cim) { [int]$cim.ParentProcessId } else { 0 }
    ParentProcessName = if ($parent) { $parent.ProcessName } else { $null }
    CreatedAt = if ($cim -and $cim.CreationDate) { $cim.CreationDate.ToUniversalTime().ToString("o") } else { $null }
    Company = if ($version) { $version.CompanyName } else { $null }
    Product = if ($version) { $version.ProductName } else { $null }
    Description = if ($version) { $version.FileDescription } else { $null }
    Services = @($ownedServices | Select-Object Name, DisplayName, StartMode, State)
    ParentServices = @($parentServices | Select-Object Name, DisplayName, StartMode, State)
    OriginReason = $reason
  }
}

$ports = Get-NetTCPConnection -State Listen |
  Sort-Object LocalPort |
  Select-Object -First 120 LocalAddress, LocalPort, OwningProcess,
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}

$connections = Get-NetTCPConnection -State Established |
  Sort-Object RemoteAddress, RemotePort |
  Select-Object -First 120 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}

$services = $servicesAll |
  Where-Object { $_.State -eq "Running" -and $_.StartMode -eq "Auto" } |
  Select-Object -First 120 Name, DisplayName, State, StartMode, ProcessId, PathName

function New-PathCheck($Label, $Path, $ExpectedType = "Any") {
  if (-not $Path) {
    return [pscustomobject]@{ Label=$Label; Path=$null; Exists=$false; Type=$ExpectedType; Size=$null; LastWriteTime=$null; Status="missing" }
  }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if (-not $item) {
    return [pscustomobject]@{ Label=$Label; Path=$Path; Exists=$false; Type=$ExpectedType; Size=$null; LastWriteTime=$null; Status="missing" }
  }
  $actualType = if ($item.PSIsContainer) { "Directory" } else { "File" }
  $wrongType = $ExpectedType -ne "Any" -and $ExpectedType -ne $actualType
  [pscustomobject]@{
    Label=$Label
    Path=$item.FullName
    Exists=$true
    Type=$actualType
    Size=if ($item.PSIsContainer) { $null } else { $item.Length }
    LastWriteTime=$item.LastWriteTimeUtc.ToString("o")
    Status=if ($wrongType) { "wrong-type" } else { "ok" }
  }
}

function Get-ExecutablePathFromCommand($Command) {
  if (-not $Command) { return $null }
  if ($Command -match '^"([^"]+)"') { return $Matches[1] }
  if ($Command -match '^(.+?\.exe)\b') { return $Matches[1] }
  return $Command
}

function Get-RecentAppFiles($AppDirectory) {
  if (-not $AppDirectory -or -not (Test-Path -LiteralPath $AppDirectory)) { return @() }
  $roots = @($AppDirectory)
  foreach ($name in @("backend","src","public","ops","logs","data","scripts")) {
    $candidate = Join-Path $AppDirectory $name
    if (Test-Path -LiteralPath $candidate) { $roots += $candidate }
  }
  $files = foreach ($root in $roots) {
    Get-ChildItem -LiteralPath $root -Force -File -ErrorAction SilentlyContinue
  }
  $files |
    Where-Object { $_.FullName -notmatch "\\node_modules\\|\\.git\\|\\backups\\" } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 12 @{Name="Path";Expression={$_.FullName}}, Length, @{Name="LastWriteTime";Expression={$_.LastWriteTimeUtc.ToString("o")}}
}

$workloads = foreach ($svc in $servicesAll) {
  $base = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
  $paramsPath = "$base\Parameters"
  $params = $null
  if (Test-Path $paramsPath) {
    $params = Get-ItemProperty $paramsPath
  }
  $isAppService = $false
  if ($svc.PathName -match "\\apps\\|nssm.exe|node.exe|caddy.exe|postgres") { $isAppService = $true }
  if ($params -and (($params.AppDirectory -match "\\apps\\") -or ($params.Application -match "node.exe|caddy.exe|postgres"))) { $isAppService = $true }
  if ($isAppService) {
    $envKeys = @()
    if ($params -and $params.AppEnvironmentExtra) {
      $envKeys = @($params.AppEnvironmentExtra | ForEach-Object { ($_ -split "=", 2)[0] } | Where-Object { $_ })
    }
    $appDirectory = if ($params) { $params.AppDirectory } else { $null }
    $application = if ($params) { $params.Application } else { $null }
    $appParameters = if ($params) { $params.AppParameters } else { $null }
    $checks = @()
    $checks += New-PathCheck "service image" (Get-ExecutablePathFromCommand $svc.PathName) "File"
    if ($appDirectory) { $checks += New-PathCheck "app directory" $appDirectory "Directory" }
    if ($application) { $checks += New-PathCheck "application" $application "File" }
    if ($appDirectory -and $appParameters -and $appParameters -match "^[^\s]+\.js$") {
      $checks += New-PathCheck "entrypoint" (Join-Path $appDirectory $appParameters) "File"
    }
    if ($appDirectory) {
      $checks += New-PathCheck "package.json" (Join-Path $appDirectory "package.json") "File"
      $checks += New-PathCheck "package-lock.json" (Join-Path $appDirectory "package-lock.json") "File"
      $checks += New-PathCheck "node_modules" (Join-Path $appDirectory "node_modules") "Directory"
      $checks += New-PathCheck "git metadata" (Join-Path $appDirectory ".git") "Directory"
      if (($svc.Name -match "Caddy") -or ($application -match "caddy")) {
        $checks += New-PathCheck "Caddyfile" (Join-Path $appDirectory "Caddyfile") "File"
      }
    }
    if ($params -and $params.AppStdout) { $checks += New-PathCheck "stdout log" $params.AppStdout "File" }
    if ($params -and $params.AppStderr) { $checks += New-PathCheck "stderr log" $params.AppStderr "File" }

    $recentChanges = @()

    $missing = @($checks | Where-Object { $_.Status -ne "ok" })
    $health = if ($svc.State -ne "Running") { "down" } elseif ($missing.Count -gt 0) { "drift" } else { "ok" }
    [pscustomobject]@{
      Name = $svc.Name
      DisplayName = $svc.DisplayName
      State = $svc.State
      StartMode = $svc.StartMode
      ProcessId = $svc.ProcessId
      Account = (Get-ItemProperty $base).ObjectName
      ServiceImage = $svc.PathName
      AppDirectory = $appDirectory
      Application = $application
      AppParameters = $appParameters
      Stdout = if ($params) { $params.AppStdout } else { $null }
      Stderr = if ($params) { $params.AppStderr } else { $null }
      EnvKeys = $envKeys
      Health = $health
      Checks = $checks
      Missing = $missing
      RecentChanges = $recentChanges
    }
  }
}

$masterTasks = Get-ScheduledTask -TaskName "MasterHUD","MasterHUD-FailedLogonBlocker" -ErrorAction SilentlyContinue |
  Select-Object TaskName, TaskPath, State
$scheduledTasks = @(
  $masterTasks
  Get-ScheduledTask |
    Where-Object { $_.State -ne "Disabled" } |
    Select-Object -First 80 TaskName, TaskPath, State
) | Where-Object { $_ } | Sort-Object TaskName -Unique

$startupCommands = Get-CimInstance Win32_StartupCommand |
  Select-Object -First 80 Name, Command, Location, User

$firewallExposure = foreach ($r in (Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow)) {
  $rulePorts = $r | Get-NetFirewallPortFilter
  $ruleAddr = $r | Get-NetFirewallAddressFilter
  $managementRule = $r.DisplayName -match "Remote Desktop|RDP|OpenSSH|WinRM|File and Printer|SMB"
  $riskyPort = $rulePorts.LocalPort -in @("22","135","139","445","3389","5985","5986") -or ($rulePorts.LocalPort -eq "Any" -and $managementRule)
  $broadRemote = $ruleAddr.RemoteAddress -in @("Any","Internet")
  if ($riskyPort -and $broadRemote) {
    [pscustomobject]@{
      Name = $r.DisplayName
      Profile = [string]$r.Profile
      Protocol = [string]$rulePorts.Protocol
      LocalPort = [string]$rulePorts.LocalPort
      RemoteAddress = [string]$ruleAddr.RemoteAddress
      Risk = "broad-management-exposure"
    }
  }
}

$listeningRisks = $ports | Where-Object {
  $_.LocalAddress -notin @("127.0.0.1","::1") -and $_.LocalPort -in @(22,135,139,445,3389,5985,5986,8080,8081,8092)
} | Select-Object LocalAddress, LocalPort, OwningProcess, ProcessName

$suspiciousProcesses = $procs | Where-Object {
  $_.Path -match "\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\|\\ProgramData\\" -or
  ($_.OriginReason -eq "User profile app" -and $_.ProcessName -notin @("Code","codex","pythonw"))
} | Select-Object -First 20 ProcessName, Id, Path, ParentProcessName, OriginReason

$adminMembers = @()
try {
  $adminMembers = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
} catch {}

$shares = @()
try {
  $shares = Get-SmbShare | Where-Object { $_.Name -notmatch "^\w\$$|^ADMIN\$$|^IPC\$$" } |
    Select-Object Name, Path, Description
} catch {}

$defender = $null
try {
  $mp = Get-MpComputerStatus
  $defender = [pscustomobject]@{
    AntivirusEnabled = $mp.AntivirusEnabled
    RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
    BehaviorMonitorEnabled = $mp.BehaviorMonitorEnabled
    AntispywareEnabled = $mp.AntispywareEnabled
    NISEnabled = $mp.NISEnabled
    QuickScanAge = $mp.QuickScanAge
    FullScanAge = $mp.FullScanAge
    SignatureAge = $mp.AntivirusSignatureAge
  }
} catch {}

function Get-CounterValue($Path) {
  try {
    return ((Get-Counter $Path).CounterSamples | Select-Object -First 1).CookedValue
  } catch {
    return $null
  }
}

$computerSystem = Get-CimInstance Win32_ComputerSystem
$operatingSystem = Get-CimInstance Win32_OperatingSystem
$committedBytes = Get-CounterValue "\Memory\Committed Bytes"
$commitLimitBytes = Get-CounterValue "\Memory\Commit Limit"
$availableBytes = Get-CounterValue "\Memory\Available Bytes"
$allProcesses = @(Get-Process)
$processWorkingSetBytes = ($allProcesses | Measure-Object WS -Sum).Sum
$processPrivateBytes = ($allProcesses | Measure-Object PM -Sum).Sum
$balloonConfigText = ((sc.exe qc Balloon 2>$null) -join [Environment]::NewLine)
$balloonStateText = ((sc.exe query Balloon 2>$null) -join [Environment]::NewLine)
$balloonDisabled = $balloonConfigText -match "START_TYPE\s+:\s+4\s+DISABLED"
$balloonStopped = $balloonStateText -match "STATE\s+:\s+1\s+STOPPED"
$isQemu = $computerSystem.Manufacturer -match "QEMU" -or $computerSystem.Model -match "QEMU"
$commitUsage = if ($commitLimitBytes -and $commitLimitBytes -gt 0) { ($committedBytes / $commitLimitBytes) * 100 } else { 0 }
$hiddenCommitBytes = $null
if ($null -ne $committedBytes -and $null -ne $processPrivateBytes) {
  $hiddenCommitBytes = [double]$committedBytes - [double]$processPrivateBytes
  if ($hiddenCommitBytes -lt 0) { $hiddenCommitBytes = 0 }
}
$vmMemoryStatus = "ok"
$vmMemoryDetail = "VM memory accounting is normal."
if ($isQemu -and (-not $balloonDisabled -or -not $balloonStopped)) {
  $vmMemoryStatus = "bad"
  $vmMemoryDetail = "QEMU VirtIO balloon driver is enabled or running; host-side ballooning can make Windows report RAM as full without a process owner."
} elseif ($commitUsage -gt 80 -and $processPrivateBytes -gt 0 -and $hiddenCommitBytes -gt ($processPrivateBytes * 3)) {
  $vmMemoryStatus = "bad"
  $vmMemoryDetail = "Windows committed memory is high but process private memory is low; this matches VM ballooning or kernel/driver allocation pressure."
} elseif ($commitUsage -gt 70) {
  $vmMemoryStatus = "warn"
  $vmMemoryDetail = "Committed memory is elevated; watch for ballooning or a process leak."
}
$vmMemory = [pscustomobject]@{
  Status = $vmMemoryStatus
  Detail = $vmMemoryDetail
  IsQemu = $isQemu
  Manufacturer = $computerSystem.Manufacturer
  Model = $computerSystem.Model
  HypervisorPresent = $computerSystem.HypervisorPresent
  TotalBytes = [double]$operatingSystem.TotalVisibleMemorySize * 1KB
  FreeBytes = [double]$operatingSystem.FreePhysicalMemory * 1KB
  AvailableBytes = $availableBytes
  CommittedBytes = $committedBytes
  CommitLimitBytes = $commitLimitBytes
  CommitUsage = $commitUsage
  ProcessWorkingSetBytes = $processWorkingSetBytes
  ProcessPrivateBytes = $processPrivateBytes
  HiddenCommitBytes = $hiddenCommitBytes
  BalloonDisabled = $balloonDisabled
  BalloonStopped = $balloonStopped
  BalloonConfig = $balloonConfigText
  BalloonState = $balloonStateText
}

$securityEvents = @()
try {
  $securityEvents = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625,4624,4720,4722,4728,4732,4738,4740; StartTime=(Get-Date).AddHours(-12)} -MaxEvents 50 |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
} catch {}

$securityFindings = @()
foreach ($rule in $firewallExposure) {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="Broad inbound firewall rule"; Detail="$($rule.Name) allows $($rule.Protocol)/$($rule.LocalPort) from $($rule.RemoteAddress)." }
}
foreach ($listener in $listeningRisks) {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="Sensitive listener"; Detail="$($listener.ProcessName) is listening on $($listener.LocalAddress):$($listener.LocalPort)." }
}
foreach ($proc in $suspiciousProcesses) {
  $securityFindings += [pscustomobject]@{ Severity="warm"; Title="Unusual process location"; Detail="$($proc.ProcessName) PID $($proc.Id) from $($proc.Path)." }
}
if ($defender -and (-not $defender.RealTimeProtectionEnabled -or -not $defender.AntivirusEnabled)) {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="Defender protection disabled"; Detail="Microsoft Defender real-time or antivirus protection is not enabled." }
}
if ($shares.Count -gt 0) {
  $securityFindings += [pscustomobject]@{ Severity="warm"; Title="Non-default SMB shares"; Detail="$($shares.Count) non-default share(s) exposed by Windows." }
}
if ($vmMemory.Status -eq "bad") {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="VM memory balloon risk"; Detail=$vmMemory.Detail }
} elseif ($vmMemory.Status -eq "warn") {
  $securityFindings += [pscustomobject]@{ Severity="warm"; Title="VM memory pressure"; Detail=$vmMemory.Detail }
}
$failedLogons = @($securityEvents | Where-Object { $_.Id -eq 4625 })
if ($failedLogons.Count -ge 5) {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="Failed logon burst"; Detail="$($failedLogons.Count) failed logon events in the last 12 hours." }
}
$accountChanges = @($securityEvents | Where-Object { $_.Id -in @(4720,4722,4728,4732,4738,4740) })
if ($accountChanges.Count -gt 0) {
  $securityFindings += [pscustomobject]@{ Severity="hot"; Title="Account or group changes"; Detail="$($accountChanges.Count) account/group security event(s) in the last 12 hours." }
}
if ($securityFindings.Count -eq 0) {
  $securityFindings += [pscustomobject]@{ Severity="cool"; Title="No obvious compromise signals"; Detail="No broad management exposure, suspicious hot processes, Defender failures, or recent account-change bursts were detected." }
}

$securityCoverage = @(
  [pscustomobject]@{ Name="Inbound firewall exposure"; Status="active"; Detail="Flags broad RDP, SSH, WinRM, SMB, and management-style allow rules." },
  [pscustomobject]@{ Name="Sensitive listeners"; Status="active"; Detail="Flags non-loopback listeners on management and app ports." },
  [pscustomobject]@{ Name="Windows Security log"; Status=if ($securityEvents.Count -gt 0) { "active" } else { "limited" }; Detail="Tracks failed logons, account creation/change, lockout, and group membership events when readable." },
  [pscustomobject]@{ Name="Administrators group"; Status=if ($adminMembers.Count -gt 0) { "active" } else { "limited" }; Detail="Lists local administrators for unexpected membership review." },
  [pscustomobject]@{ Name="Defender health"; Status=if ($defender) { "active" } else { "limited" }; Detail="Checks antivirus and real-time protection status when Defender cmdlets are available." },
  [pscustomobject]@{ Name="Persistence surface"; Status="active"; Detail="Shows services, startup commands, and enabled scheduled tasks." },
  [pscustomobject]@{ Name="Workload drift"; Status="active"; Detail="Checks app service images, directories, entrypoints, config, package files, logs, and git metadata." },
  [pscustomobject]@{ Name="Process provenance"; Status="active"; Detail="Labels hot processes by role, trust zone, service ownership, path, parent, and command line." },
  [pscustomobject]@{ Name="VM memory ballooning"; Status="active"; Detail="Checks QEMU/VirtIO balloon state, committed memory, and process-owned memory mismatch." },
  [pscustomobject]@{ Name="File integrity hashing"; Status="missing"; Detail="Not yet baselining hashes for app files, configs, service binaries, and scripts." },
  [pscustomobject]@{ Name="Caddy/app log anomaly parsing"; Status="missing"; Detail="Not yet counting suspicious HTTP probes, auth failures, user-agent bursts, or admin endpoint hits." },
  [pscustomobject]@{ Name="External uptime and TLS checks"; Status="missing"; Detail="Needs an outside monitor to confirm public sites, certificates, and ports from the internet." },
  [pscustomobject]@{ Name="Sysmon or EDR telemetry"; Status="missing"; Detail="Needs Sysmon/EDR for process creation history, command-line lineage, DNS, registry persistence, and richer forensics." },
  [pscustomobject]@{ Name="Backup restore verification"; Status="missing"; Detail="Need scheduled restore drills and alerts when backup freshness or decryptability fails." },
  [pscustomobject]@{ Name="Dependency audit monitoring"; Status="missing"; Detail="Need scheduled npm audit reporting without touching required LLM dependencies." }
)

$events = Get-WinEvent -FilterHashtable @{LogName=@("System","Application"); Level=1,2,3; StartTime=(Get-Date).AddHours(-6)} -MaxEvents 24 |
  Select-Object TimeCreated, LogName, ProviderName, Id, LevelDisplayName, Message

[pscustomobject]@{
  capturedAt = (Get-Date).ToUniversalTime().ToString("o")
  network = $nics
  disks = $disks
  volumes = $volumes
  processes = $procs
  ports = $ports
  connections = $connections
  services = $services
  workloads = $workloads
  vmMemory = $vmMemory
  scheduledTasks = $scheduledTasks
  startupCommands = $startupCommands
  security = [pscustomobject]@{
    findings = $securityFindings
    firewallExposure = $firewallExposure
    listeningRisks = $listeningRisks
    suspiciousProcesses = $suspiciousProcesses
    adminMembers = $adminMembers
    shares = $shares
    defender = $defender
    securityEvents = $securityEvents
    failedLogons = $failedLogons.Count
    accountChanges = $accountChanges.Count
    coverage = $securityCoverage
  }
  events = $events
} | ConvertTo-Json -Depth 8 -Compress -WarningAction SilentlyContinue
`;
  const result = await runPowerShell(script);
  if (!result.ok) return { error: result.error };
  return {
    ...result.data,
    network: normalizeArray(result.data.network),
    disks: normalizeArray(result.data.disks),
    volumes: normalizeArray(result.data.volumes),
    processes: normalizeArray(result.data.processes),
    ports: normalizeArray(result.data.ports),
    connections: normalizeArray(result.data.connections),
    services: normalizeArray(result.data.services),
    workloads: normalizeArray(result.data.workloads),
    vmMemory: result.data.vmMemory || null,
    scheduledTasks: normalizeArray(result.data.scheduledTasks),
    startupCommands: normalizeArray(result.data.startupCommands),
    security: {
      ...(result.data.security || {}),
      findings: normalizeArray(result.data.security?.findings),
      firewallExposure: normalizeArray(result.data.security?.firewallExposure),
      listeningRisks: normalizeArray(result.data.security?.listeningRisks),
      suspiciousProcesses: normalizeArray(result.data.security?.suspiciousProcesses),
      adminMembers: normalizeArray(result.data.security?.adminMembers),
      shares: normalizeArray(result.data.security?.shares),
      securityEvents: normalizeArray(result.data.security?.securityEvents),
      coverage: normalizeArray(result.data.security?.coverage)
    },
    events: normalizeArray(result.data.events)
  };
}

function deriveRates(snapshot) {
  const now = Date.now();
  const totalNet = (snapshot.network || []).reduce(
    (sum, nic) => ({
      rx: sum.rx + Number(nic.BytesReceivedPersec || 0),
      tx: sum.tx + Number(nic.BytesSentPersec || 0),
      rxErrors: sum.rxErrors + Number(nic.PacketsReceivedErrors || 0),
      txErrors: sum.txErrors + Number(nic.PacketsOutboundErrors || 0)
    }),
    { rx: 0, tx: 0, rxErrors: 0, txErrors: 0 }
  );
  const totalDisk = (snapshot.disks || []).reduce(
    (sum, disk) => ({
      read: sum.read + Number(disk.DiskReadBytesPersec || 0),
      write: sum.write + Number(disk.DiskWriteBytesPersec || 0),
      queue: sum.queue + Number(disk.CurrentDiskQueueLength || 0)
    }),
    { read: 0, write: 0, queue: 0 }
  );
  previousNet = { ...totalNet, now };
  previousDisk = { ...totalDisk, now };
  return { network: totalNet, disk: totalDisk };
}

function recommendations(data) {
  const tips = [];
  if (data.cpu.usage > 85) tips.push({ severity: "hot", title: "CPU pressure", detail: "Find top CPU processes and pin noisy services to scheduled windows or separate instances." });
  const vmMemory = data.windows.vmMemory;
  if (vmMemory?.Status === "bad") {
    tips.push({ severity: "hot", title: "VM memory balloon risk", detail: vmMemory.Detail || "QEMU/VirtIO memory ballooning is not in the expected disabled/stopped state." });
  } else if (vmMemory?.Status === "warn") {
    tips.push({ severity: "warm", title: "VM memory pressure", detail: vmMemory.Detail || "Committed memory is elevated; watch for ballooning or a process leak." });
  }
  if (data.memory.usage > 85) tips.push({ severity: "hot", title: "Memory pressure", detail: "Look for long-running processes with growing working sets; add service limits before Windows starts paging hard." });
  if (data.rates.disk.queue > 2) tips.push({ severity: "warm", title: "Disk queue rising", detail: "Move logs, temp files, backups, and database writes off the same volume if possible." });
  const drifted = (data.windows.workloads || []).filter((w) => w.Health === "drift" || w.Health === "down");
  if (drifted.length) tips.push({ severity: "hot", title: "Workload drift", detail: `${drifted.map((w) => w.DisplayName || w.Name).join(", ")} has missing, moved, or unhealthy service anchors.` });
  const lowVolumes = (data.windows.volumes || []).filter((v) => Number(v.Size) > 0 && Number(v.FreeSpace) / Number(v.Size) < 0.15);
  if (lowVolumes.length) tips.push({ severity: "hot", title: "Low free disk", detail: `${lowVolumes.map((v) => v.DeviceID).join(", ")} below 15% free. Free space helps avoid fragmentation, failed updates, and service crashes.` });
  if ((data.windows.events || []).some((e) => e.LevelDisplayName === "Error" || e.LevelDisplayName === "Critical")) tips.push({ severity: "warm", title: "Recent errors", detail: "Check the event strip first; repeated service or disk errors are usually better wins than random tweaking." });
  const securityHot = (data.windows.security?.findings || []).filter((f) => f.Severity === "hot");
  if (securityHot.length) tips.push({ severity: "hot", title: "Security watch alerts", detail: `${securityHot.length} high-priority security signal(s) need review.` });
  if (!tips.length) tips.push({ severity: "cool", title: "No obvious bottleneck", detail: "Baseline looks clean. Watch peak hours and compare what changes when your servers are under real load." });
  return tips;
}

function mergeSlowSecurity(windows, slow) {
  if (!windows.security) windows.security = {};
  const existingFindings = normalizeArray(windows.security.findings);
  const existingCoverage = normalizeArray(windows.security.coverage);
  const slowCoverage = normalizeArray(slow.coverage);
  const slowNames = new Set(slowCoverage.map((item) => item.Name));
  windows.security.findings = [...existingFindings, ...normalizeArray(slow.findings)];
  windows.security.coverage = [
    ...existingCoverage.filter((item) => !slowNames.has(item.Name)),
    ...slowCoverage
  ];
  windows.security.fileIntegrity = slow.fileIntegrity;
  windows.security.logAnomalies = slow.logAnomalies;
  windows.security.uptime = slow.uptime;
  windows.security.sysmon = slow.sysmon;
  windows.security.backups = slow.backups;
  windows.security.dependencyAudit = slow.dependencyAudit;
  windows.security.npmSupplyChain = slow.npmSupplyChain;
  windows.security.updateWatch = slow.updateWatch;
  windows.security.slowSecurityCapturedAt = slow.capturedAt;
  return windows;
}

async function mergeAutoBlockState(windows) {
  const blockedState = await readJsonFile(blockedLogonIpsPath, { blocked: [] });
  const blocked = normalizeArray(blockedState.blocked);
  if (!windows.security) windows.security = {};
  windows.security.autoBlockedIps = blocked;
  windows.security.coverage = normalizeArray(windows.security.coverage);
  windows.security.findings = normalizeArray(windows.security.findings);
  windows.security.coverage.push(coverageItem("Failed-logon auto-blocker", "active", `${blocked.length} remote IP(s) currently blocked after repeated failed logons.`));
  if (blocked.length) {
    windows.security.findings.push(slowFinding("warm", "Auto-blocked failed logon IPs", `${blocked.length} IP(s) are currently blocked by MasterHUD-FailedLogonBlocker.`));
  }
  return windows;
}

function computeRebootReadiness(windows = {}) {
  const checks = [];
  const services = new Map(normalizeArray(windows.services).map((service) => [String(service.Name || "").toLowerCase(), service]));
  const workloads = new Map(normalizeArray(windows.workloads).map((workload) => [String(workload.Name || "").toLowerCase(), workload]));
  const tasks = new Map(normalizeArray(windows.scheduledTasks).map((task) => [String(task.TaskName || "").toLowerCase(), task]));
  const requiredServices = normalizeArray(config.requiredServices).filter(Boolean);

  for (const name of requiredServices) {
    const service = services.get(name.toLowerCase()) || workloads.get(name.toLowerCase());
    const state = service?.State || "missing";
    const startMode = service?.StartMode || "unknown";
    const health = service?.Health || (state === "Running" ? "ok" : "down");
    checks.push({
      Name: `${name} service`,
      Status: state === "Running" && startMode === "Auto" && health !== "drift" && health !== "down" ? "ok" : "bad",
      Detail: `${state}; startup ${startMode}; health ${health}.`
    });
  }

  for (const name of ["MasterHUD", "MasterHUD-FailedLogonBlocker"]) {
    const task = tasks.get(name.toLowerCase());
    checks.push({
      Name: `${name} boot task`,
      Status: task ? "ok" : "bad",
      Detail: task ? `Scheduled task is ${task.State || "present"} at ${task.TaskPath || "\\"}.` : "Scheduled boot task was not returned by Windows."
    });
  }

  const ports = normalizeArray(windows.ports);
  const hasPort = (portNumber) => ports.some((port) => Number(port.LocalPort) === portNumber);
  for (const portNumber of normalizeArray(config.requiredPorts).filter((value) => Number.isFinite(Number(value)))) {
    checks.push({
      Name: `Port ${portNumber} listener`,
      Status: hasPort(portNumber) ? "ok" : "warn",
      Detail: hasPort(portNumber) ? "Listener is present right now." : "No listener was seen in the current sample."
    });
  }

  const bad = checks.filter((item) => item.Status === "bad").length;
  const warn = checks.filter((item) => item.Status === "warn").length;
  return {
    status: bad ? "bad" : warn ? "warn" : "ok",
    summary: `${checks.length - bad - warn}/${checks.length} ready`,
    checks
  };
}

async function collect() {
  if (collecting) return;
  collecting = true;
  try {
    const windows = await windowsSnapshot();
    const slow = await runSlowSecurityMonitors(windows);
    mergeSlowSecurity(windows, slow);
    await mergeAutoBlockState(windows);
    windows.rebootReadiness = computeRebootReadiness(windows);
    const data = {
      capturedAt: new Date().toISOString(),
      host: { hostname: os.hostname(), platform: os.platform(), release: os.release(), uptime: os.uptime() },
      cpu: cpuSnapshot(),
      memory: memorySnapshot(),
      windows,
      rates: deriveRates(windows),
      sampleMs
    };
    data.recommendations = recommendations(data);
    await publishAlerts(data);
    await appendHistory(data);
    await mergeAlertAndHistoryState(data);
    latest = data;
    broadcast(data);
  } finally {
    collecting = false;
  }
}

function broadcast(data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(payload);
}

function isLocalRequest(req) {
  return ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket.remoteAddress);
}

function sendJson(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(payload));
}

async function readRequestJson(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 8192) throw new Error("request body too large");
  }
  return body ? JSON.parse(body) : {};
}

function validIp(value) {
  return typeof value === "string" && /^[0-9a-fA-F:.]{3,45}$/.test(value);
}

function configuredServiceName(value) {
  return typeof value === "string" ? value : value?.name;
}

function currentAppRoot() {
  return config.appRoot || __dirname;
}

function currentManageableServices() {
  return new Set(normalizeArray(config.managedServices).map(configuredServiceName).filter(Boolean));
}

function currentCaddyCandidates() {
  return normalizeArray(config.caddyCandidates).filter(Boolean);
}

async function firstExistingPath(paths) {
  for (const candidate of paths) {
    if (await pathExists(candidate)) return candidate;
  }
  return null;
}

async function runServiceAction(name, action) {
  if (!currentManageableServices().has(name)) {
    return { ok: false, stdout: "", stderr: "service is not in the MasterHUD allow-list" };
  }
  const safeName = name.replace(/'/g, "''");
  const command = `$name = '${safeName}'; $svc = Get-Service -Name $name -ErrorAction Stop; if ('${action}' -eq 'start') { if ($svc.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop; (Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30)) } } else { Restart-Service -Name $name -Force -ErrorAction Stop; (Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(45)) }; $svc = Get-Service -Name $name; [pscustomobject]@{ok=$true;service=$svc.Name;status=$svc.Status.ToString()} | ConvertTo-Json -Compress`;
  return runCommand(powerShellExe, [
    "-NoLogo",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    command
  ], __dirname, 60000);
}

async function handleAction(req, res, pathname) {
  if (!isLocalRequest(req)) {
    sendJson(res, 403, { ok: false, error: "local requests only" });
    return true;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { ok: false, error: "POST required" });
    return true;
  }

  try {
    const body = await readRequestJson(req);
    if (pathname === "/api/actions/set-profile") {
      const profile = String(body.profile || "").trim();
      if (profile && !validProfileName(profile)) {
        sendJson(res, 400, { ok: false, error: "profile name must use letters, numbers, dot, underscore, or dash" });
        return true;
      }
      if (profile && !(await pathExists(profileConfigPath(profile)))) {
        sendJson(res, 404, { ok: false, error: "profile file was not found" });
        return true;
      }
      await writeJsonFile(activeProfilePath, { profile, updatedAt: new Date().toISOString() });
      await reloadConfig();
      slowSecurity.capturedAt = null;
      collect();
      sendJson(res, 200, { ok: true, message: profile ? `Active profile switched to ${profile}.` : "Active profile reset to default config.", profile: config.profile });
      return true;
    }

    if (pathname === "/api/actions/block-ip" || pathname === "/api/actions/unblock-ip") {
      if (!validIp(body.ip)) {
        sendJson(res, 400, { ok: false, error: "valid ip is required" });
        return true;
      }
      const scriptName = pathname.endsWith("unblock-ip") ? "Unblock-Ip.ps1" : "Block-Ip.ps1";
      const result = await runCommand(powerShellExe, [
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path.join(__dirname, "security", scriptName),
        "-Ip",
        body.ip
      ], __dirname, 30000);
      if (result.ok) {
        await updateBlockedIpState(body.ip, !pathname.endsWith("unblock-ip"));
      }
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout, stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/start-service" || pathname === "/api/actions/restart-service") {
      const action = pathname.endsWith("start-service") ? "start" : "restart";
      const result = await runServiceAction(body.name, action);
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout, stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/app-health") {
      if (!config.healthUrl) {
        sendJson(res, 400, { ok: false, error: "healthUrl is not configured in masterhud.config.json" });
        return true;
      }
      const safeHealthUrl = String(config.healthUrl).replace(/'/g, "''");
      const result = await runCommand(powerShellExe, [
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        `$r = Invoke-WebRequest -UseBasicParsing -Uri '${safeHealthUrl}' -TimeoutSec 10; [pscustomobject]@{ok=$true;statusCode=[int]$r.StatusCode;body=$r.Content} | ConvertTo-Json -Compress`
      ], __dirname, 20000);
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout, stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/caddy-validate") {
      if (!config.caddyConfigPath) {
        sendJson(res, 400, { ok: false, error: "caddyConfigPath is not configured in masterhud.config.json" });
        return true;
      }
      const caddyExe = await firstExistingPath(currentCaddyCandidates());
      if (!caddyExe) {
        sendJson(res, 500, { ok: false, error: "caddy.exe not found" });
        return true;
      }
      const result = await runCommand(caddyExe, [
        "validate",
        "--config",
        config.caddyConfigPath,
        "--adapter",
        "caddyfile"
      ], currentAppRoot(), 60000);
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout, stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/tablet-readiness") {
      if (!config.tabletReadinessCommand) {
        sendJson(res, 400, { ok: false, error: "tabletReadinessCommand is not configured in masterhud.config.json" });
        return true;
      }
      const result = await runCommand("cmd.exe", ["/d", "/s", "/c", config.tabletReadinessCommand], currentAppRoot(), 120000);
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout, stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/run-logon-blocker") {
      const result = await runCommand(powerShellExe, [
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path.join(__dirname, "security", "Watch-FailedLogons.ps1"),
        "-WindowMinutes",
        "30",
        "-Threshold",
        "10",
        "-BlockHours",
        "1"
      ], __dirname, 60000);
      await collect();
      sendJson(res, result.ok ? 200 : 500, { ok: result.ok, stdout: result.stdout || "Failed-logon blocker completed.", stderr: result.stderr || result.error });
      return true;
    }

    if (pathname === "/api/actions/refresh-snapshot") {
      await collect();
      if (!latest) {
        sendJson(res, 202, { ok: true, message: "Snapshot refresh requested." });
        return true;
      }
      sendJson(res, 200, { ok: true, snapshot: { capturedAt: latest.capturedAt } });
      return true;
    }

    if (pathname === "/api/actions/run-security-scan") {
      slowSecurity.capturedAt = null;
      collect();
      sendJson(res, 202, { ok: true, message: "Security scan requested." });
      return true;
    }

    if (pathname === "/api/actions/run-update-scan") {
      slowSecurity.capturedAt = null;
      collect();
      sendJson(res, 202, { ok: true, message: "Update scan requested. Refresh HUD in a minute if results are still warming." });
      return true;
    }

    if (pathname === "/api/actions/update-brief") {
      const windows = latest?.windows || await windowsSnapshot();
      const watch = await monitorUpdateWatch(windows);
      if (latest?.windows?.security) {
        latest.windows.security.updateWatch = watch;
        broadcast(latest);
      }
      sendJson(res, 200, {
        ok: true,
        message: "Read-only update brief generated. Nothing was installed or changed.",
        stdout: buildUpdateBrief(watch)
      });
      return true;
    }
  } catch (error) {
    sendJson(res, 500, { ok: false, error: error.message });
    return true;
  }
  return false;
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let filePath = path.normalize(path.join(publicDir, url.pathname === "/" ? "index.html" : url.pathname));
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403).end("Forbidden");
    return;
  }
  try {
    const body = await fs.readFile(filePath);
    res.writeHead(200, { "Content-Type": contentTypes.get(path.extname(filePath)) || "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("Not found");
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/api/snapshot") {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    res.end(JSON.stringify(latest || { status: "warming-up" }));
    return;
  }
  if (url.pathname === "/api/operator-config") {
    sendJson(res, 200, {
      ok: true,
      profile: config.profile,
      profiles: await listProfiles(),
      quickLinks: normalizeArray(config.quickLinks),
      managedServices: normalizeArray(config.managedServices)
    });
    return;
  }
  if (url.pathname === "/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-store",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*"
    });
    clients.add(res);
    if (latest) res.write(`data: ${JSON.stringify(latest)}\n\n`);
    req.on("close", () => clients.delete(res));
    return;
  }
  if (url.pathname.startsWith("/api/actions/") && await handleAction(req, res, url.pathname)) return;
  await serveStatic(req, res);
});

server.listen(port, "127.0.0.1", () => {
  console.log(`MasterHUD running at http://127.0.0.1:${port}`);
});

collect();
setInterval(collect, sampleMs);
