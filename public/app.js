const $ = (id) => document.getElementById(id);

const history = {
  cpu: [],
  memory: [],
  disk: [],
  network: []
};

const maxHistory = 80;

const fmt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const intFmt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
let operatorConfig = { quickLinks: [], managedServices: [], profiles: [], profile: { active: "" } };

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function bytes(value) {
  const n = Number(value || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Math.abs(n);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${n < 0 ? "-" : ""}${fmt.format(size)} ${units[unit]}`;
}

function percent(value) {
  return `${fmt.format(Math.max(0, Math.min(100, Number(value || 0))))}%`;
}

function pushHistory(key, value) {
  history[key].push(Number(value || 0));
  if (history[key].length > maxHistory) history[key].shift();
}

function drawSpark(id, values, color) {
  const canvas = $(id);
  const ctx = canvas.getContext("2d");
  const { width, height } = canvas;
  ctx.clearRect(0, 0, width, height);
  ctx.strokeStyle = "#29313b";
  ctx.lineWidth = 1;
  for (let y = 12; y < height; y += 18) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
  if (values.length < 2) return;
  const max = Math.max(...values, 1);
  ctx.strokeStyle = color;
  ctx.lineWidth = 3;
  ctx.beginPath();
  values.forEach((value, index) => {
    const x = (index / (maxHistory - 1)) * width;
    const y = height - 5 - (value / max) * (height - 12);
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function setBar(id, value) {
  const el = $(id);
  const v = Math.max(0, Math.min(100, Number(value || 0)));
  el.style.width = `${v}%`;
  el.style.background = v > 88 ? "var(--red)" : v > 72 ? "var(--yellow)" : "var(--green)";
}

function renderKpis(data) {
  const diskRate = Number(data.rates?.disk?.read || 0) + Number(data.rates?.disk?.write || 0);
  const netRate = Number(data.rates?.network?.rx || 0) + Number(data.rates?.network?.tx || 0);
  pushHistory("cpu", data.cpu.usage);
  pushHistory("memory", data.memory.usage);
  pushHistory("disk", diskRate);
  pushHistory("network", netRate);

  $("cpuValue").textContent = percent(data.cpu.usage);
  $("memValue").textContent = percent(data.memory.usage);
  $("diskValue").textContent = `${bytes(diskRate)}/s`;
  $("netValue").textContent = `${bytes(netRate)}/s`;
  $("diskRead").textContent = `R ${bytes(data.rates?.disk?.read)}/s`;
  $("diskWrite").textContent = `W ${bytes(data.rates?.disk?.write)}/s`;
  $("netRx").textContent = `Down ${bytes(data.rates?.network?.rx)}/s`;
  $("netTx").textContent = `Up ${bytes(data.rates?.network?.tx)}/s`;
  setBar("cpuBar", data.cpu.usage);
  setBar("memBar", data.memory.usage);
  drawSpark("cpuSpark", history.cpu, "#35d07f");
  drawSpark("memSpark", history.memory, "#35c9d0");
  drawSpark("diskSpark", history.disk, "#e8bf4b");
  drawSpark("netSpark", history.network, "#6ea8fe");
}

function renderProcesses(processes = []) {
  $("processCount").textContent = `${processes.length} tracked`;
  const maxWs = Math.max(...processes.map((p) => Number(p.WS || 0)), 1);
  $("processes").innerHTML = processes.map((p) => {
    const ram = Number(p.WS || 0);
    const services = Array.isArray(p.Services) ? p.Services : p.Services ? [p.Services] : [];
    const serviceText = services.map((s) => s.DisplayName || s.Name).filter(Boolean).join(", ");
    const origin = serviceText ? `Service: ${serviceText}` : p.OriginReason || "Process";
    const parent = p.ParentProcessName ? `${p.ParentProcessName} (${p.ParentProcessId})` : `PID ${p.ParentProcessId || "-"}`;
    const maker = [p.Company, p.Product].filter(Boolean).join(" · ");
    const label = p.FriendlyName || p.ProcessName;
    const role = p.Role || origin;
    const trust = p.Trust || "unknown";
    const path = p.Path || "No executable path exposed by Windows";
    const command = p.CommandLine || path;
    return `<div class="process-row">
      <div class="process-main">
        <div class="process-title">
          <strong class="name" title="${esc(`${p.ProcessName} · ${path}`)}">${esc(label)}</strong>
          <span class="origin-tag" title="${esc(`${origin} · ${trust}`)}">${esc(role)}</span>
        </div>
        <div class="process-path" title="${esc(path)}">${esc(p.ProcessName)} · ${esc(trust)} · ${esc(path)}</div>
      </div>
      <span class="metric">${fmt.format(Number(p.CPU || 0))}s CPU</span>
      <span class="metric">${bytes(ram)}</span>
      <div class="process-origin">
        <span class="metric" title="${esc(parent)}">parent ${esc(parent)}</span>
        <span class="metric" title="${esc(maker || p.Description || "")}">${esc(maker || p.Description || "unknown publisher")}</span>
      </div>
      <div class="microbar" title="${bytes(ram)} working set"><i style="width:${Math.min(100, ram / maxWs * 100)}%"></i></div>
      <div class="process-cmd" title="${esc(command)}">${esc(command)}</div>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No process data</strong><p>PowerShell may need more time or permissions.</p></div>`;
}

function renderVolumes(volumes = []) {
  $("volumes").innerHTML = volumes.map((v) => {
    const size = Number(v.Size || 0);
    const free = Number(v.FreeSpace || 0);
    const freePct = size ? (free / size) * 100 : 0;
    return `<div class="volume-row">
      <div class="volume-title"><strong>${esc(v.DeviceID)} ${esc(v.VolumeName || "")}</strong><span>${percent(freePct)} free</span></div>
      <div class="bar"><i style="width:${100 - freePct}%; background:${freePct < 12 ? "var(--red)" : freePct < 22 ? "var(--yellow)" : "var(--green)"}"></i></div>
      <p>${bytes(free)} free of ${bytes(size)}</p>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No fixed volumes found</strong><p>Disk telemetry did not return fixed drives.</p></div>`;
}

function renderPorts(ports = []) {
  $("portCount").textContent = `${ports.length} open`;
  $("ports").innerHTML = ports.map((p) => `<div class="port" title="${esc(p.LocalAddress)}:${esc(p.LocalPort)}">
    <strong>${esc(p.LocalPort)}</strong>
    <span>${esc(p.ProcessName || `PID ${p.OwningProcess}`)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No listening TCP ports</strong><p>Nothing is currently listening, or permissions blocked the query.</p></div>`;
}

function renderConnections(connections = []) {
  $("connectionCount").textContent = `${connections.length} live`;
  $("connections").innerHTML = connections.slice(0, 90).map((c) => `<div class="connection-row">
    <strong class="name" title="${esc(c.LocalAddress)}:${esc(c.LocalPort)}">${esc(c.LocalPort)} -> ${esc(c.RemotePort)}</strong>
    <span class="metric" title="${esc(c.RemoteAddress)}">${esc(c.RemoteAddress)}</span>
    <span class="metric">${esc(c.ProcessName || `PID ${c.OwningProcess}`)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No active TCP sessions</strong><p>No established TCP connections were returned.</p></div>`;
}

function renderServices(services = []) {
  $("serviceCount").textContent = `${services.length} running`;
  $("services").innerHTML = services.slice(0, 80).map((s) => `<div class="service-row">
    <strong class="name" title="${esc(s.PathName || s.DisplayName)}">${esc(s.DisplayName || s.Name)}</strong>
    <span class="metric">PID ${esc(s.ProcessId || "-")}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No automatic services returned</strong><p>Windows service query came back empty.</p></div>`;
}

function renderWorkloads(workloads = []) {
  $("workloadCount").textContent = `${workloads.length} apps`;
  $("workloads").innerHTML = workloads.map((w) => {
    const command = [w.Application, w.AppParameters].filter(Boolean).join(" ");
    const envKeys = Array.isArray(w.EnvKeys) ? w.EnvKeys.join(", ") : "";
    const missingCount = Array.isArray(w.Missing) ? w.Missing.length : 0;
    return `<div class="workload-row ${esc(w.Health || "ok")}">
      <strong title="${esc(w.Name)}">${esc(w.DisplayName || w.Name)} · ${esc(w.Health || "ok")}</strong>
      <span title="${esc(w.AppDirectory || "")}">${esc(w.AppDirectory || "no app directory")}</span>
      <span>PID ${esc(w.ProcessId || "-")} · ${esc(w.Account || "")} · ${missingCount} drift</span>
      <span class="wide" title="${esc(command || w.ServiceImage || "")}">${esc(command || w.ServiceImage || "")}</span>
      <span class="wide" title="${esc(envKeys)}">env keys: ${esc(envKeys || "none exposed")}</span>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No app workloads inferred</strong><p>No NSSM, app-directory, Node, Caddy, or PostgreSQL services were detected.</p></div>`;
}

function renderDrift(workloads = []) {
  const checks = workloads.flatMap((w) => {
    const all = Array.isArray(w.Checks) ? w.Checks : [];
    return all.map((check) => ({ workload: w.DisplayName || w.Name, ...check }));
  });
  const bad = checks.filter((check) => check.Status !== "ok");
  $("driftCount").textContent = `${bad.length}/${checks.length} bad`;
  const rows = (bad.length ? bad : checks.slice(0, 80));
  $("drift").innerHTML = rows.map((check) => `<div class="drift-row ${check.Status === "ok" ? "ok" : "bad"}">
    <strong title="${esc(check.workload)}">${esc(check.Label)}</strong>
    <span title="${esc(check.Path || "")}">${esc(check.Path || "missing path")}</span>
    <span>${esc(check.Status)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No drift checks</strong><p>No workload file anchors are available yet.</p></div>`;
}

function renderStartup(data = {}) {
  const tasks = Array.isArray(data.scheduledTasks) ? data.scheduledTasks : [];
  const commands = Array.isArray(data.startupCommands) ? data.startupCommands : [];
  $("startupCount").textContent = `${tasks.length + commands.length} entries`;
  const taskRows = tasks.slice(0, 45).map((task) => `<div class="startup-row">
    <strong title="${esc(task.TaskPath)}">${esc(task.TaskName)}</strong>
    <span>${esc(task.TaskPath || "")}</span>
    <span>${esc(task.State || "")}</span>
  </div>`);
  const commandRows = commands.slice(0, 35).map((cmd) => `<div class="startup-row">
    <strong title="${esc(cmd.Location)}">${esc(cmd.Name)}</strong>
    <span title="${esc(cmd.Command)}">${esc(cmd.Command || "")}</span>
    <span>${esc(cmd.User || "")}</span>
  </div>`);
  $("startup").innerHTML = [...taskRows, ...commandRows].join("") || `<div class="tip-row"><strong>No startup entries</strong><p>No enabled scheduled tasks or startup commands were returned.</p></div>`;
}

function renderSecurity(security = {}) {
  const findings = Array.isArray(security.findings) ? security.findings : [];
  const hot = findings.filter((finding) => finding.Severity === "hot").length;
  const warm = findings.filter((finding) => finding.Severity === "warm").length;
  $("securityCount").textContent = `${hot} hot · ${warm} warm`;
  $("security").innerHTML = findings.map((finding) => `<div class="security-row ${esc(finding.Severity || "cool")}">
    <strong>${esc(finding.Severity || "info")}</strong>
    <strong title="${esc(finding.Title)}">${esc(finding.Title)}</strong>
    <span title="${esc(finding.Detail)}">${esc(finding.Detail)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No security data</strong><p>Security telemetry has not returned yet.</p></div>`;
}

function renderCoverage(security = {}) {
  const parseCoverage = (item) => {
    if (typeof item !== "string") return item;
    const match = item.match(/@\{Name=(.*?); Status=(.*?); Detail=(.*)\}$/);
    if (!match) return { Name: item, Status: "limited", Detail: "Coverage item returned in an unexpected shape." };
    return { Name: match[1], Status: match[2], Detail: match[3] };
  };
  const coverage = (Array.isArray(security.coverage) ? security.coverage : []).map(parseCoverage);
  const missing = coverage.filter((item) => item.Status === "missing").length;
  const limited = coverage.filter((item) => item.Status === "limited").length;
  $("coverageCount").textContent = `${missing} missing · ${limited} limited`;
  $("coverage").innerHTML = coverage.map((item) => `<div class="coverage-row ${esc(item.Status || "active")}">
    <strong>${esc(item.Status || "active")}</strong>
    <strong title="${esc(item.Name)}">${esc(item.Name)}</strong>
    <span title="${esc(item.Detail)}">${esc(item.Detail)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No coverage map</strong><p>Coverage telemetry has not returned yet.</p></div>`;
}

function renderUpdateWatch(security = {}) {
  const watch = security.updateWatch || {};
  const windowsUpdates = Array.isArray(watch.windows?.updates) ? watch.windows.updates : [];
  const winget = Array.isArray(watch.winget?.upgrades) ? watch.winget.upgrades : [];
  const npmWorkloads = Array.isArray(watch.npmOutdated?.workloads) ? watch.npmOutdated.workloads : [];
  const npmPackages = npmWorkloads.flatMap((workload) => (Array.isArray(workload.packages) ? workload.packages : []).map((pkg) => ({ workload: workload.workload, ...pkg })));
  const repos = Array.isArray(watch.gitDrift?.repos) ? watch.gitDrift.repos : [];
  const versions = Array.isArray(watch.versions?.commands) ? watch.versions.commands : [];
  const pending = windowsUpdates.length + winget.length + npmPackages.length + repos.filter((repo) => /\bbehind\b/i.test(repo.status || "")).length;
  $("updateCount").textContent = `${pending} pending`;

  const rows = [
    ...windowsUpdates.slice(0, 8).map((update) => ({
      level: /security|defender|malicious|cumulative/i.test(update.title || "") ? "hot" : "warm",
      type: "Windows",
      title: update.title || "Pending update",
      detail: update.rebootRequired ? "reboot required" : "available"
    })),
    ...winget.slice(0, 10).map((item) => ({
      level: "warm",
      type: "winget",
      title: item.name || item.id,
      detail: `${item.version || "?"} -> ${item.available || "?"}`
    })),
    ...npmPackages.slice(0, 12).map((item) => ({
      level: "warm",
      type: "npm",
      title: `${item.workload}: ${item.name}`,
      detail: `${item.current || "?"} -> ${item.wanted || item.latest || "?"}`
    })),
    ...repos.filter((repo) => /\bbehind\b/i.test(repo.status || "")).slice(0, 6).map((repo) => ({
      level: "warm",
      type: "Git",
      title: repo.workload,
      detail: repo.status
    }))
  ];

  if (!rows.length && versions.length) {
    rows.push(...versions.slice(0, 8).map((item) => ({
      level: item.ok ? "cool" : "warm",
      type: "Version",
      title: item.name,
      detail: item.output || item.error || item.command
    })));
  }

  $("updates").innerHTML = rows.map((row) => `<div class="update-row ${esc(row.level)}">
    <strong>${esc(row.type)}</strong>
    <strong title="${esc(row.title)}">${esc(row.title)}</strong>
    <span title="${esc(row.detail)}">${esc(row.detail)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No update data yet</strong><p>Run Update Scan or wait for the slow monitors to finish.</p></div>`;
}

function renderReadiness(windows = {}) {
  const readiness = windows.rebootReadiness || {};
  const checks = Array.isArray(readiness.checks) ? readiness.checks : [];
  $("readinessCount").textContent = readiness.summary || `${checks.length} checks`;
  $("readiness").innerHTML = checks.map((check) => `<div class="readiness-row ${esc(check.Status || "warn")}">
    <strong>${esc(check.Status || "warn")}</strong>
    <strong title="${esc(check.Name)}">${esc(check.Name)}</strong>
    <span title="${esc(check.Detail)}">${esc(check.Detail)}</span>
  </div>`).join("") || `<div class="tip-row"><strong>No readiness data</strong><p>Reboot checks have not returned yet.</p></div>`;
}

function renderLogIntel(security = {}) {
  const logs = Array.isArray(security.logAnomalies?.logs) ? security.logAnomalies.logs : [];
  $("logIntelCount").textContent = `${logs.length} logs`;
  $("logIntel").innerHTML = logs.map((log) => `<div class="log-row ${(log.suspicious || log.serverErrors || log.authOrForbidden) ? "warm" : "ok"}">
    <strong title="${esc(log.path)}">${esc(log.path)}</strong>
    <span>${esc(log.lines || 0)} lines</span>
    <span>${esc(log.suspicious || 0)} probes · ${esc(log.serverErrors || 0)} 5xx · ${esc(log.authOrForbidden || 0)} auth</span>
  </div>`).join("") || `<div class="tip-row"><strong>No parsed app logs</strong><p>Log files were not found yet, or the slow monitor is still warming up.</p></div>`;
}

function renderAlertLog(security = {}) {
  const alerts = Array.isArray(security.alertLog) ? security.alertLog : [];
  $("alertCount").textContent = `${alerts.length} recent`;
  $("alertLog").innerHTML = alerts.map((alert) => {
    const time = alert.capturedAt ? new Date(alert.capturedAt).toLocaleTimeString() : "--";
    return `<div class="alert-row ${esc(alert.severity || "info")}">
      <strong>${esc(alert.severity || "info")}</strong>
      <strong title="${esc(alert.title)}">${esc(alert.title)}</strong>
      <span title="${esc(alert.detail)}">${esc(time)} · ${esc(alert.source)} · ${esc(alert.detail)}</span>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No alert trail yet</strong><p>Hot signals will be recorded here with cooldown deduping.</p></div>`;
}

function renderEvents(events = []) {
  $("events").innerHTML = events.map((event) => {
    const level = String(event.LevelDisplayName || "Warning").toLowerCase();
    const time = event.TimeCreated ? new Date(event.TimeCreated).toLocaleTimeString() : "--";
    return `<div class="event-row ${level}">
      <div class="event-title"><strong>${esc(event.ProviderName || event.LogName)}</strong><span>${esc(time)} · ${esc(event.LevelDisplayName || "")} ${esc(event.Id || "")}</span></div>
      <p>${esc(event.Message || "")}</p>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No recent warnings</strong><p>System and Application logs are quiet for the last six hours.</p></div>`;
}

function renderRecommendations(tips = []) {
  $("recommendations").innerHTML = tips.map((tip) => `<div class="tip-row ${tip.severity}">
    <div class="tip-title"><strong>${esc(tip.title)}</strong><span>${esc(tip.severity)}</span></div>
    <p>${esc(tip.detail)}</p>
  </div>`).join("");
}

function renderOperatorConfig() {
  const profiles = Array.isArray(operatorConfig.profiles) ? operatorConfig.profiles : [];
  $("profileSelect").innerHTML = [
    `<option value="">Default config</option>`,
    ...profiles.map((profile) => {
      const suffix = profile.example ? " (example)" : "";
      const selected = profile.name === operatorConfig.profile?.active ? " selected" : "";
      return `<option value="${esc(profile.name)}"${selected}>${esc(profile.label || profile.name)}${suffix}</option>`;
    })
  ].join("");

  const links = Array.isArray(operatorConfig.quickLinks) ? operatorConfig.quickLinks : [];
  $("quickLinks").innerHTML = links.map((link) => `<a class="button-link" href="${esc(link.href)}" target="_blank" rel="noopener">${esc(link.label || link.href)}</a>`).join("")
    || `<span class="muted-note">Configure quick links in masterhud.config.json.</span>`;

  const services = Array.isArray(operatorConfig.managedServices) ? operatorConfig.managedServices : [];
  $("serviceSelect").innerHTML = services.map((service) => {
    const value = typeof service === "string" ? service : service.name;
    const label = typeof service === "string" ? service : service.label || service.name;
    return `<option value="${esc(value)}">${esc(label)}</option>`;
  }).join("");
}

async function loadOperatorConfig() {
  try {
    const res = await fetch("/api/operator-config", { cache: "no-store" });
    const data = await res.json();
    if (data.ok) {
      operatorConfig = data;
      renderOperatorConfig();
    }
  } catch (error) {
    console.warn("MasterHUD config failed", error);
  }
}

function renderBlockedIps(security = {}) {
  const blocked = Array.isArray(security.autoBlockedIps) ? security.autoBlockedIps : [];
  $("blockedIpCount").textContent = `${blocked.length} active`;
  $("blockedIpList").innerHTML = blocked.map((entry) => {
    const expires = entry.expiresAt ? new Date(entry.expiresAt).toLocaleTimeString() : "manual";
    const countText = entry.count === "manual" ? "manual" : `${entry.count || 0} tries`;
    return `<div class="blocked-row">
      <strong class="name" title="${esc(entry.ip)}">${esc(entry.ip)}</strong>
      <span title="${esc(entry.count || 0)} failed attempts">${esc(countText)}</span>
      <span title="${esc(entry.expiresAt || "")}">until ${esc(expires)}</span>
      <button type="button" data-unblock-ip="${esc(entry.ip)}">Unblock</button>
    </div>`;
  }).join("") || `<div class="tip-row"><strong>No active blocks</strong><p>Repeated failed logons will appear here after the blocker runs.</p></div>`;
}

function formatActionOutput(data) {
  const parts = [];
  if (data.message) parts.push(data.message);
  if (data.stdout) parts.push(String(data.stdout).trim());
  if (data.stderr) parts.push(String(data.stderr).trim());
  if (data.error) parts.push(String(data.error).trim());
  if (data.statusCode) parts.push(`HTTP ${data.statusCode}`);
  if (data.body) parts.push(String(data.body).trim());
  if (data.snapshot?.capturedAt) parts.push(`Snapshot refreshed ${new Date(data.snapshot.capturedAt).toLocaleTimeString()}`);
  return parts.filter(Boolean).join("\n\n") || JSON.stringify(data, null, 2);
}

async function postAction(path, payload = {}, label = "Action") {
  $("actionStatus").textContent = "running";
  $("actionOutput").textContent = `${label} running...`;
  try {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    $("actionStatus").textContent = data.ok ? "done" : "failed";
    $("actionOutput").textContent = formatActionOutput(data);
    if (!data.ok) console.warn("MasterHUD action failed", data);
  } catch (error) {
    $("actionStatus").textContent = "failed";
    $("actionOutput").textContent = `${label} failed: ${error.message}`;
    console.warn("MasterHUD action failed", error);
  }
}

function setupSectionMenu() {
  const links = Array.from(document.querySelectorAll(".section-links a"));
  const jump = $("sectionJump");
  const sections = links
    .map((link) => document.querySelector(link.hash))
    .filter(Boolean);

  const setActive = (hash) => {
    links.forEach((link) => link.classList.toggle("active", link.hash === hash));
    if (jump && Array.from(jump.options).some((option) => option.value === hash)) {
      jump.value = hash;
    }
  };

  jump?.addEventListener("change", () => {
    const target = document.querySelector(jump.value);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      setActive(jump.value);
    }
  });

  links.forEach((link) => {
    link.addEventListener("click", () => setActive(link.hash));
  });

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible) setActive(`#${visible.target.id}`);
    }, { rootMargin: "-64px 0px -72% 0px", threshold: 0.01 });
    sections.forEach((section) => observer.observe(section));
  }

  setActive(window.location.hash || "#overview");
}

function setupActions() {
  $("blockIpBtn")?.addEventListener("click", () => postAction("/api/actions/block-ip", { ip: $("ipInput").value.trim() }, "Block IP"));
  $("unblockIpBtn")?.addEventListener("click", () => postAction("/api/actions/unblock-ip", { ip: $("ipInput").value.trim() }, "Unblock IP"));
  $("startServiceBtn")?.addEventListener("click", () => postAction("/api/actions/start-service", { name: $("serviceSelect").value }, `Start ${$("serviceSelect").value}`));
  $("restartServiceBtn")?.addEventListener("click", () => {
    const name = $("serviceSelect").value;
    if (window.confirm(`Restart ${name} now? This can briefly interrupt users.`)) {
      postAction("/api/actions/restart-service", { name }, `Restart ${name}`);
    }
  });
  $("healthBtn")?.addEventListener("click", () => postAction("/api/actions/app-health", {}, "App health"));
  $("caddyValidateBtn")?.addEventListener("click", () => postAction("/api/actions/caddy-validate", {}, "Caddy validate"));
  $("tabletReadinessBtn")?.addEventListener("click", () => postAction("/api/actions/tablet-readiness", {}, "Tablet readiness"));
  $("scanBtn")?.addEventListener("click", () => postAction("/api/actions/run-security-scan", {}, "Security scan"));
  $("updateScanBtn")?.addEventListener("click", () => postAction("/api/actions/run-update-scan", {}, "Update scan"));
  $("updateBriefBtn")?.addEventListener("click", () => postAction("/api/actions/update-brief", {}, "Update brief"));
  $("logonBlockerBtn")?.addEventListener("click", () => postAction("/api/actions/run-logon-blocker", {}, "Failed-logon blocker"));
  $("refreshHudBtn")?.addEventListener("click", () => postAction("/api/actions/refresh-snapshot", {}, "Refresh HUD"));
  $("applyProfileBtn")?.addEventListener("click", async () => {
    await postAction("/api/actions/set-profile", { profile: $("profileSelect").value }, "Switch profile");
    await loadOperatorConfig();
  });
  $("blockedIpList")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-unblock-ip]");
    if (!button) return;
    postAction("/api/actions/unblock-ip", { ip: button.dataset.unblockIp }, `Unblock ${button.dataset.unblockIp}`);
  });
}

function render(data) {
  $("connection").textContent = "live";
  $("connection").classList.remove("warn");
  $("clock").textContent = new Date(data.capturedAt).toLocaleTimeString();
  $("hostLine").textContent = `${data.host.hostname} · Windows ${data.host.release} · uptime ${fmt.format(data.host.uptime / 3600)}h · sample ${data.sampleMs}ms`;
  renderKpis(data);
  renderSecurity(data.windows?.security);
  renderBlockedIps(data.windows?.security);
  renderCoverage(data.windows?.security);
  renderUpdateWatch(data.windows?.security);
  renderReadiness(data.windows);
  renderLogIntel(data.windows?.security);
  renderAlertLog(data.windows?.security);
  renderProcesses(data.windows?.processes);
  renderVolumes(data.windows?.volumes);
  renderPorts(data.windows?.ports);
  renderConnections(data.windows?.connections);
  renderServices(data.windows?.services);
  renderWorkloads(data.windows?.workloads);
  renderDrift(data.windows?.workloads);
  renderStartup(data.windows);
  renderEvents(data.windows?.events);
  renderRecommendations(data.recommendations);
}

setupSectionMenu();
setupActions();
loadOperatorConfig();

const source = new EventSource("/events");
source.onmessage = (event) => render(JSON.parse(event.data));
source.onerror = () => {
  $("connection").textContent = "reconnecting";
  $("connection").classList.add("warn");
};

fetch("/api/snapshot")
  .then((res) => res.json())
  .then((data) => data.host && render(data))
  .catch(() => {});
