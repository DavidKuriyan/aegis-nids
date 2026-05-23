// ============================================================
// GLOBAL CHART REFERENCES
// ============================================================
let throughputChart   = null;
let attackPieChart    = null;
let eventTypePieChart = null;

// Polling interval IDs
let statusInterval = null;
let alertInterval  = null;
let chartInterval  = null;

// Theme Colors (SOC Theme - Deep Navy / Electric Blue / Crimson Red / Emerald Green)
const C = {
    blue:     '#00d4ff', // Electric Blue
    purple:   '#7c4dff', // Purple
    teal:     '#00e676', // Emerald Green
    emerald:  '#00e676', // Emerald Green
    amber:    '#ffab00', // Amber
    orange:   '#ff6d00', // Deep Orange
    red:      '#ff1744', // Crimson Red
    grid:     'rgba(255, 255, 255, 0.05)',
    text:     '#a0aec0'
};

// Action badge class mapping
const ACTION_CLASS = {
    icmp:          'ab-icmp',
    dns_message:   'ab-dns',
    http_request:  'ab-http_req',
    http_response: 'ab-http_res',
    tcp_connection:'ab-tcp',
    udp_message:   'ab-udp',
};

// ============================================================
// VALUE ANIMATION UTILITY
// ============================================================
function animateValue(elementId, end, duration = 800) {
    const obj = document.getElementById(elementId);
    if (!obj) return;
    
    // Parse current value in the DOM
    let start = parseInt(obj.textContent.replace(/,/g, '')) || 0;
    if (start === end) {
        obj.textContent = end.toLocaleString();
        return;
    }
    
    const startTime = performance.now();
    
    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing: easeOutQuad
        const ease = progress * (2 - progress);
        const current = Math.round(start + (end - start) * ease);
        obj.textContent = current.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    requestAnimationFrame(update);
}

// ============================================================
// LIVE TICKING CLOCK
// ============================================================
function updateClock() {
    const clockEl = document.getElementById('headerClock');
    if (clockEl) {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
}

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    loadInterfaces();
    initCharts();

    pollStatus();
    pollAlerts();
    pollCharts();

    statusInterval = setInterval(pollStatus, 1500);
    alertInterval  = setInterval(pollAlerts, 2500);
    chartInterval  = setInterval(pollCharts, 5000);

    // Start ticking clock
    setInterval(updateClock, 1000);
    updateClock();
});

// ============================================================
// API CALLS
// ============================================================
async function loadInterfaces() {
    const sel = document.getElementById('interfaceSelect');
    try {
        const res  = await fetch('/api/interfaces');
        const data = await res.json();
        if (data.status === 'success') {
            sel.innerHTML = '<option value="-1">Auto-select Active Interface</option>';
            Object.keys(data.interfaces).forEach(idx => {
                const info = data.interfaces[idx];
                const opt  = document.createElement('option');
                opt.value       = idx;
                opt.textContent = `${info.friendly_name} (${info.ip})`;
                sel.appendChild(opt);
            });
        } else {
            sel.innerHTML = '<option value="-1">Error loading interfaces</option>';
        }
    } catch (e) {
        sel.innerHTML = '<option value="-1">Could not contact backend API</option>';
        console.error(e);
    }
}

async function pollStatus() {
    try {
        const res  = await fetch('/api/status');
        const data = await res.json();
        if (data.status === 'success') updateDashboard(data);
    } catch (e) {
        console.error('Status poll error:', e);
    }
}

async function pollAlerts() {
    try {
        const res  = await fetch('/api/alerts?limit=50');
        const data = await res.json();
        if (data.status === 'success') updateAlertsTable(data.alerts);
    } catch (e) {
        console.error('Alerts poll error:', e);
    }
}

async function pollCharts() {
    try {
        const [histRes, statsRes] = await Promise.all([
            fetch('/api/charts/history?limit=20'),
            fetch('/api/charts/stats')
        ]);
        const histData  = await histRes.json();
        const statsData = await statsRes.json();
        if (histData.status === 'success' && statsData.status === 'success') {
            updateChartsData(histData.history, statsData.stats);
        }
    } catch (e) {
        console.error('Chart poll error:', e);
    }
}

// ============================================================
// CONTROLS
// ============================================================
async function startIDS() {
    const sel     = document.getElementById('interfaceSelect');
    const ifaceIdx = parseInt(sel.value);
    document.getElementById('startBtn').disabled = true;
    sel.disabled = true;

    try {
        const res  = await fetch('/api/start', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ interface_idx: ifaceIdx })
        });
        const data = await res.json();
        if (data.status === 'success') {
            document.getElementById('stopBtn').disabled = false;
            pollStatus();
        } else {
            alert('Failed to start: ' + data.message);
            document.getElementById('startBtn').disabled = false;
            sel.disabled = false;
        }
    } catch (e) {
        alert('HTTP error trying to start IDS.');
        document.getElementById('startBtn').disabled = false;
        sel.disabled = false;
    }
}

async function stopIDS() {
    document.getElementById('stopBtn').disabled = true;
    try {
        const res  = await fetch('/api/stop', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            document.getElementById('startBtn').disabled = false;
            document.getElementById('interfaceSelect').disabled = false;
            pollStatus();
        } else {
            alert('Stop error: ' + data.message);
            document.getElementById('stopBtn').disabled = false;
        }
    } catch (e) {
        document.getElementById('stopBtn').disabled = false;
    }
}

async function clearLogs() {
    if (!confirm('Purge all database logs and alerts? This cannot be undone.')) return;
    try {
        const res  = await fetch('/api/clear', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            // Reset charts locally
            if (throughputChart) {
                throughputChart.data.labels = [];
                throughputChart.data.datasets.forEach(d => d.data = []);
                throughputChart.update('none');
            }
            if (attackPieChart) {
                attackPieChart.data.labels = [];
                attackPieChart.data.datasets[0].data = [];
                attackPieChart.update('none');
            }
            if (eventTypePieChart) {
                eventTypePieChart.data.labels = [];
                eventTypePieChart.data.datasets[0].data = [];
                eventTypePieChart.update('none');
            }
            clearMiniTables();
            pollAlerts();
            pollStatus();
        } else {
            alert('Clear error: ' + data.message);
        }
    } catch (e) { console.error(e); }
}

async function retrainModel() {
    const btn = document.getElementById('retrainBtn');
    btn.disabled = true;
    document.getElementById('retrainStatusText').textContent = 'Submitting retrain task...';
    try {
        const res  = await fetch('/api/retrain', { method: 'POST' });
        const data = await res.json();
        if (data.status !== 'success') {
            alert('Retrain error: ' + data.message);
            btn.disabled = false;
        }
    } catch (e) { btn.disabled = false; }
}

function exportAlertsCSV() {
    alert('Alerts are auto-saved to:\n\n[logs/alerts.csv]\n\nLook in your project logs/ directory.');
}

// ============================================================
// DASHBOARD UPDATE
// ============================================================
function updateDashboard(data) {
    const sniffing   = data.engines.packet_capture    === 'RUNNING';
    const predicting = data.engines.prediction_engine === 'RUNNING';

    // Buttons
    document.getElementById('startBtn').disabled          = sniffing;
    document.getElementById('interfaceSelect').disabled   = sniffing;
    document.getElementById('stopBtn').disabled           = !sniffing;

    // Engine badges
    const capBadge = document.getElementById('captureStatusBadge');
    const predBadge = document.getElementById('predictionStatusBadge');
    capBadge.textContent  = sniffing   ? 'RUNNING' : 'STOPPED';
    capBadge.className    = 'badge ' + (sniffing   ? 'badge-running' : 'badge-stopped');
    predBadge.textContent = predicting ? 'RUNNING' : 'STOPPED';
    predBadge.className   = 'badge ' + (predicting ? 'badge-running' : 'badge-stopped');

    // Sidebar state dot
    const dot  = document.getElementById('sidebarStateDot');
    const stxt = document.getElementById('sidebarStateText');
    if (sniffing) {
        dot.className   = 'pulse-circle pulse-circle-green';
        stxt.textContent = 'System Active';
        stxt.style.color = C.emerald;
    } else {
        dot.className   = 'pulse-circle pulse-circle-red';
        stxt.textContent = 'Offline';
        stxt.style.color = C.text;
    }

    // Header state elements (for top-bar)
    const headerDot = document.getElementById('headerStateDot');
    const headerText = document.getElementById('headerStateText');
    if (headerDot && headerText) {
        if (sniffing) {
            headerDot.className = 'pulse-circle pulse-circle-green';
            headerText.textContent = 'SYSTEM ACTIVE';
            headerText.style.color = C.emerald;
        } else {
            headerDot.className = 'pulse-circle pulse-circle-red';
            headerText.textContent = 'SYSTEM OFFLINE';
            headerText.style.color = C.text;
        }
    }

    // KPI - status
    const kpiStatus   = document.getElementById('kpiStatus');
    const kpiIconBox  = document.getElementById('statusIconBox');
    kpiStatus.textContent = sniffing ? 'Online' : 'Offline';
    kpiStatus.style.color = sniffing ? C.emerald : C.text;
    kpiIconBox.className  = 'kpi-icon ' + (sniffing ? 'kpi-green' : 'kpi-blue');

    // KPI - packets / flows (animated counters)
    animateValue('kpiPackets', data.traffic_stats.total_packets, 800);
    animateValue('kpiFlows', data.traffic_stats.active_flows, 800);

    // KPI - intrusions
    const count     = data.traffic_stats.malicious_packets;
    const kpiAlerts = document.getElementById('kpiAlerts');
    const alertIcon = document.getElementById('alertIconBox');
    animateValue('kpiAlerts', count, 800);
    
    if (count > 0) {
        kpiAlerts.style.color = C.red;
        alertIcon.className   = 'kpi-icon kpi-red';
        alertIcon.style.animation = 'pulse-red 1.5s infinite';
    } else {
        kpiAlerts.style.color = C.text;
        alertIcon.className   = 'kpi-icon kpi-blue';
        alertIcon.style.animation = 'none';
    }

    // Model + adapter
    const mStatus = document.getElementById('modelStatus');
    mStatus.textContent = data.engines.model_status === 'TRAINED' ? 'RF Active' : 'Signature Fallback';
    mStatus.style.color = data.engines.model_status === 'TRAINED' ? C.emerald : C.orange;
    document.getElementById('activeAdapterName').textContent = data.active_adapter;

    // Resources
    const cpu = data.system_resources.cpu;
    const ram = data.system_resources.ram;
    document.getElementById('cpuVal').textContent   = `${cpu}%`;
    document.getElementById('cpuFill').style.width  = `${cpu}%`;
    document.getElementById('ramVal').textContent   = `${ram}%`;
    document.getElementById('ramFill').style.width  = `${ram}%`;

    // Retrain status
    const retrainTxt = document.getElementById('retrainStatusText');
    const retrainBtn = document.getElementById('retrainBtn');
    if (data.training_state.is_training) {
        retrainTxt.textContent = data.training_state.status_msg;
        retrainTxt.style.color = C.amber;
        retrainBtn.disabled    = true;
        retrainBtn.innerHTML   = '<i class="fa-solid fa-spinner fa-spin"></i> Training...';
    } else {
        retrainTxt.textContent = data.training_state.status_msg;
        retrainBtn.disabled    = false;
        retrainBtn.innerHTML   = '<i class="fa-solid fa-rotate"></i> Rebuild Classifier';
        retrainTxt.style.color = data.training_state.error ? C.red
            : (data.training_state.status_msg.includes('success') ? C.emerald : C.text);
    }

    // Kibana panels
    if (data.kibana_stats) {
        updateKibanaPanels(data.kibana_stats);
    }
}

// ============================================================
// KIBANA PANELS
// ============================================================
function updateKibanaPanels(stats) {
    updateMiniTable('ipAddrTable', stats.ip_addresses, true);
    updateMiniTable('dnsTable',    stats.dns_queries,  false);
    updateMiniTable('httpTable',   stats.http_servers, false);
    updateMiniTable('uaTable',     stats.user_agents,  false);
    updateMiniTable('ctTable',     stats.content_types,false);

    // Update event types donut
    if (eventTypePieChart && stats.event_types && Object.keys(stats.event_types).length > 0) {
        const keys = Object.keys(stats.event_types);
        const vals = keys.map(k => stats.event_types[k]);
        eventTypePieChart.data.labels = keys;
        eventTypePieChart.data.datasets[0].data = vals;
        eventTypePieChart.update('none');
    }

    // Raw events table
    if (stats.recent_events && stats.recent_events.length > 0) {
        updateRawEventsTable(stats.recent_events);
    }
}

function updateMiniTable(containerId, dataObj, isIp) {
    const el = document.getElementById(containerId);
    if (!el) return;
    if (!dataObj || Object.keys(dataObj).length === 0) {
        el.innerHTML = '<div class="mini-stat-empty">Waiting for data...</div>';
        return;
    }

    const maxVal = Math.max(...Object.values(dataObj));
    let html = '';
    Object.entries(dataObj).forEach(([label, count]) => {
        const pct = maxVal > 0 ? Math.round((count / maxVal) * 100) : 0;
        const fontClass = isIp ? 'mono-font font-bold' : '';
        html += `
            <div class="mini-stat-row">
                <span class="mini-stat-label ${fontClass}" title="${label}">${label}</span>
                <div class="mini-stat-bar-wrap">
                    <div class="mini-stat-bar-bg">
                        <div class="mini-stat-bar-fill" style="width:${pct}%"></div>
                    </div>
                    <span class="mini-stat-count">${count}</span>
                </div>
            </div>`;
    });
    el.innerHTML = html;
}

function clearMiniTables() {
    ['ipAddrTable','dnsTable','httpTable','uaTable','ctTable'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<div class="mini-stat-empty">Waiting for data...</div>';
    });
    const evBody = document.getElementById('eventsTableBody');
    if (evBody) evBody.innerHTML = '<tr><td colspan="9" class="no-alerts">No events captured yet.</td></tr>';
}

function updateRawEventsTable(events) {
    const tbody = document.getElementById('eventsTableBody');
    if (!tbody) return;
    let html = '';
    events.slice(0, 50).forEach(ev => {
        const action = ev.action || 'ip';
        const cls    = ACTION_CLASS[action] || 'ab-default';
        const actionLabel = action.replace('_', ' ').toUpperCase();
        const indicator = ev.indicator
            ? `<span class="indicator-badge">${ev.indicator}</span>` : '—';
        const url = ev.url ? `<span title="${ev.url}">${ev.url.substring(0, 40)}${ev.url.length > 40 ? '…' : ''}</span>` : '—';
        const ct  = ev.content_type || '—';

        html += `<tr>
            <td class="mono-font" style="font-size:0.68rem; color:var(--text-muted);">${ev.time}</td>
            <td><span class="action-badge ${cls}">${actionLabel}</span></td>
            <td class="mono-font">${ev.src_ip || '—'}</td>
            <td class="mono-font">${ev.src_port || '—'}</td>
            <td class="mono-font">${ev.dst_ip || '—'}</td>
            <td class="mono-font">${ev.dst_port || '—'}</td>
            <td style="font-size:0.68rem; color:var(--text-secondary);">${ct}</td>
            <td style="font-size:0.68rem; color:var(--accent-blue);">${url}</td>
            <td>${indicator}</td>
        </tr>`;
    });
    tbody.innerHTML = html || '<tr><td colspan="9" class="no-alerts">No events captured yet.</td></tr>';
}

// ============================================================
// ALERTS TABLE
// ============================================================
function updateAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-alerts">No malicious flows detected in this session.</td></tr>';
        return;
    }
    let html = '';
    alerts.forEach(a => {
        const riskCls = `threat-${a.risk_level}`;
        html += `<tr class="severity-row-${a.risk_level.toLowerCase()}">
            <td class="mono-font" style="font-size:0.7rem; color:var(--text-muted);">${a.timestamp}</td>
            <td style="font-weight:600; color:var(--text-primary);">${a.attack_type}</td>
            <td><span class="threat-badge ${riskCls}">${a.risk_level}</span></td>
            <td class="mono-font">${a.src_ip}:${a.src_port}</td>
            <td class="mono-font">${a.dst_ip}:${a.dst_port}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); border:1px solid var(--card-border);">${a.protocol}</span></td>
            <td class="text-right mono-font" style="color:var(--text-secondary); font-size:0.7rem;">
                ${a.flow_duration.toFixed(3)}s | Pkts: ${a.packet_count}
            </td>
        </tr>`;
    });
    tbody.innerHTML = html;
}

// ============================================================
// CHART.JS INIT
// ============================================================
function initCharts() {
    const baseOpts = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: C.text, font: { family: 'Inter', size: 10 }, boxWidth: 10 } }
        }
    };

    // 1. Throughput Line Chart
    const tCtx = document.getElementById('throughputChart').getContext('2d');
    
    // Create soft gradients
    const benignGrad = tCtx.createLinearGradient(0, 0, 0, 240);
    benignGrad.addColorStop(0, 'rgba(0, 230, 118, 0.25)'); // Emerald Green
    benignGrad.addColorStop(1, 'rgba(0, 230, 118, 0.0)');
    
    const threatGrad = tCtx.createLinearGradient(0, 0, 0, 240);
    threatGrad.addColorStop(0, 'rgba(255, 23, 68, 0.25)'); // Crimson Red
    threatGrad.addColorStop(1, 'rgba(255, 23, 68, 0.0)');

    throughputChart = new Chart(tCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Benign',
                    borderColor: C.emerald,
                    backgroundColor: benignGrad,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    data: []
                },
                {
                    label: 'Threats',
                    borderColor: C.red,
                    backgroundColor: threatGrad,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    data: []
                }
            ]
        },
        options: {
            ...baseOpts,
            scales: {
                x: { grid: { color: C.grid }, ticks: { color: C.text, font: { size: 8 } } },
                y: { grid: { color: C.grid }, ticks: { color: C.text, font: { size: 8 } } }
            }
        }
    });

    // 2. Attack Breakdown Doughnut
    const aCtx = document.getElementById('attackPieChart').getContext('2d');
    attackPieChart = new Chart(aCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [C.blue, C.purple, C.orange, C.amber, C.red, '#b388ff', '#80d8ff', '#ff8a80'],
                borderWidth: 1,
                borderColor: 'rgba(10, 14, 26, 0.8)'
            }]
        },
        options: {
            ...baseOpts,
            cutout: '70%',
            plugins: {
                legend: { position: 'bottom', labels: { color: C.text, font: { size: 9 }, boxWidth: 8 } }
            }
        }
    });

    // 3. Event Types Doughnut
    const eCtx = document.getElementById('eventTypePieChart').getContext('2d');
    eventTypePieChart = new Chart(eCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [C.blue, C.purple, C.emerald, C.amber, C.orange, C.red],
                borderWidth: 1,
                borderColor: 'rgba(10, 14, 26, 0.8)'
            }]
        },
        options: {
            ...baseOpts,
            cutout: '70%',
            plugins: {
                legend: { position: 'bottom', labels: { color: C.text, font: { size: 9 }, boxWidth: 8 } }
            }
        }
    });
}

function updateChartsData(history, stats) {
    // Throughput (reversed in JS to order left-to-right/chronological)
    if (history && history.length > 0 && throughputChart) {
        const histCopy = [...history].reverse();
        throughputChart.data.labels            = histCopy.map(h => h.window_time.split(' ')[1]);
        throughputChart.data.datasets[0].data  = histCopy.map(h => h.benign_packets);
        throughputChart.data.datasets[1].data  = histCopy.map(h => h.malicious_packets);
        throughputChart.update('none');
    }

    // Attack vectors doughnut
    if (stats && stats.attack_types && attackPieChart) {
        const keys = Object.keys(stats.attack_types).filter(k => k !== 'BENIGN');
        attackPieChart.data.labels              = keys;
        attackPieChart.data.datasets[0].data    = keys.map(k => stats.attack_types[k]);
        attackPieChart.update('none');
    }
}

// ============================================================
// TAB NAVIGATION
// ============================================================
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById(tabId + 'Tab').classList.add('active');
    document.getElementById('nav-' + tabId).classList.add('active');
}

// ============================================================
// THREAT SIMULATOR
// ============================================================
async function triggerSimulation(attackType, mode) {
    try {
        const res  = await fetch('/api/simulate', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ type: attackType, mode: mode })
        });
        const data = await res.json();
        if (data.status === 'success') {
            alert('✓ ' + data.message + '\n\nCheck the Dashboard tab — alerts should appear within a few seconds.');
            pollStatus();
            pollAlerts();
            pollCharts();
        } else {
            alert('Simulation error: ' + data.message);
        }
    } catch (e) {
        alert('HTTP error during simulation.');
        console.error(e);
    }
}
