/**
 * Pentagon Security Dashboard - JavaScript
 * Handles real-time updates, charts, maps, and user interactions
 */

// =============================================================================
// GLOBAL STATE
// =============================================================================

const state = {
    tasks: {},
    eventSource: null,
    charts: {},
    map: null,
    mapMarkers: [],
    logs: [],
    sourceLocation: { lat: 40.7128, lon: -74.0060 } // Default: New York
};

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initEventStream();
    initCharts();
    initMap();
    loadTasks();
    loadStats();
    
    // Periodic refresh
    setInterval(loadStats, 30000);
});

// =============================================================================
// NAVIGATION
// =============================================================================

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.dataset.section;
            
            // Update active states
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Show corresponding section
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(section).classList.add('active');
            
            // Reinitialize map when switching to map section
            if (section === 'map' && state.map) {
                setTimeout(() => state.map.invalidateSize(), 100);
            }
        });
    });
}

// =============================================================================
// SERVER-SENT EVENTS
// =============================================================================

function initEventStream() {
    if (state.eventSource) {
        state.eventSource.close();
    }
    
    state.eventSource = new EventSource('/api/events');
    
    state.eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleEvent(data);
        } catch (error) {
            console.error('Failed to parse event:', error);
        }
    };
    
    state.eventSource.onerror = () => {
        console.log('Event stream error, reconnecting in 5s...');
        setTimeout(initEventStream, 5000);
    };
}

function handleEvent(event) {
    switch (event.type) {
        case 'connected':
            addLog('Connected to Pentagon server', 'success');
            break;
        case 'task_created':
            state.tasks[event.data.id] = event.data;
            addLog(`Task created: ${event.data.type} on ${event.data.target}`, 'info');
            updateTasksUI();
            updateStats();
            break;
        case 'task_updated':
            state.tasks[event.data.id] = event.data;
            updateTasksUI();
            updateStats();
            updateMapConnections();
            break;
        case 'task_log':
            addLog(`[${event.data.task_id}] ${event.data.log.message}`, 'system');
            break;
        case 'task_result':
            if (event.data.result.type === 'geo_data') {
                updateMapWithGeoData(event.data.result);
            }
            break;
    }
}

// =============================================================================
// TASKS API
// =============================================================================

async function loadTasks() {
    try {
        const response = await fetch('/api/tasks');
        if (response.ok) {
            state.tasks = await response.json();
            updateTasksUI();
        }
    } catch (error) {
        console.error('Failed to load tasks:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const stats = await response.json();
            updateStats(stats);
            updateCharts(stats);
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

function updateStats(stats) {
    // Calculate stats from current tasks if not provided
    if (!stats) {
        stats = calculateLocalStats();
    }
    
    document.getElementById('active-tasks').textContent = 
        Object.values(state.tasks).filter(t => t.status === 'running').length;
    document.getElementById('completed-tasks').textContent = 
        Object.values(state.tasks).filter(t => t.status === 'completed').length;
    document.getElementById('hosts-found').textContent = stats.total_hosts_found || 0;
    document.getElementById('packets-captured').textContent = stats.total_packets_captured || 0;
}

function calculateLocalStats() {
    const tasks = Object.values(state.tasks);
    return {
        total_hosts_found: tasks.reduce((sum, t) => sum + (t.hosts_found || 0), 0),
        total_ports_scanned: tasks.reduce((sum, t) => sum + (t.ports_scanned || 0), 0),
        total_packets_captured: tasks.reduce((sum, t) => sum + (t.packets_captured || 0), 0),
        task_types: tasks.reduce((acc, t) => {
            acc[t.type] = (acc[t.type] || 0) + 1;
            return acc;
        }, {}),
        status_counts: tasks.reduce((acc, t) => {
            acc[t.status] = (acc[t.status] || 0) + 1;
            return acc;
        }, {})
    };
}

function updateTasksUI() {
    updateActiveTasksList();
    updateAllTasksTable();
}

function updateActiveTasksList() {
    const container = document.getElementById('active-tasks-list');
    const activeTasks = Object.values(state.tasks).filter(t => t.status === 'running');
    
    if (activeTasks.length === 0) {
        container.innerHTML = '<div class="empty-state">No active tasks. Start a scan from the Scans tab.</div>';
        return;
    }
    
    container.innerHTML = activeTasks.map(task => `
        <div class="task-item" onclick="showTaskDetails('${task.id}')">
            <div class="task-icon">${getTaskIcon(task.type)}</div>
            <div class="task-info">
                <div class="task-name">${getTaskTypeName(task.type)}</div>
                <div class="task-target">${escapeHtml(task.target)}</div>
            </div>
            <div class="task-progress">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${task.progress}%"></div>
                </div>
                <div class="progress-text">${task.progress}%</div>
            </div>
            <span class="task-status ${task.status}">${task.status}</span>
        </div>
    `).join('');
}

function updateAllTasksTable() {
    const tbody = document.getElementById('tasks-tbody');
    const tasks = Object.values(state.tasks);
    
    if (tasks.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-secondary);">No tasks yet</td></tr>';
        return;
    }
    
    tbody.innerHTML = tasks.map(task => `
        <tr>
            <td><code>${task.id.substring(0, 12)}...</code></td>
            <td>${getTaskIcon(task.type)} ${getTaskTypeName(task.type)}</td>
            <td>${escapeHtml(task.target)}</td>
            <td><span class="task-status ${task.status}">${task.status}</span></td>
            <td>
                <div class="progress-bar" style="width: 100px; display: inline-block;">
                    <div class="progress-fill" style="width: ${task.progress}%"></div>
                </div>
                ${task.progress}%
            </td>
            <td>${formatTime(task.start_time)}</td>
            <td>
                ${task.status === 'running' 
                    ? `<button class="btn-danger" onclick="stopTask('${task.id}')">Stop</button>` 
                    : `<button class="btn-secondary" onclick="showTaskDetails('${task.id}')" style="padding: 6px 10px;">View</button>`}
            </td>
        </tr>
    `).join('');
}

// =============================================================================
// SCAN ACTIONS
// =============================================================================

async function startNmapScan() {
    const target = document.getElementById('nmap-target').value;
    const scanType = document.getElementById('nmap-type').value;
    
    if (!target) {
        showToast('Please enter a target IP or subnet', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/scan/nmap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: scanType })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Nmap scan started: ${data.task_id}`, 'success');
            document.getElementById('nmap-target').value = '';
        } else {
            showToast(data.error || 'Failed to start scan', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
}

async function startCapture() {
    const interface_ = document.getElementById('capture-interface').value;
    const duration = document.getElementById('capture-duration').value;
    
    if (!interface_) {
        showToast('Please enter an interface name', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/scan/traffic', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: interface_, duration: parseInt(duration) })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Traffic capture started: ${data.task_id}`, 'success');
        } else {
            showToast(data.error || 'Failed to start capture', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
}

async function startSpoof() {
    const target = document.getElementById('spoof-target').value;
    const gateway = document.getElementById('spoof-gateway').value;
    
    if (!target || !gateway) {
        showToast('Please enter both target and gateway IPs', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/scan/spoof', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, gateway })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`ARP spoofing started: ${data.task_id}`, 'success');
            document.getElementById('spoof-target').value = '';
            document.getElementById('spoof-gateway').value = '';
        } else {
            showToast(data.error || 'Failed to start spoofing', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
}

async function stopTask(taskId) {
    try {
        const response = await fetch(`/api/task/${taskId}/stop`, { method: 'POST' });
        const data = await response.json();
        
        if (response.ok) {
            showToast('Task stopped', 'info');
        } else {
            showToast(data.error || 'Failed to stop task', 'error');
        }
    } catch (error) {
        showToast('Network error. Please try again.', 'error');
    }
}

// =============================================================================
// CHARTS
// =============================================================================

function initCharts() {
    const ctx1 = document.getElementById('taskDistChart').getContext('2d');
    const ctx2 = document.getElementById('statusChart').getContext('2d');
    const ctx3 = document.getElementById('activityChart').getContext('2d');
    
    const chartColors = {
        primary: '#00ff88',
        secondary: '#0066ff',
        warning: '#d29922',
        danger: '#f85149',
        info: '#58a6ff'
    };
    
    // Task Distribution Pie Chart
    state.charts.taskDist = new Chart(ctx1, {
        type: 'doughnut',
        data: {
            labels: ['Network Scan', 'Traffic Capture', 'ARP Spoof'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [chartColors.primary, chartColors.secondary, chartColors.warning],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#8b949e', padding: 15 }
                }
            }
        }
    });
    
    // Status Bar Chart
    state.charts.status = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: ['Running', 'Completed', 'Failed', 'Stopped'],
            datasets: [{
                label: 'Tasks',
                data: [0, 0, 0, 0],
                backgroundColor: [chartColors.info, chartColors.primary, chartColors.danger, chartColors.warning],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#8b949e' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#8b949e' }
                }
            }
        }
    });
    
    // Activity Line Chart
    state.charts.activity = new Chart(ctx3, {
        type: 'line',
        data: {
            labels: generateTimeLabels(10),
            datasets: [{
                label: 'Activity',
                data: Array(10).fill(0),
                borderColor: chartColors.primary,
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#8b949e' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#8b949e' }
                }
            }
        }
    });
}

function updateCharts(stats) {
    if (!stats) return;
    
    // Update task distribution
    const taskTypes = stats.task_types || {};
    state.charts.taskDist.data.datasets[0].data = [
        taskTypes.nmap || 0,
        taskTypes.traffic_capture || 0,
        taskTypes.arp_spoof || 0
    ];
    state.charts.taskDist.update('none');
    
    // Update status chart
    const statusCounts = stats.status_counts || {};
    state.charts.status.data.datasets[0].data = [
        statusCounts.running || 0,
        statusCounts.completed || 0,
        statusCounts.failed || 0,
        statusCounts.stopped || 0
    ];
    state.charts.status.update('none');
    
    // Update activity chart (add new data point)
    const activityData = state.charts.activity.data.datasets[0].data;
    activityData.push(Object.values(state.tasks).filter(t => t.status === 'running').length);
    if (activityData.length > 10) activityData.shift();
    state.charts.activity.data.labels = generateTimeLabels(activityData.length);
    state.charts.activity.update('none');
}

function generateTimeLabels(count) {
    const labels = [];
    const now = new Date();
    for (let i = count - 1; i >= 0; i--) {
        const time = new Date(now - i * 30000);
        labels.push(time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
    }
    return labels;
}

// =============================================================================
// MAP
// =============================================================================

function initMap() {
    // Create map centered on world view
    state.map = L.map('threat-map', {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        attributionControl: false
    });
    
    // Add dark tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
    }).addTo(state.map);
    
    // Add default source marker (your location)
    addSourceMarker();
    
    // Load initial connections
    loadMapConnections();
}

function addSourceMarker() {
    const sourceIcon = L.divIcon({
        className: 'custom-marker',
        html: '<div class="marker-pulse source"></div>',
        iconSize: [20, 20]
    });
    
    L.marker([state.sourceLocation.lat, state.sourceLocation.lon], { icon: sourceIcon })
        .addTo(state.map)
        .bindPopup('<b>Your Location</b><br>Pentagon Control Center');
}

async function loadMapConnections() {
    try {
        const response = await fetch('/api/map/connections');
        if (response.ok) {
            const connections = await response.json();
            updateMapMarkers(connections);
        }
    } catch (error) {
        console.error('Failed to load map connections:', error);
    }
}

function updateMapConnections() {
    loadMapConnections();
}

function updateMapMarkers(connections) {
    // Clear existing markers
    state.mapMarkers.forEach(marker => state.map.removeLayer(marker));
    state.mapMarkers = [];
    
    const countries = new Set();
    
    connections.forEach(conn => {
        if (conn.target && conn.target.lat && conn.target.lon) {
            const targetIcon = L.divIcon({
                className: 'custom-marker',
                html: `<div class="marker-pulse target"></div>`,
                iconSize: [20, 20]
            });
            
            const marker = L.marker([conn.target.lat, conn.target.lon], { icon: targetIcon })
                .bindPopup(`
                    <b>${conn.target.ip}</b><br>
                    ${conn.target.city}, ${conn.target.country}<br>
                    <small>Task: ${conn.type} (${conn.status})</small>
                `);
            
            state.mapMarkers.push(marker);
            marker.addTo(state.map);
            
            // Draw connection line
            if (conn.status === 'running') {
                const line = L.polyline([
                    [state.sourceLocation.lat, state.sourceLocation.lon],
                    [conn.target.lat, conn.target.lon]
                ], {
                    color: '#00ff88',
                    weight: 2,
                    opacity: 0.6,
                    dashArray: '5, 10'
                });
                state.mapMarkers.push(line);
                line.addTo(state.map);
            }
            
            countries.add(conn.target.country);
        }
    });
    
    // Update map stats
    document.getElementById('map-connections').textContent = connections.length;
    document.getElementById('map-countries').textContent = countries.size;
}

function updateMapWithGeoData(geoData) {
    if (geoData.target && geoData.target.lat && geoData.target.lon) {
        const targetIcon = L.divIcon({
            className: 'custom-marker',
            html: '<div class="marker-pulse target"></div>',
            iconSize: [20, 20]
        });
        
        const marker = L.marker([geoData.target.lat, geoData.target.lon], { icon: targetIcon })
            .addTo(state.map)
            .bindPopup(`<b>${geoData.target.ip}</b><br>${geoData.target.city}, ${geoData.target.country}`);
        
        state.mapMarkers.push(marker);
        
        // Draw animated connection line
        const line = L.polyline([
            [state.sourceLocation.lat, state.sourceLocation.lon],
            [geoData.target.lat, geoData.target.lon]
        ], {
            color: '#00ff88',
            weight: 2,
            opacity: 0.8,
            dashArray: '5, 10'
        }).addTo(state.map);
        
        state.mapMarkers.push(line);
    }
}

// =============================================================================
// LOGS
// =============================================================================

function addLog(message, type = 'system') {
    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
    const logEntry = { timestamp, message, type };
    state.logs.push(logEntry);
    
    // Keep only last 500 logs
    if (state.logs.length > 500) {
        state.logs = state.logs.slice(-500);
    }
    
    const logsContent = document.getElementById('logs-content');
    const logElement = document.createElement('div');
    logElement.className = `log-entry ${type}`;
    logElement.innerHTML = `<span class="log-time">[${timestamp}]</span><span class="log-message">${escapeHtml(message)}</span>`;
    logsContent.appendChild(logElement);
    logsContent.scrollTop = logsContent.scrollHeight;
}

function clearLogs() {
    state.logs = [];
    document.getElementById('logs-content').innerHTML = 
        '<div class="log-entry system"><span class="log-time">[--:--:--]</span><span class="log-message">Logs cleared</span></div>';
}

function exportLogs() {
    const logText = state.logs.map(l => `[${l.timestamp}] [${l.type}] ${l.message}`).join('\n');
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentagon-logs-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Logs exported', 'success');
}

// =============================================================================
// MODAL
// =============================================================================

function showTaskDetails(taskId) {
    const task = state.tasks[taskId];
    if (!task) return;
    
    const modal = document.getElementById('task-modal');
    const modalBody = document.getElementById('task-modal-body');
    
    modalBody.innerHTML = `
        <div style="margin-bottom: 20px;">
            <h4 style="color: var(--text-bright); margin-bottom: 8px;">${getTaskIcon(task.type)} ${getTaskTypeName(task.type)}</h4>
            <span class="task-status ${task.status}">${task.status}</span>
        </div>
        
        <div class="form-group">
            <label>Task ID</label>
            <code style="display: block; padding: 8px; background: var(--background-input); border-radius: 4px;">${task.id}</code>
        </div>
        
        <div class="form-group">
            <label>Target</label>
            <div style="padding: 8px; background: var(--background-input); border-radius: 4px;">${escapeHtml(task.target)}</div>
        </div>
        
        <div class="form-group">
            <label>Progress</label>
            <div class="progress-bar" style="height: 12px;">
                <div class="progress-fill" style="width: ${task.progress}%"></div>
            </div>
            <div style="text-align: right; margin-top: 4px; color: var(--text-secondary);">${task.progress}%</div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
            <div class="form-group">
                <label>Started</label>
                <div style="padding: 8px; background: var(--background-input); border-radius: 4px;">
                    ${formatTime(task.start_time)}
                </div>
            </div>
            <div class="form-group">
                <label>Ended</label>
                <div style="padding: 8px; background: var(--background-input); border-radius: 4px;">
                    ${task.end_time ? formatTime(task.end_time) : 'In progress...'}
                </div>
            </div>
        </div>
        
        <div class="form-group">
            <label>Metrics</label>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;">
                <div style="padding: 12px; background: var(--background-input); border-radius: 4px; text-align: center;">
                    <div style="font-size: 20px; font-weight: bold; color: var(--primary-color);">${task.hosts_found || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Hosts Found</div>
                </div>
                <div style="padding: 12px; background: var(--background-input); border-radius: 4px; text-align: center;">
                    <div style="font-size: 20px; font-weight: bold; color: var(--primary-color);">${task.ports_scanned || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Ports</div>
                </div>
                <div style="padding: 12px; background: var(--background-input); border-radius: 4px; text-align: center;">
                    <div style="font-size: 20px; font-weight: bold; color: var(--primary-color);">${task.packets_captured || 0}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">Packets</div>
                </div>
            </div>
        </div>
        
        <div class="form-group">
            <label>Recent Logs</label>
            <div style="max-height: 200px; overflow-y: auto; background: var(--background-input); border-radius: 4px; padding: 12px; font-family: monospace; font-size: 12px;">
                ${task.logs.length > 0 
                    ? task.logs.slice(-10).map(l => 
                        `<div style="margin-bottom: 4px;"><span style="color: var(--text-secondary);">[${formatTime(l.timestamp)}]</span> ${escapeHtml(l.message)}</div>`
                      ).join('')
                    : '<div style="color: var(--text-secondary);">No logs yet</div>'
                }
            </div>
        </div>
    `;
    
    modal.classList.add('active');
}

function closeModal() {
    document.getElementById('task-modal').classList.remove('active');
}

// Close modal on outside click
document.addEventListener('click', (e) => {
    const modal = document.getElementById('task-modal');
    if (e.target === modal) {
        closeModal();
    }
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }
});

// =============================================================================
// TOAST NOTIFICATIONS
// =============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function getTaskIcon(type) {
    const icons = {
        nmap: '🌐',
        traffic_capture: '📊',
        arp_spoof: '🎭'
    };
    return icons[type] || '📋';
}

function getTaskTypeName(type) {
    const names = {
        nmap: 'Network Scan',
        traffic_capture: 'Traffic Capture',
        arp_spoof: 'ARP Spoofing'
    };
    return names[type] || type;
}

function formatTime(isoString) {
    if (!isoString) return '--:--:--';
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
