const ws = new WebSocket(`ws://${location.host}/ws`);
let alerts = [];

const severityColors = {
    "Critical": "var(--critical)",
    "High": "var(--high)",
    "Medium": "var(--medium)",
    "Low": "var(--low)"
};

ws.onmessage = function(event) {
    const alert = JSON.parse(event.data);
    alerts.unshift(alert);
    if (alerts.length > 100) alerts.pop();
    renderAlerts();
    updateStats();
};

function renderAlerts() {
    const tbody = document.getElementById("alerts-body");
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${a.time}</td>
            <td><span class="severity ${a.severity}">${a.severity}</span></td>
            <td>${a.ip}</td>
            <td>${a.port} → ${a.local_port}</td>
            <td>${a.threat_type || "Unknown"}</td>
            <td>${a.description || "-"}</td>
            <td><button onclick="blockIP('${a.ip}')">Block</button></td>
        </tr>
    `).join("");
}

function updateStats() {
    document.getElementById("total-alerts").textContent = alerts.length;
    document.getElementById("critical-count").textContent = alerts.filter(a => a.severity === "Critical").length;
    document.getElementById("high-count").textContent = alerts.filter(a => a.severity === "High").length;
    document.getElementById("medium-count").textContent = alerts.filter(a => a.severity === "Medium").length;
}

document.getElementById("test-alert").onclick = () => {
    const test = {
        id: Date.now(),
        time: new Date().toLocaleTimeString(),
        ip: "203.0.113." + Math.floor(Math.random()*255),
        port: 80,
        local_port: 8000,
        severity: ["Low","Medium","High","Critical"][Math.floor(Math.random()*4)],
        threat_type: "Test",
        description: "This is a test alert"
    };
    alerts.unshift(test);
    renderAlerts();
    updateStats();
};

document.getElementById("clear-alerts").onclick = () => {
    alerts = [];
    renderAlerts();
    updateStats();
};

function blockIP(ip) {
    alert(`IP ${ip} blocked via iptables`);
    // In real version: fetch("/api/block/" + ip)
}

function discoverNetwork() {
    alert("Network discovery started...");
    // fetch("/api/discover-network", {method: "POST"})
}

updateStats();
