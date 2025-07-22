let socket = io();
let capturing = false;
let packets = [];
let uniqueIPs = new Set();
let selectedIP = '';

// Chart.js setup
let trafficChart, protocolChart;
let trafficData = [];
let protocolCounts = {};
const TRAFFIC_WINDOW = 60; // seconds

const COMMON_PORTS = {
    80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 23: 'TELNET', 3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP', 8080: 'HTTP-ALT', 137: 'NetBIOS', 445: 'SMB', 139: 'NetBIOS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 161: 'SNMP', 389: 'LDAP', 636: 'LDAPS', 5060: 'SIP', 5061: 'SIPS', 1812: 'RADIUS', 1813: 'RADIUS', 69: 'TFTP', 514: 'Syslog', 2049: 'NFS', 1900: 'SSDP', 5353: 'mDNS', 8000: 'HTTP-ALT', 8888: 'HTTP-ALT', 25: 'SMTP', 587: 'SMTP', 465: 'SMTPS', 995: 'POP3S', 993: 'IMAPS', 5900: 'VNC', 6000: 'X11', 6667: 'IRC', 12345: 'NetBus', 31337: 'Back Orifice'
};

function updateIPDropdown() {
    const ipDropdown = document.getElementById('ip-filter');
    const ips = Array.from(uniqueIPs).sort();
    ipDropdown.innerHTML = '<option value="">All IPs</option>' + ips.map(ip => `<option value="${ip}">${ip}</option>`).join('');
}

function renderTable() {
    const tbody = document.getElementById('packet-table-body');
    tbody.innerHTML = '';
    let filtered = selectedIP ? packets.filter(pkt => pkt.src_ip === selectedIP || pkt.dst_ip === selectedIP) : packets;
    filtered.slice(-100).reverse().forEach(pkt => {
        const row = `<tr>
            <td class="px-2 py-1">${pkt.timestamp}</td>
            <td class="px-2 py-1">${pkt.src_ip}</td>
            <td class="px-2 py-1">${pkt.dst_ip}</td>
            <td class="px-2 py-1">${pkt.protocol}</td>
            <td class="px-2 py-1">${pkt.src_port}</td>
            <td class="px-2 py-1">${pkt.dst_port}</td>
            <td class="px-2 py-1">${pkt.url}</td>
            <td class="px-2 py-1">${pkt.length}</td>
        </tr>`;
        tbody.insertAdjacentHTML('beforeend', row);
    });
}

function renderServiceTable() {
    const tbody = document.getElementById('service-table-body');
    const label = document.getElementById('service-ip-label');
    tbody.innerHTML = '';
    label.textContent = selectedIP ? `for ${selectedIP}` : '';
    if (!selectedIP) return;
    // Compute stats
    let stats = {};
    packets.forEach(pkt => {
        if (pkt.src_ip === selectedIP) {
            let key = `out-${pkt.dst_port}-${pkt.protocol}`;
            if (!stats[key]) stats[key] = {direction: 'Outgoing', port: pkt.dst_port, protocol: pkt.protocol, service: COMMON_PORTS[pkt.dst_port] || '', packets: 0, bytes: 0};
            stats[key].packets++;
            stats[key].bytes += parseInt(pkt.length) || 0;
        }
        if (pkt.dst_ip === selectedIP) {
            let key = `in-${pkt.src_port}-${pkt.protocol}`;
            if (!stats[key]) stats[key] = {direction: 'Incoming', port: pkt.src_port, protocol: pkt.protocol, service: COMMON_PORTS[pkt.src_port] || '', packets: 0, bytes: 0};
            stats[key].packets++;
            stats[key].bytes += parseInt(pkt.length) || 0;
        }
    });
    Object.values(stats).sort((a, b) => b.bytes - a.bytes).forEach(row => {
        tbody.insertAdjacentHTML('beforeend', `<tr>
            <td class="px-2 py-1">${row.direction}</td>
            <td class="px-2 py-1">${row.port}</td>
            <td class="px-2 py-1">${row.protocol}</td>
            <td class="px-2 py-1">${row.service}</td>
            <td class="px-2 py-1">${row.packets}</td>
            <td class="px-2 py-1">${row.bytes}</td>
        </tr>`);
    });
}

function updateCharts() {
    // Traffic Volume (Packets/sec)
    let now = Date.now();
    let filtered = selectedIP ? packets.filter(pkt => pkt.src_ip === selectedIP || pkt.dst_ip === selectedIP) : packets;
    let times = Array(TRAFFIC_WINDOW).fill(0);
    let labels = [];
    for (let i = TRAFFIC_WINDOW - 1; i >= 0; i--) {
        let t = new Date(now - i * 1000);
        labels.push(t.toLocaleTimeString().slice(3, 8));
    }
    filtered.forEach(pkt => {
        let pktTime = new Date();
        let pktIdx = TRAFFIC_WINDOW - 1;
        if (pkt.timestamp) {
            // Try to parse timestamp as HH:MM:SS
            let parts = pkt.timestamp.split(":");
            if (parts.length === 3) {
                let pktDate = new Date();
                pktDate.setHours(parseInt(parts[0]), parseInt(parts[1]), parseInt(parts[2]), 0);
                pktIdx = Math.floor((now - pktDate.getTime()) / 1000);
                pktIdx = TRAFFIC_WINDOW - 1 - pktIdx;
            }
        }
        if (pktIdx >= 0 && pktIdx < TRAFFIC_WINDOW) times[pktIdx]++;
    });
    if (trafficChart) {
        trafficChart.data.labels = labels;
        trafficChart.data.datasets[0].data = times;
        trafficChart.update('none');
    }
    // Protocol Distribution
    protocolCounts = {};
    filtered.forEach(pkt => {
        let proto = pkt.protocol || 'Other';
        protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
    });
    if (protocolChart) {
        protocolChart.data.labels = Object.keys(protocolCounts);
        protocolChart.data.datasets[0].data = Object.values(protocolCounts);
        protocolChart.update('none');
    }
    renderServiceTable();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('capture-btn').addEventListener('click', () => {
        if (!capturing) {
            socket.emit('start_capture', {interface: 'Wi-Fi'}); // TODO: make interface selectable
            capturing = true;
            document.getElementById('capture-btn').textContent = 'Stop Capture';
        } else {
            socket.emit('stop_capture');
            capturing = false;
            document.getElementById('capture-btn').textContent = 'Start Capture';
        }
    });

    document.getElementById('ip-filter').addEventListener('change', (e) => {
        selectedIP = e.target.value;
        renderTable();
        updateCharts();
        renderServiceTable();
    });

    socket.on('packet', pkt => {
        packets.push(pkt);
        if (pkt.src_ip) uniqueIPs.add(pkt.src_ip);
        if (pkt.dst_ip) uniqueIPs.add(pkt.dst_ip);
        updateIPDropdown();
        renderTable();
        updateCharts();
        renderServiceTable();
    });

    // Initialize charts
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: Array(TRAFFIC_WINDOW).fill(''),
            datasets: [{
                label: 'Packets/sec',
                data: Array(TRAFFIC_WINDOW).fill(0),
                borderColor: 'rgb(59, 130, 246)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            animation: false,
            scales: { y: { beginAtZero: true } }
        }
    });
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                label: 'Protocols',
                data: [],
                backgroundColor: [
                    'rgba(59, 130, 246, 0.7)',
                    'rgba(16, 185, 129, 0.7)',
                    'rgba(234, 179, 8, 0.7)',
                    'rgba(239, 68, 68, 0.7)',
                    'rgba(168, 85, 247, 0.7)',
                    'rgba(71, 85, 105, 0.7)'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } },
            animation: false
        }
    });
}); 