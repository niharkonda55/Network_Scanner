let socket = io();
let pcapPackets = [];
let pcapAlerts = [];
let pcapDevices = {};

function renderPcapPacketTable() {
    const tbody = document.getElementById('pcap-packet-table-body');
    tbody.innerHTML = '';
    pcapPackets.slice(-100).reverse().forEach(pkt => {
        const row = `<tr>
            <td class="px-2 py-1">${pkt.timestamp}</td>
            <td class="px-2 py-1">${pkt.src_ip}</td>
            <td class="px-2 py-1">${pkt.dst_ip}</td>
            <td class="px-2 py-1">${pkt.protocol}</td>
            <td class="px-2 py-1">${pkt.src_port}</td>
            <td class="px-2 py-1">${pkt.dst_port}</td>
            <td class="px-2 py-1">${pkt.length}</td>
        </tr>`;
        tbody.insertAdjacentHTML('beforeend', row);
    });
}

function renderPcapPhishingTable() {
    const tbody = document.getElementById('pcap-phishing-table-body');
    tbody.innerHTML = '';
    pcapAlerts.slice(-100).reverse().forEach(alert => {
        const badgeColor = alert.risk === 'High' ? 'bg-red-100 text-red-700' : alert.risk === 'Medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-green-100 text-green-700';
        const row = `<tr>
            <td class="px-2 py-1">${alert.timestamp}</td>
            <td class="px-2 py-1">${alert.src_ip}</td>
            <td class="px-2 py-1">${alert.dst_ip}</td>
            <td class="px-2 py-1">${alert.protocol}</td>
            <td class="px-2 py-1">${alert.url}</td>
            <td class="px-2 py-1"><span class="${badgeColor} px-2 py-1 rounded">${alert.risk}</span></td>
            <td class="px-2 py-1">${alert.score}</td>
        </tr>`;
        tbody.insertAdjacentHTML('beforeend', row);
    });
}

function renderPcapDeviceTable() {
    const tbody = document.getElementById('pcap-device-table-body');
    tbody.innerHTML = '';
    Object.values(pcapDevices).sort((a, b) => b.packets - a.packets).forEach(device => {
        const row = `<tr>
            <td class="px-2 py-1">${device.ip}</td>
            <td class="px-2 py-1">${device.mac}</td>
            <td class="px-2 py-1">${device.vendor}</td>
            <td class="px-2 py-1">${device.first_seen}</td>
            <td class="px-2 py-1">${device.last_seen}</td>
            <td class="px-2 py-1">${device.packets}</td>
        </tr>`;
        tbody.insertAdjacentHTML('beforeend', row);
    });
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('pcap-upload-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const fileInput = document.getElementById('pcap-file');
        const status = document.getElementById('pcap-status');
        if (!fileInput.files.length) return;
        const formData = new FormData();
        formData.append('pcap', fileInput.files[0]);
        status.textContent = 'Uploading and analyzing...';
        pcapPackets = [];
        pcapAlerts = [];
        pcapDevices = {};
        renderPcapPacketTable();
        renderPcapPhishingTable();
        renderPcapDeviceTable();
        fetch('/upload_pcap', {
            method: 'POST',
            body: formData
        }).then(resp => resp.json()).then(data => {
            if (data.success) {
                status.textContent = 'Analysis started. Results will appear below.';
            } else {
                status.textContent = 'Error: ' + (data.error || 'Unknown error');
            }
        }).catch(() => {
            status.textContent = 'Upload failed.';
        });
    });

    socket.on('pcap_packet', pkt => {
        pcapPackets.push(pkt);
        renderPcapPacketTable();
    });
    socket.on('pcap_phishing_alert', alert => {
        pcapAlerts.push(alert);
        renderPcapPhishingTable();
    });
    socket.on('pcap_device_update', device => {
        pcapDevices[device.ip + '-' + device.mac] = device;
        renderPcapDeviceTable();
    });
    socket.on('pcap_analysis_done', () => {
        document.getElementById('pcap-status').textContent = 'Analysis complete!';
    });
}); 