let socket = io();
let alerts = [];

function renderPhishingTable() {
    const tbody = document.getElementById('phishing-table-body');
    tbody.innerHTML = '';
    alerts.slice(-100).reverse().forEach(alert => {
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

document.addEventListener('DOMContentLoaded', () => {
    socket.on('phishing_alert', alert => {
        alerts.push(alert);
        renderPhishingTable();
    });
}); 