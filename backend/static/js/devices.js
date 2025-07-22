let socket = io();
let devices = {};

function renderDeviceTable() {
    const tbody = document.getElementById('device-table-body');
    tbody.innerHTML = '';
    Object.values(devices).sort((a, b) => b.packets - a.packets).forEach(device => {
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
    socket.on('device_update', device => {
        devices[device.ip + '-' + device.mac] = device;
        renderDeviceTable();
    });
}); 