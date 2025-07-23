// static/js/live_monitor.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("Live Monitor page loaded.");

    const interfaceSelect = document.getElementById('interface-select');
    const startCaptureBtn = document.getElementById('start-capture-btn');
    const stopCaptureBtn = document.getElementById('stop-capture-btn');
    const livePacketTableBody = document.getElementById('live-packet-table-body');

    let socket; // Variable to hold the SocketIO connection

    // Function to fetch and populate network interfaces
    async function loadNetworkInterfaces() {
        try {
            const response = await fetch('/api/interfaces');
            const interfaces = await response.json();

            interfaceSelect.innerHTML = ''; // Clear loading message
            if (interfaces.length > 0) {
                interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    option.textContent = iface.description;
                    interfaceSelect.appendChild(option);
                });
                startCaptureBtn.disabled = false; // Enable start button if interfaces are found
            } else {
                const option = document.createElement('option');
                option.value = "";
                option.textContent = "No interfaces found.";
                interfaceSelect.appendChild(option);
                startCaptureBtn.disabled = true;
            }
        } catch (error) {
            console.error('Error fetching network interfaces:', error);
            interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
            startCaptureBtn.disabled = true;
        }
    }

    // Initialize SocketIO connection
    function connectSocket() {
        // Ensure the Socket.IO client library is loaded in base.html
        // For Flask-SocketIO, the default namespace is usually '/'
        socket = io(); // Connects to the current host/port

        socket.on('connect', () => {
            console.log('Socket.IO connected!');
            // You can emit a 'ready' event or similar here if needed
        });

        socket.on('disconnect', () => {
            console.log('Socket.IO disconnected!');
            // Handle UI changes on disconnect if capture was running
            startCaptureBtn.disabled = false;
            stopCaptureBtn.disabled = true;
            livePacketTableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">Capture stopped or disconnected.</td></tr>';
        });

        socket.on('new_packet', (packet) => {
            // Add new packet to the top of the table
            const row = document.createElement('tr');
            const riskColorClass = packet.risk_level === 'High' ? 'bg-red-100 text-red-800' :
                packet.risk_level === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-green-100 text-green-800';
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.timestamp}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.source_ip}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.dest_ip}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.protocol}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.url}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.size} bytes</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${riskColorClass}">${packet.risk_level}</span>
                </td>
            `;
            // Prepend the new row to the table body
            if (livePacketTableBody.firstChild && livePacketTableBody.firstChild.tagName === 'TR' && livePacketTableBody.firstChild.getAttribute('colspan') === '7') {
                // If the "No packets captured yet" row exists, remove it
                livePacketTableBody.innerHTML = '';
            }
            livePacketTableBody.prepend(row);

            // Keep only the last N rows to prevent table from growing too large
            const maxRows = 50; // Display max 50 packets
            while (livePacketTableBody.children.length > maxRows) {
                livePacketTableBody.removeChild(livePacketTableBody.lastChild);
            }
        });

        socket.on('capture_status', (data) => {
            console.log('Capture Status:', data.message);
            // You can display this status in the UI if needed
        });
    }

    // --- Event Listeners for Buttons ---
    startCaptureBtn.addEventListener('click', () => {
        const selectedInterface = interfaceSelect.value;
        if (selectedInterface && socket) {
            socket.emit('start_capture', { interface: selectedInterface });
            startCaptureBtn.disabled = true;
            stopCaptureBtn.disabled = false;
            livePacketTableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">Starting capture...</td></tr>';
        } else {
            console.warn("No interface selected or Socket.IO not connected.");
        }
    });

    stopCaptureBtn.addEventListener('click', () => {
        if (socket) {
            socket.emit('stop_capture');
            startCaptureBtn.disabled = false;
            stopCaptureBtn.disabled = true;
            livePacketTableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">Stopping capture...</td></tr>';
        }
    });

    // Initial load of interfaces and connect to Socket.IO
    loadNetworkInterfaces();
    connectSocket();
});
