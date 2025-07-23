// static/js/devices.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("Devices on Network page loaded.");

    const devicesTableBody = document.getElementById('devices-table-body');
    const scanDevicesBtn = document.getElementById('scan-devices-btn');
    const interfaceSelect = document.getElementById('interface-select-devices');
    const ipRangeInput = document.getElementById('ip-range-input');
    const scanStatusDiv = document.getElementById('scan-status');

    let socket; // Socket.IO instance

    // Function to fetch and populate network interfaces for the scan
    async function loadNetworkInterfacesForScan() {
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
                scanDevicesBtn.disabled = false; // Enable scan button if interfaces are found
            } else {
                const option = document.createElement('option');
                option.value = "";
                option.textContent = "No interfaces found.";
                interfaceSelect.appendChild(option);
                scanDevicesBtn.disabled = true;
            }
        } catch (error) {
            console.error('Error fetching network interfaces for scan:', error);
            interfaceSelect.innerHTML = '<option value="">Error loading interfaces</option>';
            scanDevicesBtn.disabled = true;
        }
    }

    // Function to fetch and display current discovered devices
    async function fetchDiscoveredDevices() {
        try {
            const response = await fetch('/api/devices_data');
            const devices = await response.json();

            updateDevicesTable(devices);
        } catch (error) {
            console.error('Error fetching discovered devices:', error);
            devicesTableBody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-red-500">Error loading devices.</td></tr>';
        }
    }

    // Function to update the devices table
    function updateDevicesTable(devices) {
        devicesTableBody.innerHTML = ''; // Clear existing rows
        if (devices.length > 0) {
            devices.sort((a, b) => (a.last_seen < b.last_seen) ? 1 : -1); // Sort by last seen (most recent first)
            devices.forEach(device => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${device.ip}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${device.mac}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${device.vendor}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${device.last_seen}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${device.type}</td>
                `;
                devicesTableBody.appendChild(row);
            });
        } else {
            devicesTableBody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">No devices discovered yet. Perform a scan!</td></tr>';
        }
    }

    // Initialize Socket.IO connection for real-time updates (if any)
    function connectSocket() {
        socket = io(); // Connects to the current host/port

        socket.on('connect', () => {
            console.log('Devices Socket.IO connected!');
        });

        socket.on('disconnect', () => {
            console.log('Devices Socket.IO disconnected!');
        });

        socket.on('devices_updated', (devices) => {
            console.log('Received devices_updated event:', devices);
            updateDevicesTable(devices); // Update table when new devices are found
        });
    }

    // Event listener for the "Scan Devices" button
    if (scanDevicesBtn) {
        scanDevicesBtn.addEventListener('click', async () => {
            const selectedInterface = interfaceSelect.value;
            const ipRange = ipRangeInput.value.trim();

            if (!selectedInterface) {
                scanStatusDiv.textContent = "Please select a network interface.";
                return;
            }

            scanStatusDiv.textContent = "Starting ARP scan... This may take a moment.";
            scanDevicesBtn.disabled = true;

            try {
                const response = await fetch('/api/scan_devices', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ interface: selectedInterface, ip_range: ipRange || null })
                });

                const result = await response.json();
                if (response.ok) {
                    scanStatusDiv.textContent = result.message;
                    // Devices will be updated via 'devices_updated' socket event
                } else {
                    scanStatusDiv.textContent = `Error: ${result.message}`;
                }
            } catch (error) {
                console.error('Error initiating ARP scan:', error);
                scanStatusDiv.textContent = `Error initiating scan: ${error.message}`;
            } finally {
                scanDevicesBtn.disabled = false;
            }
        });
    }

    // Initial load of interfaces and devices
    loadNetworkInterfacesForScan();
    fetchDiscoveredDevices();
    connectSocket(); // Connect to Socket.IO for real-time updates
});
