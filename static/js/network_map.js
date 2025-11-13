// static/js/network_map.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("Network map script loaded.");

    const container = document.getElementById('network-map');
    let network = null;

    // Function to initialize and render the network map
    function drawNetworkMap(devices) {
        // Create a central node for the network
        const nodes = [{ id: 'center', label: 'Network', shape: 'dot', color: '#4299e1' }];
        const edges = [];

        // Create a node for each discovered device
        devices.forEach(device => {
            nodes.push({
                id: device.mac,
                label: `${device.ip}\n${device.vendor}`,
                shape: 'box',
                color: '#63b3ed'
            });
            edges.push({
                from: 'center',
                to: device.mac
            });
        });

        const data = {
            nodes: new vis.DataSet(nodes),
            edges: new vis.DataSet(edges),
        };

        const options = {
            layout: {
                hierarchical: false
            },
            edges: {
                color: "#000000"
            }
        };

        network = new vis.Network(container, data, options);
    }

    // Function to fetch device data from the API
    async function fetchDevices() {
        try {
            const response = await fetch('/api/devices_data');
            const devices = await response.json();
            drawNetworkMap(devices);
        } catch (error) {
            console.error('Error fetching devices for network map:', error);
        }
    }

    // Initial fetch of devices
    fetchDevices();
});
