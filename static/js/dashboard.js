// static/js/dashboard.js
let threatChart; // global chart reference

document.addEventListener('DOMContentLoaded', function () {
    // Get the context of the canvas element we want to draw the chart on
    const ctx = document.getElementById('threatChart');

    // Check if the canvas element exists before trying to create a chart
    if (ctx) {
        threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [], // start empty, will be filled dynamically
                datasets: [{
                    label: 'Phishing Attempts',
                    data: [],
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    title: { display: false }
                },
                scales: {
                    x: { grid: { display: false } },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(200, 200, 200, 0.2)' }
                    }
                }
            }
        });
    } else {
        console.error("Canvas element with ID 'threatChart' not found.");
    }

    function fetchDashboardData() {
        fetch('/api/dashboard_data')
            .then(response => response.json())
            .then(data => {
                // Update stats
                document.getElementById('packetsCaptured').innerText = data.packets_captured;
                document.getElementById('phishingAttempts').innerText = data.phishing_attempts;
                document.getElementById('devicesFound').innerText = data.devices_found;

                // Update chart
                if (threatChart) {
                    threatChart.data.labels = data.threat_summary.labels;
                    threatChart.data.datasets[0].data = data.threat_summary.data;
                    threatChart.update();
                }

                // Update recent events
                const tbody = document.getElementById('eventsBody');
                tbody.innerHTML = '';
                data.recent_events.forEach(event => {
                    let badgeClass = 'bg-green-100 text-green-800';
                    if (event.risk_level === 'High') badgeClass = 'bg-red-100 text-red-800';
                    else if (event.risk_level === 'Medium') badgeClass = 'bg-yellow-100 text-yellow-800';

                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td class="px-6 py-4 text-sm text-gray-900">${event.time}</td>
                        <td class="px-6 py-4 text-sm text-gray-900">${event.source_ip}</td>
                        <td class="px-6 py-4 text-sm text-gray-900">${event.dest_ip}</td>
                        <td class="px-6 py-4 text-sm text-gray-900">${event.protocol}</td>
                        <td class="px-6 py-4 text-sm text-gray-900">${event.url}</td>
                        <td class="px-6 py-4 text-sm">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${badgeClass}">
                                ${event.risk_level}
                            </span>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            })
            .catch(error => console.error('Error fetching dashboard data:', error));
    }

    // Call initially and repeat every 5 seconds
    fetchDashboardData();
    setInterval(fetchDashboardData, 5000);
});
