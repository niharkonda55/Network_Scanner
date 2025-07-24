// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', function () {
    // Get the context of the canvas element we want to draw the chart on
    const ctx = document.getElementById('threatChart');

    // Check if the canvas element exists before trying to create a chart
    if (ctx) {
        new Chart(ctx, {
            type: 'line', // Type of chart (e.g., 'line', 'bar', 'pie')
            data: {
                // Labels for the x-axis (time points)
                labels: ['12:00', '12:05', '12:10', '12:15', '12:20', '12:25'],
                datasets: [{
                    label: 'Phishing Attempts', // Label for the dataset
                    data: [0, 1, 2, 1, 3, 4], // Data points for the chart
                    borderColor: 'rgb(239, 68, 68)', // Red color for the line
                    backgroundColor: 'rgba(239, 68, 68, 0.1)', // Light red fill under the line
                    fill: true, // Fill the area under the line
                    tension: 0.4 // Smooth the line
                }]
            },
            options: {
                responsive: true, // Make the chart responsive to container size
                maintainAspectRatio: false, // Allow height to be controlled by CSS
                plugins: {
                    legend: {
                        display: false // Hide the legend for simplicity
                    },
                    title: {
                        display: false, // Hide the title as we have an H2 above
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false // Hide x-axis grid lines
                        }
                    },
                    y: {
                        beginAtZero: true, // Start y-axis from zero
                        grid: {
                            color: 'rgba(200, 200, 200, 0.2)' // Light grid lines for y-axis
                        }
                    }
                }
            }
        });
    } else {
        console.error("Canvas element with ID 'threatChart' not found.");
    }
    function fetchRecentEvents() {
        fetch('/api/recent_events')
            .then(response => response.json())
            .then(data => {
                const tbody = document.getElementById('eventsBody');
                tbody.innerHTML = ''; // clear previous rows

                data.forEach(event => {
                    const row = document.createElement('tr');

                    row.innerHTML = `
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.time}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.src_ip}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.dst_ip}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.protocol}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${event.url}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm">
                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                            ${event.risk === 'High' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}">
                            ${event.risk}
                        </span>
                    </td>
                `;
                    tbody.appendChild(row);
                });
            })
            .catch(error => console.error('Error fetching events:', error));
    }

    // Call initially and repeat every 5 seconds
    fetchRecentEvents();
    setInterval(fetchRecentEvents, 5000);

});

// You can add more JavaScript functions here for dynamic updates,
// filtering, or other dashboard functionalities.
