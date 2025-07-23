// static/js/phishing_logs.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("Phishing Logs page loaded.");

    const phishingLogsTableBody = document.getElementById('phishing-logs-table-body');
    const exportLogsBtn = document.getElementById('export-logs-btn');

    // Function to fetch and display phishing logs
    async function fetchPhishingLogs() {
        try {
            // TODO: Implement backend API endpoint to fetch phishing logs from your database
            const response = await fetch('/api/phishing_logs');
            const logs = await response.json();

            phishingLogsTableBody.innerHTML = ''; // Clear existing rows
            if (logs.length > 0) {
                logs.forEach(log => {
                    const row = document.createElement('tr');
                    const riskColorClass = log.risk_level === 'High' ? 'bg-red-100 text-red-800' :
                        log.risk_level === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800';
                    row.innerHTML = `
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.timestamp}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.source_ip}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.dest_ip}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.url_domain}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.detection_method}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${riskColorClass}">${log.risk_score}</span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${log.details || 'N/A'}</td>
                    `;
                    phishingLogsTableBody.appendChild(row);
                });
            } else {
                phishingLogsTableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-gray-500">No phishing attempts logged yet.</td></tr>';
            }
        } catch (error) {
            console.error('Error fetching phishing logs:', error);
            phishingLogsTableBody.innerHTML = '<tr><td colspan="7" class="px-6 py-4 text-center text-red-500">Error loading logs.</td></tr>';
        }
    }

    // TODO: Implement export functionality
    exportLogsBtn.addEventListener('click', async () => {
        try {
            // This will trigger a download of the CSV/JSON data
            window.location.href = '/api/export_phishing_logs?format=csv'; // Or format=json
        } catch (error) {
            console.error('Error exporting logs:', error);
            alert('Failed to export logs. Please try again.');
        }
    });

    // Initial load of logs
    fetchPhishingLogs();
});
