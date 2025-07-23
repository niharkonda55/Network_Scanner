// static/js/pcap_analysis.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("PCAP Analysis page loaded.");

    const pcapDropArea = document.getElementById('pcap-drop-area');
    const pcapFileInput = document.getElementById('pcap-file-input');
    const pcapFileName = document.getElementById('pcap-file-name');
    const analyzePcapBtn = document.getElementById('analyze-pcap-btn');
    const pcapAnalysisStatus = document.getElementById('pcap-analysis-status');
    const pcapAnalysisResults = document.getElementById('pcap-analysis-results');
    const pcapResultsTableBody = document.getElementById('pcap-results-table-body');

    let uploadedFile = null;

    // Handle drag and drop
    pcapDropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        pcapDropArea.classList.add('border-blue-500');
    });

    pcapDropArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        pcapDropArea.classList.remove('border-blue-500');
    });

    pcapDropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        pcapDropArea.classList.remove('border-blue-500');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadedFile = files[0];
            pcapFileName.textContent = `Selected file: ${uploadedFile.name}`;
            analyzePcapBtn.disabled = false;
        }
    });

    // Handle file input change
    pcapFileInput.addEventListener('change', (e) => {
        const files = e.target.files;
        if (files.length > 0) {
            uploadedFile = files[0];
            pcapFileName.textContent = `Selected file: ${uploadedFile.name}`;
            analyzePcapBtn.disabled = false;
        }
    });

    // Handle analyze button click
    analyzePcapBtn.addEventListener('click', async () => {
        if (!uploadedFile) {
            pcapAnalysisStatus.textContent = "Please select a PCAP file first.";
            return;
        }

        pcapAnalysisStatus.textContent = "Analyzing file... This may take a moment.";
        analyzePcapBtn.disabled = true;
        pcapAnalysisResults.classList.add('hidden'); // Hide previous results

        const formData = new FormData();
        formData.append('pcap_file', uploadedFile);

        try {
            // TODO: Implement backend API endpoint for PCAP upload and analysis
            const response = await fetch('/api/analyze_pcap', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            pcapAnalysisStatus.textContent = `Analysis complete. Found ${result.packets_analyzed} packets, ${result.phishing_detected} phishing attempts.`;
            pcapAnalysisResults.classList.remove('hidden');

            // Populate results table
            pcapResultsTableBody.innerHTML = '';
            if (result.analyzed_packets && result.analyzed_packets.length > 0) {
                result.analyzed_packets.forEach(packet => {
                    const row = document.createElement('tr');
                    const riskColorClass = packet.risk_level === 'High' ? 'bg-red-100 text-red-800' :
                        packet.risk_level === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800';
                    row.innerHTML = `
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.time}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.source_ip}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.dest_ip}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.protocol}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.url || 'N/A'}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${riskColorClass}">${packet.risk_level}</span>
                        </td>
                    `;
                    pcapResultsTableBody.appendChild(row);
                });
            } else {
                pcapResultsTableBody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">No relevant packets found in analysis.</td></tr>';
            }

        } catch (error) {
            console.error('Error analyzing PCAP file:', error);
            pcapAnalysisStatus.textContent = `Error analyzing file: ${error.message}`;
        } finally {
            analyzePcapBtn.disabled = false;
        }
    });
});
