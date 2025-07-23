// static/js/settings.js

document.addEventListener('DOMContentLoaded', function () {
    console.log("Settings page loaded.");

    const loggingToggle = document.getElementById('logging-toggle');
    const phishTankApiKeyInput = document.getElementById('phishtank-api-key');
    const googleSafeBrowsingApiKeyInput = document.getElementById('google-safe-browsing-api-key');
    const saveSettingsBtn = document.getElementById('save-settings-btn');

    // Function to load current settings (e.g., from backend or localStorage)
    async function loadSettings() {
        try {
            // TODO: Implement backend API endpoint to fetch settings
            const response = await fetch('/api/settings');
            const settings = await response.json();

            loggingToggle.checked = settings.enable_logging || false;
            phishTankApiKeyInput.value = settings.phishtank_api_key || '';
            googleSafeBrowsingApiKeyInput.value = settings.google_safe_browsing_api_key || '';
        } catch (error) {
            console.error('Error loading settings:', error);
            // Optionally, initialize with default values if loading fails
            loggingToggle.checked = false;
        }
    }

    // Function to save settings
    saveSettingsBtn.addEventListener('click', async () => {
        const settings = {
            enable_logging: loggingToggle.checked,
            phishtank_api_key: phishTankApiKeyInput.value.trim(),
            google_safe_browsing_api_key: googleSafeBrowsingApiKeyInput.value.trim()
        };

        try {
            // TODO: Implement backend API endpoint to save settings
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                alert('Settings saved successfully!'); // Use a custom modal in production
            } else {
                alert('Failed to save settings.'); // Use a custom modal in production
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            alert('An error occurred while saving settings.'); // Use a custom modal in production
        }
    });

    // Initial load of settings
    loadSettings();
});
