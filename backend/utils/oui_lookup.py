OUI_DB = {
    '00:1A:2B': 'Cisco Systems',
    '00:1B:63': 'Apple, Inc.',
    '00:1C:B3': 'Samsung Electronics',
    '00:1D:D8': 'Sony Corporation',
    '00:1E:C2': 'Dell Inc.',
    '00:1F:3B': 'Hewlett Packard',
    '00:21:6A': 'Intel Corporate',
    '00:22:48': 'Hon Hai Precision Ind. Co., Ltd.',
    '00:23:69': 'LG Electronics',
    '00:25:9C': 'AzureWave Technologies',
    # ... (add more as needed or load from file)
}

def lookup_vendor(mac):
    if not mac:
        return ''
    prefix = mac.upper().replace('-', ':')[:8]
    return OUI_DB.get(prefix, 'Unknown') 