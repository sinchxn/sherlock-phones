class NetworkAnalyzer:
    def __init__(self):
        self.security_levels = {
            'open': 'High Risk',
            'wep': 'High Risk',
            'wpa': 'Medium Risk',
            'wpa2': 'Low Risk'
        }
        
    def analyze_networks(self, networks):
        analysis = {
            'total_networks': len(networks),
            'security_breakdown': {
                'open': 0,
                'wep': 0,
                'wpa': 0,
                'wpa2': 0,
                'unknown': 0
            },
            'risky_networks': [],
            'security_summary': '',
            'location_types': {
                'airports': [],
                'universities': [],
                'other': []
            }
        }
        
        for network in networks:
            security = network['security'].lower()
            ssid = network['ssid'].lower()
            
            # Categorize network type
            if 'airport' in ssid:
                analysis['location_types']['airports'].append(network)
            elif any(edu in ssid for edu in ['yale', 'university', 'edu']):
                analysis['location_types']['universities'].append(network)
            else:
                analysis['location_types']['other'].append(network)
            
            # Security analysis
            if 'open' in security:
                analysis['security_breakdown']['open'] += 1
                analysis['risky_networks'].append(network)
            elif 'wep' in security:
                analysis['security_breakdown']['wep'] += 1
                analysis['risky_networks'].append(network)
            elif 'wpa2' in security:
                analysis['security_breakdown']['wpa2'] += 1
            elif 'wpa' in security:
                analysis['security_breakdown']['wpa'] += 1
            else:
                analysis['security_breakdown']['unknown'] += 1
        
        analysis['security_summary'] = self._create_summary(analysis)
        return analysis
    
    def _create_summary(self, analysis):
        risky_count = len(analysis['risky_networks'])
        total = analysis['total_networks']
        
        if total == 0:
            return "No networks found"
            
        if risky_count == 0:
            return "All networks use secure protocols"
        else:
            return f"Found {risky_count} potentially risky networks out of {total}"