from hidden_file_detector import HiddenFileDetector

class FileAnalyzer:
    def __init__(self):
        self.forensic_extractor = None
        self.hidden_detector = None
        self.suspicious_patterns = {
            '.enc': 'Possibly encrypted file',
            '.hid': 'Hidden file',
            'secret': 'Marked as secret',
            'password': 'Password-related file',
            'encrypt': 'Possibly encrypted',
            'hide': 'Hidden content'
        }

    def set_forensic_extractor(self, extractor):
        self.forensic_extractor = extractor
        self.hidden_detector = HiddenFileDetector(extractor.run_adb_command)

    def analyze_files(self, data):
        print("\nAnalyzing files and scanning for hidden content...")
        
        file_analysis = {
            'downloads': self._analyze_downloads(data['files']['downloads']),
            'hidden_files': self._analyze_hidden_files(data['hidden_files']),
            'summary': {},
            'suspicious_patterns': self._find_suspicious_patterns(data)
        }

        print("\nScanning Download directory...")
        specific_dirs = [
            '/sdcard/Download',
            '/storage/emulated/0/Download'
        ]
        
        for directory in specific_dirs:
            print(f"\nScanning directory: {directory}")
            self.hidden_detector.scan_directory(directory)
            
        findings = self.hidden_detector.get_findings_summary()
        print("\nFile Analysis Results:")
        print(f"Found {len(findings['findings']['extension_mismatches'])} mismatches")
        for mismatch in findings['findings']['extension_mismatches']:
            print(f"Mismatch: {mismatch['path']}")
            print(f"Declared as: {mismatch['declared_ext']}")
            print(f"Actually is: {mismatch['actual_ext']}")
            
        file_analysis['hidden_detection'] = findings
        file_analysis['summary'] = {
            'total_downloads': len(data['files']['downloads']),
            'total_hidden': len(data['hidden_files']),
            'suspicious_count': len(file_analysis['suspicious_patterns']),
            'extension_mismatches': len(findings['findings']['extension_mismatches'])
        }
        
        return file_analysis

    def _analyze_downloads(self, downloads):
        return {'count': len(downloads)}

    def _analyze_hidden_files(self, hidden_files):
        return {'count': len(hidden_files)}

    def _find_suspicious_patterns(self, data):
        suspicious = []
        for file_info in data['files'].get('downloads', []):
            filename = file_info.get('name', '').lower()
            for pattern, reason in self.suspicious_patterns.items():
                if pattern in filename:
                    suspicious.append({
                        'file': filename,
                        'reason': reason
                    })
        return suspicious

    def _assess_risk_level(self, path, details):
        """Assess risk level of a file"""
        path_lower = path.lower()
        
        # High risk patterns
        high_risk = ['encrypt', '.enc', 'hideu', 'secret', 'password']
        if any(pattern in path_lower for pattern in high_risk):
            return 'high'
            
        # Medium risk patterns
        medium_risk = ['.nomedia', 'hidden', '.hid', 'dont_delete']
        if any(pattern in path_lower for pattern in medium_risk):
            return 'medium'
            
        # Check file permissions if available
        if details and ('x' in details or 'w' in details):
            return 'medium'
            
        return 'low'

    def get_scanning_status(self):
        """Get current scanning status and statistics"""
        if not self.hidden_detector:
            return {
                'total_files_scanned': 0,
                'suspicious_files_found': 0,
                'hidden_directories_found': 0
            }
            
        return {
            'total_files_scanned': len(self.hidden_detector.findings['dot_files']) + 
                                 len(self.hidden_detector.findings['nomedia_files']) + 
                                 len(self.hidden_detector.findings['extension_mismatches']),
            'suspicious_files_found': len(self.hidden_detector.findings['extension_mismatches']),
            'hidden_directories_found': len(self.hidden_detector.findings['nomedia_files'])
        }