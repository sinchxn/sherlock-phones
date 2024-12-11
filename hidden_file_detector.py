import os
from pathlib import Path

class HiddenFileDetector:
    def __init__(self, adb_executor):
        self.adb_executor = adb_executor
        self.signatures = {
            b'\xFF\xD8\xFF': '.jpg',
            b'\x89\x50\x4E\x47\x0D\x0A': '.png',
            b'%PDF': '.pdf',
            b'PK': '.zip',
            b'GIF87a': '.gif',
            b'GIF89a': '.gif',
            b'ID3': '.mp3',
            b'\x52\x61\x72\x21': '.rar',
            b'\x00\x00\x00\x20\x66\x74\x79\x70': '.mp4'
        }
        
        self.findings = {
            'dot_files': [],
            'nomedia_files': [],
            'extension_mismatches': []
        }

    def scan_directory(self, directory):
        print(f"\nScanning {directory} for hidden files...")
        cmd = f'shell find {directory} -type f 2>/dev/null'
        files_output = self.adb_executor(cmd)
        
        if not files_output:
            print(f"No files found in {directory}")
            return

        for file_path in files_output.split('\n'):
            if not file_path.strip():
                continue
            
            print(f"Checking file: {file_path}")
            self._check_file_signature(file_path)
            self._check_hidden_file(file_path)

    def _check_hidden_file(self, file_path):
        filename = os.path.basename(file_path)
        if filename.startswith('.'):
            file_details = self.adb_executor(f'shell ls -la "{file_path}"')
            self.findings['dot_files'].append({
                'path': file_path,
                'details': file_details
            })
            print(f"Found hidden file: {file_path}")

    def _check_file_signature(self, file_path):
        print(f"Checking signature for: {file_path}")
        try:
            # Get file signature
            cmd = f'shell xxd -p -l 16 "{file_path}"'
            file_start = self.adb_executor(cmd)
            print(f"File start bytes: {file_start}")

            if file_start and len(file_start.strip()) >= 8:
                try:
                    file_start_bytes = bytes.fromhex(file_start.strip())
                    declared_ext = os.path.splitext(file_path)[1].lower()
                    
                    for signature, expected_ext in self.signatures.items():
                        if file_start_bytes.startswith(signature):
                            if declared_ext != expected_ext:
                                print(f"Found mismatch in {file_path}")
                                print(f"Declared: {declared_ext}, Actual: {expected_ext}")
                                self.findings['extension_mismatches'].append({
                                    'path': file_path,
                                    'declared_ext': declared_ext,
                                    'actual_ext': expected_ext
                                })
                            break
                except Exception as e:
                    print(f"Error processing hex data for {file_path}: {e}")
                    
        except Exception as e:
            print(f"Error checking signature for {file_path}: {e}")

    def get_findings_summary(self):
        return {
            'total_dot_files': len(self.findings['dot_files']),
            'total_nomedia': len(self.findings['nomedia_files']),
            'total_mismatches': len(self.findings['extension_mismatches']),
            'findings': self.findings
        }