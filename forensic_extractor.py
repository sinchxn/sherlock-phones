import subprocess
from datetime import datetime
import json
import os

class ForensicExtractor:
    def __init__(self):
        self.adb_path = "./platform-tools/adb"  # Updated for Mac
        self.check_setup()
        self.data = {
            "device_info": {},
            "communications": {
                "calls": [],
                "messages": []
            },
            "networks": [],
            "files": {
                "photos": [],
                "downloads": [],
                "recent_activity": []
            },
            "hidden_files": []
        }

    def check_setup(self):
        if not os.path.exists(self.adb_path):
            raise Exception("ADB not found. Please ensure platform-tools is in the correct location")
        
        try:
            result = subprocess.run([self.adb_path, 'devices'], 
                                  capture_output=True, 
                                  text=True)
            if "device" not in result.stdout:
                raise Exception("No device connected. Please check USB connection and debugging settings")
            print("Setup successful! Device connected and ready.")
        except Exception as e:
            print(f"Setup failed: {e}")
            raise

    def run_adb_command(self, command):
        try:
            result = subprocess.run([self.adb_path] + command.split(), 
                                  capture_output=True, 
                                  text=True)
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command {command}: {e}")
            return None

    def extract_device_info(self):
        print("\nExtracting device info...")
        user_info = self.run_adb_command("shell dumpsys user")
        
        username = None
        last_login = None
        for line in user_info.split('\n'):
            if 'UserInfo{' in line:
                username = line.split(':')[1].split(':')[0]
            if 'Last logged in:' in line:
                last_login = line.split('Last logged in:')[1].strip()
        
        self.data['device_info'] = {
            'username': username,
            'model': self.run_adb_command("shell getprop ro.product.model"),
            'android_version': self.run_adb_command("shell getprop ro.build.version.release"),
            'last_login': last_login
        }

    def extract_calls_sms(self):
        print("\nStarting call extraction...")
        calls_output = self.run_adb_command('shell content query --uri content://call_log/calls')
        
        if not calls_output:
            print("No call data received")
            return

        print("\nProcessing calls...")
        for line in calls_output.split('Row:'):
            if not line.strip():
                continue

            print("\n" + "="*50)
            print("Processing new call record")

            call = {}
            try:
                # Split the line into individual fields
                fields = line.split(',')
                
                # Process each field
                for field in fields:
                    field = field.strip()
                    
                    # Core call information (keeping existing working type extraction)
                    if field.startswith('type='):
                        raw_type = field.replace('type=', '').strip()
                        print(f"Raw type string: '{raw_type}'")
                        try:
                            type_num = int(raw_type)
                            print(f"Converted type number: {type_num}")
                            call['type'] = {
                                1: 'INCOMING',
                                2: 'OUTGOING',
                                3: 'MISSED',
                                5: 'REJECTED',
                                4: 'VOICEMAIL',
                                6: 'BLOCKED',
                                7: 'ANSWERED_EXTERNALLY'
                            }.get(type_num)
                            if call['type'] is None:
                                print(f"WARNING: Unmapped type number: {type_num}")
                                call['type'] = f'UNKNOWN_{type_num}'
                            else:
                                print(f"Mapped to call type: {call['type']}")
                        except ValueError as e:
                            print(f"ERROR converting type '{raw_type}': {e}")
                            call['type'] = 'UNKNOWN'

                    # Number information
                    elif field.startswith('number='):
                        call['number'] = field.replace('number=', '').strip()
                    elif field.startswith('formatted_number='):
                        call['formatted_number'] = field.replace('formatted_number=', '').strip()
                    elif field.startswith('normalized_number='):
                        call['normalized_number'] = field.replace('normalized_number=', '').strip()
                    elif field.startswith('matched_number='):
                        call['matched_number'] = field.replace('matched_number=', '').strip()
                    elif field.startswith('numbertype='):
                        num_type = field.replace('numbertype=', '').strip()
                        if num_type != 'NULL':
                            call['number_type'] = num_type

                    # Timing information
                    elif field.startswith('duration='):
                        call['duration'] = field.replace('duration=', '').strip()
                    elif field.startswith('date='):
                        try:
                            timestamp = int(field.replace('date=', '').strip())
                            call['date'] = datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M:%S')
                            call['timestamp'] = timestamp  # Keep raw timestamp
                        except ValueError as e:
                            print(f"ERROR processing date: {e}")
                    elif field.startswith('ring_time='):
                        ring_time = field.replace('ring_time=', '').strip()
                        if ring_time != '0':
                            call['ring_time'] = ring_time

                    # Contact information
                    elif field.startswith('name='):
                        name = field.replace('name=', '').strip()
                        if name and name != 'NULL':
                            call['contact_name'] = name
                    elif field.startswith('lookup_uri='):
                        uri = field.replace('lookup_uri=', '').strip()
                        if uri and uri != 'NULL':
                            call['contact_lookup_uri'] = uri
                    elif field.startswith('photo_uri='):
                        photo = field.replace('photo_uri=', '').strip()
                        if photo and photo != 'NULL':
                            call['contact_photo_uri'] = photo

                    # Location information
                    elif field.startswith('geocoded_location='):
                        location = field.replace('geocoded_location=', '').strip()
                        if location and location != 'NULL':
                            call['location'] = location
                    elif field.startswith('countryiso='):
                        country = field.replace('countryiso=', '').strip()
                        if country and country != 'NULL':
                            call['country'] = country

                    # Call status information
                    elif field.startswith('missed_reason='):
                        missed = field.replace('missed_reason=', '').strip()
                        if missed != '0':
                            call['missed_reason'] = missed
                    elif field.startswith('block_reason='):
                        block = field.replace('block_reason=', '').strip()
                        if block != '0':
                            call['block_reason'] = block
                    elif field.startswith('presentation='):
                        pres = field.replace('presentation=', '').strip()
                        if pres != '1':  # 1 is normal presentation
                            call['presentation'] = pres

                    # Device information
                    elif field.startswith('subscription_id='):
                        call['sim_id'] = field.replace('subscription_id=', '').strip()
                    elif field.startswith('phone_account_address='):
                        account = field.replace('phone_account_address=', '').strip()
                        if account and account != 'NULL':
                            call['phone_account'] = account

                    # Additional flags
                    elif field.startswith('is_read='):
                        is_read = field.replace('is_read=', '').strip()
                        if is_read and is_read.lower() != 'null':
                            call['is_read'] = bool(int(is_read))
                    elif field.startswith('new='):
                        new = field.replace('new=', '').strip()
                        if new:
                            call['is_new'] = bool(int(new))
                    elif field.startswith('is_special_number='):
                        special = field.replace('is_special_number=', '').strip()
                        if special != '0':
                            call['is_special'] = True

                # Only add if we have required fields
                if all(key in call for key in ['number', 'type', 'date']):
                    print("\nAdding call record:")
                    for key, value in call.items():
                        print(f"{key}: {value}")
                    self.data['communications']['calls'].append(call)
                else:
                    missing = [key for key in ['number', 'type', 'date'] if key not in call]
                    print(f"WARNING: Skipping incomplete call record. Missing: {missing}")

            except Exception as e:
                print(f"ERROR processing call record: {str(e)}")
                continue

        print("\nCall extraction completed")
        print(f"Total calls processed: {len(self.data['communications']['calls'])}")

        # Extract SMS
        sms_output = self.run_adb_command('shell content query --uri content://sms')
        if sms_output:
            for line in sms_output.split('Row:'):
                if line.strip():
                    message = {}
                    if 'address=' in line:
                        message['number'] = line.split('address=')[1].split(',')[0].strip()
                    if 'body=' in line:
                        message['content'] = line.split('body=')[1].split(',')[0].strip()
                    if 'type=' in line:
                        type_num = line.split('type=')[1].split(',')[0].strip()
                        message['type'] = 'RECEIVED' if type_num == '1' else 'SENT'
                    if 'date=' in line:
                        timestamp = int(line.split('date=')[1].split(',')[0].strip())
                        message['date'] = datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M:%S')
                    
                    self.data['communications']['messages'].append(message)

    def extract_networks(self):
        print("\nExtracting network information...")
        wifi_output = self.run_adb_command('shell cmd wifi list-networks')
        if wifi_output:
            networks = []
            for line in wifi_output.split('\n'):
                if 'Network Id' not in line and line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        network = {
                            "ssid": parts[1],
                            "security": ' '.join(parts[2:])
                        }
                        networks.append(network)
            self.data["networks"] = networks

    def scan_hidden_files(self):
        print("\nScanning for hidden files...")
        hidden_patterns = [
            '.nomedia',
            '.*',
            '.hidden',
            '.enc',
            '.locked'
        ]
        
        directories = [
            '/sdcard',
            '/data/local/tmp',
            '/storage/emulated/0',
            '/system',  # Add system directories
            '/data'     # Add data directories
        ]
        
        suspicious_files = []
        
        for directory in directories:
            cmd = f'shell find {directory} -type f 2>/dev/null'
            files = self.run_adb_command(cmd)
            
            if files:
                for file in files.split('\n'):
                    if any(pattern in file for pattern in hidden_patterns):
                        file_info = self.run_adb_command(f'shell ls -la "{file}"')
                        suspicious_files.append({
                            'path': file,
                            'details': file_info
                        })
        
        self.data['hidden_files'] = suspicious_files          

    def extract_files(self):
        print("\nExtracting file information...")
        
        # Get recent photos
        dcim_list = self.run_adb_command('shell ls -la /sdcard/DCIM/Camera/')
        if dcim_list:
            for line in dcim_list.split('\n'):
                if 'IMG_' in line or 'VID_' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        self.data['files']['photos'].append({
                            'name': ' '.join(parts[8:]),
                            'date': f"{parts[5]} {parts[6]} {parts[7]}",
                            'size': parts[4]
                        })

        # Get downloads
        downloads_list = self.run_adb_command('shell ls -la /sdcard/Download/')
        if downloads_list:
            for line in downloads_list.split('\n'):
                if line.strip() and not line.startswith('total'):
                    parts = line.split()
                    if len(parts) >= 8:
                        self.data['files']['downloads'].append({
                            'name': ' '.join(parts[8:]),
                            'date': f"{parts[5]} {parts[6]} {parts[7]}",
                            'size': parts[4]
                        })

    def extract_all(self):
        print("Starting focused forensic extraction...")
        self.extract_device_info()
        self.extract_calls_sms()
        self.extract_networks()
        self.extract_files()
        self.scan_hidden_files()
        return self.data
    
    def save_report(self, filename='forensic_report.json'):
        print(f"\nSaving raw data to {filename}...")
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"Raw data saved to {filename}")

    