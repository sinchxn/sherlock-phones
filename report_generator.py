import json
from datetime import datetime
import base64
import logging
import os

class AdvancedReportGenerator:
    def __init__(self):
        # Initialize logger
        self.logger = logging.getLogger(__name__)

        # Default colors
        self.colors = {
            'primary': 'rgb(75, 192, 192)',
            'secondary': 'rgb(255, 99, 132)',
            'warning': 'rgb(255, 205, 86)',
            'danger': 'rgb(255, 99, 132)',
            'success': 'rgb(75, 192, 192)',
            'info': 'rgb(54, 162, 235)'
        }
        
        # Default chart configuration
        self.chart_config = {
            "network_security": {
                "types": ["WPA2", "WPA", "WEP", "Open", "Unknown"],
                "risk_scores": [20, 40, 80, 100, 60],
                "colors": {
                    "WPA2": "#4CAF50",
                    "WPA": "#2196F3",
                    "WEP": "#FFC107",
                    "Open": "#F44336",
                    "Unknown": "#9E9E9E"
                }
            },
            "risk_levels": {
                "high": {"score": 90, "color": "#F44336"},
                "medium": {"score": 60, "color": "#FFC107"},
                "low": {"score": 30, "color": "#4CAF50"}
            }
        }
        
        # Try to load custom configuration if it exists
        config_path = 'config/chart_config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    custom_config = json.load(f)
                    # Update default config with custom values
                    self.chart_config.update(custom_config)
                self.logger.info("Custom chart configuration loaded successfully")
            except json.JSONDecodeError as e:
                self.logger.warning(f"Error loading chart config: {str(e)}. Using defaults")
            except Exception as e:
                self.logger.warning(f"Unexpected error loading config: {str(e)}. Using defaults")
        else:
            self.logger.info("No custom chart configuration found. Using defaults")

    def _get_network_data(self, network_analysis):
        """Process network data according to config"""
        network_data = []
        for net_type in self.chart_config['network_security']['types']:
            key = net_type.lower()
            network_data.append({
                'value': network_analysis['security_breakdown'].get(key, 0),
                'itemStyle': {'color': self.chart_config['network_security']['colors'][net_type]}
            })
        return network_data

    def _get_risk_level(self, reason):
        """Get risk level data from config"""
        if 'high' in reason.lower():
            return self.chart_config['risk_levels']['high']
        elif 'medium' in reason.lower():
            return self.chart_config['risk_levels']['medium']
        return self.chart_config['risk_levels']['low']

    def generate_complete_report(self, data, file_analysis, network_analysis, communication_analysis):
        """Generate an ultra-comprehensive, interactive HTML forensic report"""
        try:
            # Process network data
            network_data = self._get_network_data(network_analysis)

            # Extract risk scores from JSON
            risk_scores = network_analysis['risk_scores']  # Assuming this is in your JSON

            # Extract communication data for graphs
            incoming_calls = communication_analysis['calls'].get('call_types', {}).get('INCOMING', 0)
            outgoing_calls = communication_analysis['calls'].get('call_types', {}).get('OUTGOING', 0)
            missed_calls = communication_analysis['calls'].get('call_types', {}).get('MISSED', 0)
            sent_messages = communication_analysis['messages'].get('message_types', {}).get('SENT', 0)
            received_messages = communication_analysis['messages'].get('message_types', {}).get('RECEIVED', 0)

            # Prepare data for network security chart
            open_networks = network_analysis['security_breakdown'].get('open', 0)
            wep_networks = network_analysis['security_breakdown'].get('wep', 0)
            wpa_networks = network_analysis['security_breakdown'].get('wpa', 0)
            wpa2_networks = network_analysis['security_breakdown'].get('wpa2', 0)

            # Prepare file signature anomalies
            file_signature_anomalies = file_analysis.get('hidden_detection', {}).get('findings', {}).get('extension_mismatches', [])

            # Generate HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>🕵️ Forensic Deep Dive Report</title>
                <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/echarts/5.4.3/echarts.min.js"></script>
                <style>
                    @keyframes pulse {{ 
                        0% {{ transform: scale(1); }}
                        50% {{ transform: scale(1.05); }}
                        100% {{ transform: scale(1); }}
                    }}
                    .risk-indicator {{ 
                        animation: pulse 2s infinite;
                    }}
                    .advanced-hover:hover {{ 
                        transform: scale(1.02);
                        box-shadow: 0 10px 15px rgba(0,0,0,0.2);
                        transition: all 0.3s ease;
                    }}
                </style>
            </head>
            <body class="bg-gray-900 text-gray-100">
                <div class="container mx-auto px-4 py-8">
                    <!-- ORIGINAL SECTIONS START -->
                    
                    <!-- Header -->
                    <header class="text-center mb-12">
                        <h1 class="text-4xl font-bold text-red-500 animate-pulse">🔍 Advanced Forensic Analysis Report</h1>
                        <p class="text-xl text-gray-400">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </header>

                    <!-- Original Device & Network Section -->
                    <section class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="bg-gray-800 p-6 rounded-lg shadow-xl advanced-hover">
                            <h2 class="text-2xl font-semibold text-blue-400 mb-4">🖥️ Device Forensics</h2>
                            <div class="space-y-2">
                                <p><strong>Model:</strong> {data['device_info'].get('model', 'Unknown')}</p>
                                <p><strong>Android Version:</strong> {data['device_info'].get('android_version', 'Unknown')}</p>
                                <p><strong>Last Login:</strong> {data['device_info'].get('last_login', 'Unknown')}</p>
                            </div>
                        </div>

                        <div class="bg-gray-800 p-6 rounded-lg shadow-xl advanced-hover">
                            <h2 class="text-2xl font-semibold text-green-400 mb-4">📡 Network Threat Matrix</h2>
                            <canvas id="networkSecurityChart" width="400" height="200"></canvas>
                        </div>
                    </section>

                    <!-- Original Risk Analysis Section -->
                    <section class="mt-12">
                        <div class="bg-gray-800 p-8 rounded-lg shadow-2xl">
                            <h2 class="text-3xl font-bold text-red-500 mb-6">🚨 Comprehensive Risk Analysis</h2>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="bg-gray-700 p-4 rounded risk-indicator">
                                    <h3 class="text-xl font-semibold text-yellow-400">Network Risks</h3>
                                    <p>Open Networks: {network_analysis['security_breakdown']['open']}</p>
                                    <p>Vulnerable WEP: {network_analysis['security_breakdown']['wep']}</p>
                                </div>
                                <div class="bg-gray-700 p-4 rounded risk-indicator">
                                    <h3 class="text-xl font-semibold text-orange-400">File Anomalies</h3>
                                    <p>Hidden Files: {file_analysis['summary']['total_hidden']}</p>
                                    <p>Suspicious Files: {file_analysis['summary']['suspicious_count']}</p>
                                </div>
                                <div class="bg-gray-700 p-4 rounded risk-indicator">
                                    <h3 class="text-xl font-semibold text-purple-400">Communication Patterns</h3>
                                    <p>Total Calls: {communication_analysis['calls']['total_calls']}</p>
                                    <p>Total Messages: {communication_analysis['messages']['total_messages']}</p>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Original Communication Heatmap -->
                    <section class="mt-12">
                        <div class="bg-gray-800 p-8 rounded-lg">
                            <h2 class="text-3xl font-bold text-blue-500 mb-6">📊 Interactive Communication Heatmap</h2>
                            <canvas id="communicationHeatmap" width="600" height="300"></canvas>
                        </div>
                    </section>

                    <!-- Original File Signatures Section -->
                    <section class="mt-12">
                        <div class="bg-gray-800 p-8 rounded-lg">
                            <h2 class="text-3xl font-bold text-green-500 mb-6">🕵️ File Signature Anomalies</h2>
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="bg-gray-700">
                                        <th class="p-3">File Path</th>
                                        <th class="p-3">Declared Extension</th>
                                        <th class="p-3">Actual Extension</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {''.join([f'''
                                    <tr class="border-b border-gray-700 hover:bg-gray-700">
                                        <td class="p-3">{file['path']}</td>
                                        <td class="p-3 text-yellow-400">{file['declared_ext']}</td>
                                        <td class="p-3 text-red-500">{file['actual_ext']}</td>
                                    </tr>
                                    ''' for file in file_analysis.get('hidden_detection', {}).get('findings', {}).get('extension_mismatches', [])])}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <!-- ORIGINAL SECTIONS END -->

                    <!-- NEW SECTIONS START -->

                    <!-- Enhanced Communication Analysis -->
                    <section class="mt-12">
                        <div class="bg-gray-800 p-8 rounded-lg shadow-xl">
                            <h2 class="text-3xl font-bold text-yellow-500 mb-6">📱 Enhanced Communication Analysis</h2>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                                <div>
                                    <h3 class="text-xl font-semibold text-blue-400 mb-4">Call Patterns</h3>
                                    <canvas id="callPatternsChart"></canvas>
                                </div>
                                <div>
                                    <h3 class="text-xl font-semibold text-green-400 mb-4">Message Distribution</h3>
                                    <canvas id="messageDistChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Network Deep Dive -->
                    <section class="mt-12">
                        <div class="bg-gray-800 p-8 rounded-lg shadow-xl">
                            <h2 class="text-3xl font-bold text-indigo-500 mb-6">🌐 Network Security Deep Dive</h2>
                            <div id="networkDeepDive" style="width: 100%; height: 400px;"></div>
                        </div>
                    </section>

                    <script>
                        // ORIGINAL CHARTS START
                        
                        // Original Network Security Chart
                        var networkCtx = document.getElementById('networkSecurityChart').getContext('2d');
                        new Chart(networkCtx, {{
                            type: 'pie',
                            data: {{
                                labels: ['Open', 'WEP', 'WPA', 'WPA2'],
                                datasets: [{{
                                    data: [
                                        {open_networks},
                                        {wep_networks},
                                        {wpa_networks},
                                        {wpa2_networks}
                                    ],
                                    backgroundColor: [
                                        'rgba(255, 99, 132, 0.8)', 
                                        'rgba(255, 159, 64, 0.8)', 
                                        'rgba(255, 205, 86, 0.8)', 
                                        'rgba(75, 192, 192, 0.8)'
                                    ]
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                plugins: {{
                                    datalabels: {{
                                        color: 'white',
                                        font: {{ weight: 'bold' }}
                                    }}
                                }}
                            }}
                        }});

                        // Original Communication Heatmap
                        var heatmapCtx = document.getElementById('communicationHeatmap').getContext('2d');
                        new Chart(heatmapCtx, {{
                            type: 'line',
                            data: {{
                                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                                datasets: [
                                    {{
                                        label: 'Incoming Calls',
                                        data: [12, 19, 3, 5, 2, 3],
                                        borderColor: 'rgb(75, 192, 192)',
                                        tension: 0.1
                                    }},
                                    {{
                                        label: 'Outgoing Calls',
                                        data: [2, 3, 20, 5, 1, 4],
                                        borderColor: 'rgb(255, 99, 132)',
                                        tension: 0.1
                                    }}
                                ]
                            }},
                            options: {{
                                responsive: true,
                                plugins: {{
                                    title: {{ display: true, text: 'Communication Activity Heatmap' }}
                                }}
                            }}
                        }});

                        // ORIGINAL CHARTS END

                        // NEW VISUALIZATIONS START

                        // Enhanced Communication Analysis
                        const callCtx = document.getElementById('callPatternsChart').getContext('2d');
                        new Chart(callCtx, {{
                            type: 'bar',
                            data: {{
                                labels: ['Call Distribution'],
                                datasets: [
                                    {{
                                        label: 'Incoming',
                                        data: [{incoming_calls}],
                                        backgroundColor: 'rgba(75, 192, 192, 0.8)'
                                    }},
                                    {{
                                        label: 'Outgoing',
                                        data: [{outgoing_calls}],
                                        backgroundColor: 'rgba(255, 99, 132, 0.8)'
                                    }},
                                    {{
                                        label: 'Missed',
                                        data: [{missed_calls}],
                                        backgroundColor: 'rgba(255, 206, 86, 0.8)'
                                    }}
                                ]
                            }},
                            options: {{
                                responsive: true,
                                plugins: {{
                                    legend: {{
                                        position: 'top',
                                    }},
                                    title: {{
                                        display: true,
                                        text: 'Call Type Distribution'
                                    }}
                                }},
                                scales: {{
                                    y: {{
                                        beginAtZero: true
                                    }}
                                }}
                            }}
                        }});

                        // Message Distribution Chart
                        const msgCtx = document.getElementById('messageDistChart').getContext('2d');
                        new Chart(msgCtx, {{
                            type: 'doughnut',
                            data: {{
                                labels: ['Sent', 'Received'],
                                datasets: [{{
                                    data: [
                                        {sent_messages},
                                        {received_messages}
                                    ],
                                    backgroundColor: [
                                        'rgba(54, 162, 235, 0.8)',
                                        'rgba(75, 192, 192, 0.8)'
                                    ]
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                plugins: {{
                                    legend: {{
                                        position: 'top'
                                    }},
                                    title: {{
                                        display: true,
                                        text: 'Message Type Distribution'
                                    }}
                                }}
                            }}
                        }});

                        // Network Deep Dive
                        const networkDeepDive = echarts.init(document.getElementById('networkDeepDive'));
                        networkDeepDive.setOption({{
                            tooltip: {{
                                trigger: 'axis',
                                axisPointer: {{
                                    type: 'shadow'
                                }}
                            }},
                            legend: {{
                                data: ['Networks', 'Risk Score'],
                                textStyle: {{
                                    color: '#fff'
                                }}
                            }},
                            xAxis: {{
                                data: ['WPA2', 'WPA', 'WEP', 'Open'],
                                axisLabel: {{
                                    color: '#fff'
                                }}
                            }},
                            yAxis: [
                                {{
                                    type: 'value',
                                    name: 'Count',
                                    nameTextStyle: {{
                                        color: '#fff'
                                    }},
                                    axisLabel: {{
                                        color: '#fff'
                                    }}
                                }},
                                {{
                                    type: 'value',
                                    name: 'Risk Score',
                                    max: 100,
                                    nameTextStyle: {{
                                        color: '#fff'
                                    }},
                                    axisLabel: {{
                                        color: '#fff'
                                    }}
                                }}
                            ],
                            series: [
                                {{
                                    name: 'Networks',
                                    type: 'bar',
                                    data: [{open_networks}, {wep_networks}, {wpa_networks}, {wpa2_networks}]
                                }},
                                {{
                                    name: 'Risk Score',
                                    type: 'line',
                                    yAxisIndex: 1,
                                    data: {json.dumps(risk_scores)}
                                }}
                            ]
                        }});

                        // Handle window resize for all charts
                        window.addEventListener('resize', () => {{
                            networkDeepDive.resize();
                        }});
                    </script>
                </div>
            </body>
            </html>
            """

            report_file = f'forensic_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Enhanced Forensic Report Generated: {report_file}")
            return report_file
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise