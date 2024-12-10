# Android Device Forensics Analyzer 🔍
A powerful, user-friendly tool that automates Android device forensics by extracting digital artifacts and presenting them through an interactive dashboard. Enhanced with AI capabilities, it provides intelligent insights alongside traditional analysis, making it perfect for digital forensics investigators, security researchers, and IT professionals who need comprehensive device analysis.

# 🚀 Key Features

- Smart Data Collection: Automatically extracts communications, device info, and file system data
- AI-Powered Analysis: Leverages Google's Gemini 1.5 Pro to provide preliminary forensic insights
- Interactive Dashboard: Beautiful visualizations including heatmaps and activity timelines
- File Intelligence: Advanced detection of hidden and suspicious files
- Network Analysis: Assess WiFi configurations and security risks
- Communication Mapping: Analyze patterns in messages and calls

# 🛠️ Quick Start
## Prerequisites

Python 3.8+
Android Debug Bridge (ADB)
Android device with USB debugging enabled
Google Gemini API key

## Installation

1. Get the code:
```
git clone https://github.com/sinchxm/sherlock-phones
cd android-forensics-analyzer
```
2. Set up dependencies:
```
pip install -r requirements.txt
```
3. Configure your API key:
```
# In config.py
GEMINI_API_KEY = "your-api-key-here"
```
## Running an Analysis

Connect your Android device via USB
Enable USB debugging on the device
Run the analyzer:
```
python main.py
```
# 📊 Output
The tool generates two outputs:
- An interactive HTML dashboard with visualizations, and an analysis report with an AI Forensic Investigator's insights.
- A detailed JSON report with raw findings

# ⚠️ Important Notes

- This tool requires USB debugging access
- Focuses on user-accessible data (non-rooted devices, for now)
- Must have proper authorization to analyze any device
- Internet connection required for AI features

# 🙏 Acknowledgments
Built as part of CIS542-Digital Forensics, this tool streamlines the Android forensics investigation process while providing meaningful insights through modern visualization techniques.

