from forensic_extractor import ForensicExtractor
from network_analyzer import NetworkAnalyzer
from file_analyzer import FileAnalyzer
from communication_analyzer import CommunicationAnalyzer
from report_generator import AdvancedReportGenerator
import traceback
import os
import logging

def test_specific_file(extractor, file_path):
    print(f"\nTesting specific file: {file_path}")
    test_cmd = f'shell ls -l "{file_path}"'
    exists = extractor.run_adb_command(test_cmd)
    if exists:
        print(f"File exists: {exists}")
        cmd = f'shell xxd -p -l 16 "{file_path}"'
        result = extractor.run_adb_command(cmd)
        print(f"File signature: {result}")
    else:
        print(f"File not found: {file_path}")

def debug_files():
    print("\nStarting debug file checks...")
    extractor = ForensicExtractor()
    
    xxd_test = extractor.run_adb_command('shell which xxd')
    print(f"xxd available: {xxd_test}")
    
    print("\nFiles in Download directory:")
    ls_result = extractor.run_adb_command('shell ls -la /sdcard/Download/')
    print(ls_result)
    
    test_files = [
        '/sdcard/Download/EGR-500-1.pdf',
        '/sdcard/Download/test.txt',
        '/sdcard/Download/IMG-20240908-WA0002.txt',
        '/sdcard/Download/document.pdf',
        '/sdcard/Download/secret.enc'
    ]
    
    for file in test_files:
        test_specific_file(extractor, file)

def main():
    try:
        print("Starting forensic analysis...")
        
        # Initialize components
        extractor = ForensicExtractor()
        network_analyzer = NetworkAnalyzer()
        file_analyzer = FileAnalyzer()
        file_analyzer.set_forensic_extractor(extractor)
        comm_analyzer = CommunicationAnalyzer()
        report_gen = AdvancedReportGenerator()
        
        # Extract data
        print("\nExtracting data...")
        data = extractor.extract_all()
        
        # Analyze everything
        print("\nAnalyzing data...")
        network_analysis = network_analyzer.analyze_networks(data.get('networks', {}))
        file_analysis = file_analyzer.analyze_files(data)
        comm_analysis = comm_analyzer.analyze_communications(data)
        
        # Generate reports
        print("\nGenerating reports...")
        output_dir = "forensic_reports"
        os.makedirs(output_dir, exist_ok=True)
        
        # Save raw JSON data
        raw_data_path = os.path.join(output_dir, 'forensic_report.json')
        print(f"Saving raw data to {raw_data_path}...")
        extractor.save_report(raw_data_path)
        print(f"Raw data saved to {raw_data_path}")
        
        # Generate HTML report
        report_file = report_gen.generate_complete_report(
            data=data, 
            file_analysis=file_analysis, 
            network_analysis=network_analysis, 
            communication_analysis=comm_analysis
        )
        
        print("\nAnalysis complete!")
        print(f"Generated report: {report_file}")
        print(f"Reports directory: {output_dir}")
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        print(traceback.format_exc())

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    debug_files()
    main()