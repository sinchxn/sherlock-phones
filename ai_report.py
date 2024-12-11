import json
import os
import google.generativeai as genai

# Configure the API key
genai.configure(api_key="")

# Create the model
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 1024,
    "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-pro",
    generation_config=generation_config,
)

# Function to compact JSON data
def compact_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)  # Load JSON data
    compacted_data = json.dumps(data, separators=(',', ':'))  # Compact the JSON data
    return compacted_data

# Function to generate a forensic report
def generate_forensic_report(data):
    prompt = f"""You are an experienced digital forensics investigator. I have extracted data from an Android device that includes communications (calls and SMS), WiFi networks, device info, and file data.

As a forensic investigator, analyze this extracted data and provide your professional insights and findings. Be creative in your analysis and highlight anything you find interesting or noteworthy.

Here's the extracted data:
{data}"""

    chat_session = model.start_chat(
        history=[
        ]
    )

    response = chat_session.send_message(prompt)
    return response.text

# Main execution
def main():
    file_path = 'forensic_report.json'  # Path to your JSON file
    
    # Compact the JSON file
    compacted_data = compact_json(file_path)
    
    # Generate the forensic report
    try:
        report = generate_forensic_report(compacted_data)

        # Save the report to a file
        with open('ai_report.txt', 'w', encoding='utf-8') as f:
            f.write(report)
    
        print("\nGenerated Forensic Report:\n")
        print(report)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
