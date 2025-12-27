import zipfile
import os
import time

def create_dummy_apk(filename="benign_test_app.apk"):
    """
    Creates a harmless file that LOOKS like an APK (which is just a ZIP)
    to test the antivirus detection logic.
    """
    print(f"Creating safe test file: {filename}...")
    
    # an APK is just a ZIP file with specific files inside.
    # We will create a valid ZIP structure but with harmless text files inside.
    with zipfile.ZipFile(filename, 'w') as apk:
        # Add a fake manifest (required for it to roughly look like an APK structure)
        apk.writestr('AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test"></manifest>')
        # Add a dummy text file saying this is safe
        apk.writestr('README.txt', 'This is a BENIGN test file for CyberNova Security Testing. It contains NO malicious code.')
        
    print("✅ File Created!")
    print(f"📍 Location: {os.path.abspath(filename)}")
    print("ℹ️  Copy this file to your 'Downloads' or 'Desktop' folder to trigger the Real-Time Shield.")

if __name__ == "__main__":
    create_dummy_apk()
