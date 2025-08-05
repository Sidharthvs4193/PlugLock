import os
import wmi
import json
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from dotenv import load_dotenv()

#Load environment varibales
load_dotenv()


def get_usb_devices():
    c = wmi.WMI()
    usb_devices = []
    for drive in c.Win32_DiskDrive():
        if 'USB' in drive.PNPDeviceID and drive.SerialNumber:
            for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    usb_devices.append({
                        'serial': drive.SerialNumber.strip(),
                        'model': drive.Model,
                        'size': f"{int(drive.Size)/(1024**3):.1f} GB" if drive.Size else "Unknown",
                        'drive_letter': logical_disk.Caption
                    })
    return usb_devices

def generate_master_key(usb_serial, password="default_password"):
    salt = usb_serial.encode() + os.getenv('APP_SECRET')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def hide_file(file_path):
    """Hide file using system + hidden attributes"""
    try:
        subprocess.run(['attrib', '+s', '+h', file_path], check=True, shell=True)
        print(f"✓ File hidden successfully: {file_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to hide file: {e}")
        return False

def make_usb_readonly(drive_letter):
    """Make USB drive read-only using diskpart"""
    try:
        script_content = f"""select volume {drive_letter[0]}
attributes volume set readonly
exit"""
        script_path = "diskpart_script.txt"
        with open(script_path, 'w') as f:
            f.write(script_content)
        result = subprocess.run(['diskpart', '/s', script_path], 
                              capture_output=True, text=True, shell=True)
        os.remove(script_path)
        if result.returncode == 0:
            print("✓ USB drive set to read-only successfully")
            return True
        else:
            print(f"✗ Failed to set USB read-only: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error making USB read-only: {e}")
        return False

def create_key_file(usb_drive_letter, usb_serial):
    try:
        master_key = generate_master_key(usb_serial)
        cipher = Fernet(master_key)
        key_data = {
            'app_name': 'SecureCalculator',
            'usb_serial': usb_serial,
            'version': '1.0',
            'valid': True
        }
        encrypted_data = cipher.encrypt(json.dumps(key_data).encode())
        key_file_path = os.path.join(usb_drive_letter, 'calc_key.bin')
        with open(key_file_path, 'wb') as f:
            f.write(encrypted_data)
        print(f"✓ Key file created: {key_file_path}")
        if hide_file(key_file_path):
            print("✓ Key file hidden from view")
        readme_path = os.path.join(usb_drive_letter, 'README.txt')
        with open(readme_path, 'w') as f:
            f.write("This USB drive contains security keys for authorized software.\n")
            f.write("Do not modify or delete any files on this drive.\n")
            f.write("Contact your system administrator for assistance.\n")
        print("✓ README file created")
        make_readonly = input("\nDo you want to make this USB drive read-only for extra security? (y/N): ")
        if make_readonly.lower() == 'y':
            print("\nApplying read-only protection...")
            if make_usb_readonly(usb_drive_letter):
                print("⚠️  WARNING: USB is now READ-ONLY!")
                print("⚠️  To modify files later, you'll need to remove read-only protection manually.")
            else:
                print("⚠️  Read-only protection failed. USB remains writable.")
        return True
    except Exception as e:
        print(f"✗ Error creating key file: {e}")
        return False

def main():
    print("=== Enhanced USB Key Generator for Secure Calculator ===\n")
    print("⚠️  This will create a hidden, encrypted key file on your USB drive.")
    print("⚠️  Optionally, the entire USB can be made read-only for maximum security.\n")
    usb_devices = get_usb_devices()
    if not usb_devices:
        print("No USB devices found. Please insert a USB drive and try again.")
        return
    print("Available USB devices:")
    for i, device in enumerate(usb_devices):
        print(f"{i+1}. {device['model']} ({device['size']}) - Drive {device['drive_letter']} - Serial: {device['serial']}")
    try:
        choice = int(input(f"\nSelect USB device (1-{len(usb_devices)}): ")) - 1
        if choice < 0 or choice >= len(usb_devices):
            print("Invalid selection.")
            return
    except ValueError:
        print("Invalid input.")
        return
    selected_device = usb_devices[choice]
    print(f"\nSelected: {selected_device['model']} (Drive {selected_device['drive_letter']})")
    print("⚠️  This will create security files on this USB drive.")
    confirm = input("Continue? (y/N): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        return
    success = create_key_file(
        selected_device['drive_letter'] + '\\',
        selected_device['serial']
    )
    if success:
        print(f"\n✅ USB security key created successfully!")
        print(f"✅ Serial number: {selected_device['serial']}")
        print(f"✅ Drive: {selected_device['drive_letter']}")
        print(f"✅ Key file is hidden from normal view")
        print("\n🔒 Your secure USB key is ready!")
        print("🔒 Keep this USB drive safe - it's required to run your calculator!")
    else:
        print("\n❌ Failed to create USB key.")

if __name__ == "__main__":
    main()
