import tkinter as tk
from tkinter import messagebox
import os
import json
import wmi
import pythoncom
from math import sqrt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from dotenv import load_dotenv()

#Extracting environment variables
load_dotenv()

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

def get_usb_serial_and_drive():
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for drive in c.Win32_DiskDrive():
            if drive.PNPDeviceID and 'USB' in str(drive.PNPDeviceID) and drive.SerialNumber:
                serial = drive.SerialNumber.strip()
                for partition in drive.associators("Win32_DiskDriveToDiskPartition"):
                    for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                        return serial, logical_disk.Caption + '\\'
        return None, None
    except Exception as e:
        return None, None
    finally:
        pythoncom.CoUninitialize()

def find_and_verify_key():
    serial, drive = get_usb_serial_and_drive()
    if serial and drive:
        key_file_path = os.path.join(drive, 'calc_key.bin')
        if os.path.exists(key_file_path):
            try:
                master_key = generate_master_key(serial)
                cipher = Fernet(master_key)
                with open(key_file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
                key_data = json.loads(decrypted_data.decode())
                if (key_data.get('app_name') == 'SecureCalculator' and
                    key_data.get('usb_serial') == serial and
                    key_data.get('valid') == True):
                    return serial, drive
            except Exception as e:
                print(f"Key verification failed: {e}")
    return None, None

class EnhancedCalculator(tk.Tk):
    def __init__(self, usb_serial):
        super().__init__()
        self.title("🔒 Secure Calculator Pro")
        self.geometry("360x520")
        self.resizable(False, False)
        self.configure(bg='#2c3e50')
        self.current = ""
        self.usb_serial = usb_serial
        self.is_locked = False
        self.poll_interval = 2000  # ms

        self.create_widgets()
        self.after(self.poll_interval, self.poll_usb)

    def create_widgets(self):
        self.display_var = tk.StringVar(value="0")
        display = tk.Entry(self, textvariable=self.display_var, 
                          font=("Arial", 24), bd=10, relief=tk.RIDGE, 
                          justify='right', bg='#34495e', fg='#ecf0f1', 
                          insertbackground='#ecf0f1')
        display.pack(fill=tk.X, padx=15, pady=15)

        num_color = '#3498db'
        op_color = '#e74c3c'
        func_color = '#f39c12'
        clear_color = '#95a5a6'

        buttons = [
            [('C', clear_color), ('√', func_color), ('x²', func_color), ('÷', op_color)],
            [('7', num_color), ('8', num_color), ('9', num_color), ('×', op_color)],
            [('4', num_color), ('5', num_color), ('6', num_color), ('-', op_color)],
            [('1', num_color), ('2', num_color), ('3', num_color), ('+', op_color)],
            [('0', num_color), ('.', num_color), ('%', func_color), ('=', '#27ae60')],
        ]

        frame = tk.Frame(self, bg='#2c3e50')
        frame.pack(expand=True, fill='both', padx=15, pady=5)
        
        for r, row in enumerate(buttons):
            for c, (char, color) in enumerate(row):
                btn = tk.Button(frame, text=char, font=("Arial", 16, "bold"), 
                               height=2, width=5, bg=color, fg='white',
                               activebackground='#1abc9c', activeforeground='white',
                               command=lambda ch=char: self.on_button_click(ch))
                btn.grid(row=r, column=c, padx=2, pady=2, sticky="nsew")

        for i in range(5):
            frame.grid_rowconfigure(i, weight=1)
            frame.grid_columnconfigure(i, weight=1)

        status_frame = tk.Frame(self, bg='#2c3e50')
        status_frame.pack(fill=tk.X, padx=15, pady=5)
        self.status_label = tk.Label(status_frame, text="🔒 Protected by USB Key", 
                                    font=("Arial", 9, "bold"), fg="#27ae60", bg='#2c3e50')
        self.status_label.pack(side=tk.LEFT)
        if self.usb_serial:
            tk.Label(status_frame, text=f"Key: ...{self.usb_serial[-4:]}", 
                    font=("Arial", 8), fg="#95a5a6", bg='#2c3e50').pack(side=tk.RIGHT)

    def on_button_click(self, char):
        if self.is_locked:
            return
        if char == 'C':
            self.current = ""
            self.display_var.set("0")
        elif char == '=':
            try:
                expression = self.current.replace('÷', '/').replace('×', '*')
                result = eval(expression)
                if result == int(result):
                    self.display_var.set(str(int(result)))
                else:
                    self.display_var.set(f"{result:.8g}")
                self.current = str(result)
            except Exception:
                self.display_var.set("Error")
                self.current = ""
        elif char == '√':
            try:
                value = float(self.display_var.get())
                if value < 0:
                    self.display_var.set("Error")
                else:
                    result = sqrt(value)
                    self.display_var.set(f"{result:.8g}")
                    self.current = str(result)
            except Exception:
                self.display_var.set("Error")
                self.current = ""
        elif char == 'x²':
            try:
                value = float(self.display_var.get())
                result = value ** 2
                if result == int(result):
                    self.display_var.set(str(int(result)))
                else:
                    self.display_var.set(f"{result:.8g}")
                self.current = str(result)
            except Exception:
                self.display_var.set("Error")
                self.current = ""
        elif char == '%':
            try:
                value = float(self.display_var.get())
                result = value / 100
                self.display_var.set(f"{result:.8g}")
                self.current = str(result)
            except Exception:
                self.display_var.set("Error")
                self.current = ""
        else:
            if self.display_var.get() == "0" or self.display_var.get() == "Error":
                self.current = ""
            self.current += char
            self.display_var.set(self.current)

    def poll_usb(self):
        serial, _ = find_and_verify_key()
        if not self.is_locked:
            if serial != self.usb_serial:
                self.lock_app()
        else:
            if serial == self.usb_serial:
                self.unlock_app()
        self.after(self.poll_interval, self.poll_usb)

    def lock_app(self):
        if not self.is_locked:
            self.is_locked = True
            self.withdraw()
            self.status_label.config(text="🔒 LOCKED - USB Key Required", fg="#e74c3c")
            messagebox.showerror("🔒 SECURITY LOCK", 
                               "USB KEY REMOVED!\n\n🔑 Calculator locked for security.\n⚠️ Insert your USB key to continue.")

    def unlock_app(self):
        if self.is_locked:
            self.is_locked = False
            self.deiconify()
            self.status_label.config(text="🔒 Protected by USB Key", fg="#27ae60")
            messagebox.showinfo("🔓 UNLOCKED", "USB key detected!\n✅ Calculator unlocked.")

    def on_closing(self):
        self.destroy()

def show_auth_dialog():
    root = tk.Tk()
    root.withdraw()
    dialog = tk.Toplevel(root)
    dialog.title("🔒 Secure Calculator - Authentication")
    dialog.geometry("450x250")
    dialog.resizable(False, False)
    dialog.configure(bg='#2c3e50')
    dialog.grab_set()
    
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (450 // 2)
    y = (dialog.winfo_screenheight() // 2) - (250 // 2)
    dialog.geometry(f"450x250+{x}+{y}")

    tk.Label(dialog, text="🔒 USB Security Key Required", 
            font=("Arial", 16, "bold"), fg='#ecf0f1', bg='#2c3e50').pack(pady=15)
    
    tk.Label(dialog, text="Insert your USB security key\nor enter backup password:", 
            font=("Arial", 11), fg='#bdc3c7', bg='#2c3e50').pack(pady=5)
    
    tk.Label(dialog, text="Backup Password:", 
            font=("Arial", 10), fg='#ecf0f1', bg='#2c3e50').pack(pady=(15,5))
    
    password_var = tk.StringVar()
    password_entry = tk.Entry(dialog, textvariable=password_var, show="*", 
                             width=30, font=("Arial", 12), bg='#34495e', 
                             fg='#ecf0f1', insertbackground='#ecf0f1')
    password_entry.pack(pady=5)
    
    result = {'authenticated': False, 'usb_serial': None}

    def check_auth():
        serial, _ = find_and_verify_key()
        if serial:
            result['authenticated'] = True
            result['usb_serial'] = serial
            dialog.destroy()
            return
        password = password_var.get()
        if password == os.getenv('BACKUP_PASSWORD'):
            result['authenticated'] = True
            result['usb_serial'] = None
            dialog.destroy()
        else:
            messagebox.showerror("Authentication Failed", "Invalid password or USB key not found!")
            password_entry.delete(0, tk.END)

    def refresh_usb():
        serial, _ = find_and_verify_key()
        if serial:
            result['authenticated'] = True
            result['usb_serial'] = serial
            dialog.destroy()
        else:
            messagebox.showinfo("USB Status", "USB key still not detected.")

    button_frame = tk.Frame(dialog, bg='#2c3e50')
    button_frame.pack(pady=15)
    
    tk.Button(button_frame, text="🔓 Unlock", command=check_auth, 
             bg="#27ae60", fg="white", width=12, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="🔄 Refresh", command=refresh_usb, 
             bg="#3498db", fg="white", width=12, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="❌ Exit", command=dialog.destroy, 
             bg="#e74c3c", fg="white", width=12, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

    def auto_refresh():
        if dialog.winfo_exists():
            serial, _ = find_and_verify_key()
            if serial:
                result['authenticated'] = True
                result['usb_serial'] = serial
                dialog.destroy()
            else:
                dialog.after(2000, auto_refresh)
    
    dialog.after(2000, auto_refresh)
    password_entry.focus()
    password_entry.bind('<Return>', lambda e: check_auth())
    
    root.wait_window(dialog)
    root.destroy()
    return result['authenticated'], result['usb_serial']

def main():
    serial, _ = find_and_verify_key()
    if not serial:
        authenticated, serial = show_auth_dialog()
        if not authenticated:
            return
    app = EnhancedCalculator(serial)
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()

if __name__ == "__main__":
    main()
