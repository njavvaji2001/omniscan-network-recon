import os
import csv
import socket
import re
import threading
import subprocess
import webbrowser # Built-in Python engine to handle opening browser windows
from datetime import datetime
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.appbar import MDTopAppBar, MDTopAppBarTitle
from kivymd.uix.button import MDButton, MDButtonText
from kivymd.uix.label import MDLabel
from kivy.clock import Clock

PENTEST_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB"
}

MAC_VENDORS = {
    "10:36:AA": "Cisco Systems / Linksys Router",
    "48:E1:E9": "Apple Inc. (Mac/iPhone/iPad)",
    "D0:39:57": "ASUSTek Computer Inc.",
    "80:84:89": "Intel Corporate Interface",
    "88:57:1D": "Samsung Electronics",
    "24:7D:4D": "Huawei Technologies",
    "AA:E6:D3": "Private/Randomized Mobile MAC Address",
    "3A:A4:20": "Private/Randomized Mobile MAC Address",
    "82:B1:82": "Private/Randomized Mobile MAC Address",
    "2A:E1:F2": "Private/Randomized Mobile MAC Address"
}

class OmniScanApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "Teal"
        self.theme_cls.theme_style = "Dark" 

        screen = MDScreen()

        # 1. Top App Bar Navigation Layout
        appbar = MDTopAppBar(pos_hint={"top": 1})
        appbar_title = MDTopAppBarTitle(text="OmniScan Advanced Vendor Monitor")
        appbar.add_widget(appbar_title)
        screen.add_widget(appbar)

        # 2. Real-Time Status Text Display 
        self.status_label = MDLabel(
            text="Engine Idle.\n\nClick 'START SCAN' to map the network environment with Vendor tracking.",
            halign="center",
            pos_hint={"center_x": 0.5, "center_y": 0.60},
            theme_text_color="Secondary"
        )
        screen.add_widget(self.status_label)

        # 3. Interactive Recruiter Link Tracking Panel (Your Name & LinkedIn Info)
        developer_profile = MDLabel(
            text="Developed by: [b]Nithin Javvaji[/b]\n[color=008080]Click here to connect on LinkedIn[/color]",
            markup=True, # Tells Kivy to render the bold and color markdown tags natively
            halign="center",
            pos_hint={"center_x": 0.5, "center_y": 0.32}
        )
        # Bind an on-touch listener event so clicking the text opens your profile page
        developer_profile.bind(on_touch_down=self.open_linkedin_url)
        screen.add_widget(developer_profile)

        # 4. Interactive Start and Stop Execution Controls
        self.start_btn = MDButton(
            MDButtonText(text="START SCAN"),
            style="filled",
            pos_hint={"center_x": 0.35, "center_y": 0.15}
        )
        self.start_btn.bind(on_release=self.start_scan)
        screen.add_widget(self.start_btn)

        self.stop_btn = MDButton(
            MDButtonText(text="STOP & EXPORT"),
            style="tonal",
            pos_hint={"center_x": 0.65, "center_y": 0.15},
            disabled=True
        )
        self.stop_btn.bind(on_release=self.stop_and_export)
        screen.add_widget(self.stop_btn)

        self.scan_active = False
        self.inventory_data = {}
        self.display_log = ""

        return screen

    def open_linkedin_url(self, instance, touch):
        """Forces the local device operating system to launch a browser window straight to your profile."""
        if instance.collide_point(*touch.pos):
            webbrowser.open("https://www.linkedin.com/in/nithinjavvaji/")

    def get_local_subnet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            ip_parts = local_ip.split('.')
            base_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
            return base_subnet, local_ip
        except Exception:
            return "10.0.0.", "127.0.0.1"

    def get_mac_from_arp(self, target_ip):
        try:
            with os.popen(f"arp -n {target_ip}") as f:
                arp_output = f.read()
            mac_match = re.search(r"(([a-fA-F0-9]{1,2}[:-]){5}[a-fA-F0-9]{1,2})", arp_output)
            if mac_match:
                return mac_match.group(0).upper()
        except Exception:
            pass
        return "UNKNOWN"

    def get_vendor_by_mac(self, mac_address):
        if not mac_address or mac_address == "UNKNOWN":
            return "Active Network Node"
        prefix = mac_address[:8].upper()
        return MAC_VENDORS.get(prefix, "Active Network Node")

    def start_scan(self, instance):
        if self.scan_active:
            return
        self.scan_active = True
        self.inventory_data.clear()
        self.display_log = "Launching concurrent ICMP scan loops with vendor matching...\n\n"
        self.status_label.text = self.display_log
        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        
        threading.Thread(target=self.network_scanner_engine, daemon=True).start()

    def update_ui_text(self, text_update):
        self.status_label.text = text_update

    def ping_single_host(self, target_ip, base_subnet):
        if not self.scan_active:
            return

        try:
            response = subprocess.call(
                ["ping", "-c", "1", "-t", "1", target_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            if response == 0:
                mac_address = self.get_mac_from_arp(target_ip)
                resolved_name = self.get_vendor_by_mac(mac_address)

                discovered_ports = []
                for port, desc in PENTEST_PORTS.items():
                    p_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    p_sock.settimeout(0.02)
                    if p_sock.connect_ex((target_ip, port)) == 0:
                        discovered_ports.append(f"{port}({desc})")
                    p_sock.close()
                
                ports_str = ", ".join(discovered_ports) if discovered_ports else "None"

                self.inventory_data[target_ip] = {
                    "IP": target_ip, "Name": resolved_name, "MAC": mac_address, "Ports": ports_str
                }

                line = f"▶ {target_ip} | {resolved_name} | {mac_address} | Ports: {ports_str}\n"
                self.display_log += line
                Clock.schedule_once(lambda dt: self.update_ui_text(self.display_log))
        except Exception:
            pass

    def network_scanner_engine(self):
        base_subnet, my_ip = self.get_local_subnet()
        
        self.inventory_data[my_ip] = {
            "IP": my_ip, "Name": "Host System (This Mac)", "MAC": "LOCAL_INTERFACE", "Ports": "N/A"
        }
        
        self.display_log = f"Scanning Target Subnet Matrix: {base_subnet}0/24\n\nIdentified Assets:\n"
        Clock.schedule_once(lambda dt: self.update_ui_text(self.display_log))

        threads = []
        for host in range(1, 255):
            target_ip = f"{base_subnet}{host}"
            if target_ip == my_ip:
                continue
            
            t = threading.Thread(target=self.ping_single_host, args=(target_ip, base_subnet), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if self.scan_active:
            self.scan_active = False
            self.display_log += f"\n🚨 STATUS: COMPLETED 🚨\nTotal Active System Assets Captured: {len(self.inventory_data)}\nClick 'STOP & EXPORT' to save data."
            Clock.schedule_once(lambda dt: self.update_ui_text(self.display_log))

    def stop_and_export(self, instance):
        self.scan_active = False
        if not self.inventory_data:
            self.start_btn.disabled = False
            self.stop_btn.disabled = True
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"omniscan_vendor_report_{timestamp}.csv"

        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["IP", "Name", "MAC", "Ports"])
                writer.writeheader()
                for ip, details in self.inventory_data.items():
                    writer.writerow(details)

            full_path = os.path.abspath(filename)
            self.status_label.text = f"🛡️ DATA DOWNLOADED COPIED!\n\nSaved spreadsheet:\n📄 {filename}\n\nPath:\n{full_path}"
        except Exception as e:
            self.status_label.text = f"Error printing assessment sheet: {str(e)}"

        self.start_btn.disabled = False
        self.stop_btn.disabled = True

if __name__ == "__main__":
    OmniScanApp().run()

