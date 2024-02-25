import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import socket

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")

        # Host Entry
        self.host_label = tk.Label(root, text="Target Host:")
        self.host_label.pack()
        self.host_entry = tk.Entry(root)
        self.host_entry.pack()

        # Port Range Entry
        self.port_range_label = tk.Label(root, text="Port Range (e.g., 80-100):")
        self.port_range_label.pack()
        self.port_range_entry = tk.Entry(root)
        self.port_range_entry.pack()

        # Scan Button
        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack()

        # Results Area
        self.results_area = scrolledtext.ScrolledText(root, height=10)
        self.results_area.pack()

    def scan_target(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                self.results_area.insert(tk.END, f"Port {port}: Open\n")
            sock.close()
        except Exception as e:
            self.results_area.insert(tk.END, f"Error scanning port {port}: {e}\n")

    def start_scan(self):
        host = self.host_entry.get()
        port_range = self.port_range_entry.get().split('-')
        if len(port_range) == 2:
            start_port, end_port = int(port_range[0]), int(port_range[1])
            self.results_area.delete(1.0, tk.END)  # Clear previous results
            self.results_area.insert(tk.END, f"Scanning target {host} from port {start_port} to {end_port}\n")
            for port in range(start_port, end_port + 1):
                self.scan_target(host, port)
        else:
            self.results_area.insert(tk.END, "Invalid port range. Please use the format start-end (e.g., 80-100).\n")

    def start_scan_thread(self):
        scan_thread = Thread(target=self.start_scan)
        scan_thread.daemon = True
        scan_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()
import socket

def port_scan(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def main():
    while True:
        print("\nSimple Port Scanner")
        print("1. Scan ports on a host")
        print("2. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            host = input("Enter the host IP to scan: ")
            start_port = int(input("Enter the start port: "))
            end_port = int(input("Enter the end port: "))

            print(f"\nScanning ports {start_port}-{end_port} on {host}...")
            open_ports = port_scan(host, start_port, end_port)

            if open_ports:
                print("Open Ports:")
                for port in open_ports:
                    print(f"Port {port} is open")
            else:
                print("No open ports found.")
        elif choice == "2":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
