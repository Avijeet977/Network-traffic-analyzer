import threading
import sqlite3
import csv
from scapy.all import sniff
import tkinter as tk
from tkinter import ttk

# -------------------------
# Custom Queue Data Structure
# -------------------------

class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class PacketQueue:
    def __init__(self):
        self.front = None
        self.rear = None
        self.lock = threading.Lock()

    def enqueue(self, data):
        with self.lock:
            node = Node(data)
            if not self.rear:
                self.front = self.rear = node
            else:
                self.rear.next = node
                self.rear = node

    def dequeue(self):
        with self.lock:
            if not self.front:
                return None
            temp = self.front
            self.front = temp.next
            if not self.front:
                self.rear = None
            return temp.data

# -------------------------
# Database Manager
# -------------------------

class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect("packets.db")
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            length INTEGER
        )
        """)
        self.conn.commit()

    def insert_packet(self, protocol, src, dst, length):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO packets (protocol, source_ip, destination_ip, length) VALUES (?, ?, ?, ?)",
                       (protocol, src, dst, length))
        self.conn.commit()

# -------------------------
# Packet Capture
# -------------------------

class PacketCapture:
    def __init__(self, queue, db):
        self.queue = queue
        self.db = db
        self.running = False

    def start_capture(self):
        self.running = True
        threading.Thread(target=self.capture).start()

    def stop_capture(self):
        self.running = False

    def process_packet(self, packet):
        if packet.haslayer("IP"):
            protocol = packet.summary().split()[0]
            src = packet["IP"].src
            dst = packet["IP"].dst
            length = len(packet)
            self.queue.enqueue((protocol, src, dst, length))
            self.db.insert_packet(protocol, src, dst, length)

    def capture(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.running)

# -------------------------
# GUI
# -------------------------

class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")

        self.queue = PacketQueue()
        self.db = DatabaseManager()
        self.capture = PacketCapture(self.queue, self.db)

        self.setup_ui()

    def setup_ui(self):
        self.start_btn = tk.Button(self.root, text="Start Capture", command=self.capture.start_capture)
        self.start_btn.pack()

        self.stop_btn = tk.Button(self.root, text="Stop Capture", command=self.capture.stop_capture)
        self.stop_btn.pack()

        self.tree = ttk.Treeview(self.root, columns=("Protocol", "Source", "Destination", "Length"), show="headings")
        for col in ("Protocol", "Source", "Destination", "Length"):
            self.tree.heading(col, text=col)
        self.tree.pack()

        self.update_ui()

    def update_ui(self):
        packet = self.queue.dequeue()
        if packet:
            self.tree.insert("", tk.END, values=packet)
        self.root.after(100, self.update_ui)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzerGUI(root)
    root.mainloop()