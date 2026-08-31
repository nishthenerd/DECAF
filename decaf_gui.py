import os
import hashlib
import mimetypes
import threading
import queue
import time
import platform
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# =================================================================================
# UTILITY FUNCTIONS
# =================================================================================

def read_file_in_chunks(file_path, chunk_size=8192):
    """Generator to read large files in chunks to save memory."""
    try:
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(chunk_size)
                if not data:
                    break
                yield data
    except Exception as e:
        print(f"[ERROR] Reading file {file_path}: {e}")
        yield b''

def compute_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        for chunk in read_file_in_chunks(file_path):
            sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Hashing file {file_path}: {e}")
        return None

def get_file_metadata(file_path):
    """Get metadata such as size, creation time, modification time."""
    try:
        stats = os.stat(file_path)
        size = stats.st_size
        ctime = datetime.fromtimestamp(stats.st_ctime)
        mtime = datetime.fromtimestamp(stats.st_mtime)
        return {'size_bytes': size, 'created': ctime, 'modified': mtime}
    except Exception as e:
        print(f"[ERROR] Getting metadata for {file_path}: {e}")
        return {}

def categorize_file_type(file_path):
    """Return a high-level category for the file based on MIME type."""
    try:
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type is None:
            return "Unknown"
        if mime_type.startswith('image'):
            return "Image"
        if mime_type.startswith('video'):
            return "Video"
        if mime_type.startswith('audio'):
            return "Audio"
        if mime_type == 'application/pdf':
            return "PDF Document"
        if mime_type.startswith('text'):
            return "Text Document"
        if mime_type == 'application/x-msdownload' or mime_type == 'application/x-executable':
            return "Executable"
        if mime_type.startswith('application'):
            return "Application File"
        return "Other"
    except Exception as e:
        print(f"[ERROR] Categorizing file {file_path}: {e}")
        return "Unknown"

def is_suspicious_file(file_path):
    """Basic heuristic: flag files with suspicious extensions."""
    suspicious_exts = ['.exe', '.dll', '.bat', '.js', '.vbs', '.scr', '.pif', '.com', '.msi', '.cmd', '.ps1']
    ext = os.path.splitext(file_path)[1].lower()
    if ext in suspicious_exts:
        return True
    return False

def simulate_malware_signature_check(file_path):
    """Fake malware signature check with dummy suspicious patterns."""
    suspicious_patterns = ['MZ', 'PE', 'This program cannot be run', 'virus', 'malware']
    try:
        with open(file_path, 'rb') as f:
            content = f.read(2048).decode(errors='ignore').lower()
            for pattern in suspicious_patterns:
                if pattern.lower() in content:
                    return True, f"Pattern '{pattern}' found"
        return False, "No suspicious signatures"
    except Exception as e:
        return False, f"Error reading file: {e}"

def extract_files_from_usb(usb_path):
    """Recursively find all files in USB mount directory."""
    all_files = []
    try:
        for root, dirs, files in os.walk(usb_path):
            for file in files:
                full_path = os.path.join(root, file)
                all_files.append(full_path)
        return all_files
    except Exception as e:
        print(f"[ERROR] Extracting files from USB path {usb_path}: {e}")
        return []

def log_event(log_file, message):
    """Append timestamped message to a log file."""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_file, 'a') as log:
            log.write(f"{timestamp} - {message}\n")
    except Exception as e:
        print(f"[ERROR] Logging event: {e}")

# =================================================================================
# PDF REPORT GENERATION
# =================================================================================

def generate_pdf_report(device_info, file_details, malware_results, report_path):
    """Generate a detailed forensic PDF report."""
    try:
        c = canvas.Canvas(report_path, pagesize=letter)
        width, height = letter
        
        c.setFont("Helvetica-Bold", 22)
        c.drawString(50, height - 50, "DECAF - Digital Evidence Collection & Analysis Framework")
        
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 80, f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, height - 100, f"Target device directory: {device_info}")
        c.line(50, height - 110, width - 50, height - 110)
        
        y = height - 130
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Files Analyzed and Findings:")
        y -= 25
        
        c.setFont("Helvetica", 10)
        if not file_details:
            c.drawString(60, y, "No files were extracted or analyzed.")
            y -= 20
        else:
            for filepath, metadata in file_details.items():
                if y < 100:
                    c.showPage()
                    y = height - 50
                c.drawString(60, y, f"File: {filepath}")
                y -= 15
                c.drawString(70, y, f"Type: {metadata.get('file_type', 'Unknown')}")
                y -= 15
                c.drawString(70, y, f"Size (bytes): {metadata.get('size_bytes', 'N/A')}")
                y -= 15
                c.drawString(70, y, f"Created: {metadata.get('created', 'N/A')}")
                y -= 15
                c.drawString(70, y, f"Modified: {metadata.get('modified', 'N/A')}")
                y -= 15
                c.drawString(70, y, f"SHA256: {metadata.get('sha256', 'N/A')}")
                y -= 15
                malware_flag, malware_msg = malware_results.get(filepath, (False, "Not scanned"))
                c.drawString(70, y, f"Malware Scan: {malware_msg}")
                y -= 30
        
        c.save()
        print(f"[INFO] Report saved at: {report_path}")
    except Exception as e:
        print(f"[ERROR] Generating report: {e}")

# =================================================================================
# MULTI-THREADING WORKER CLASSES FOR FILE ANALYSIS
# =================================================================================

class FileAnalyzer(threading.Thread):
    """Thread to analyze files independently."""
    def __init__(self, file_queue, result_queue):
        threading.Thread.__init__(self)
        self.file_queue = file_queue
        self.result_queue = result_queue
        self.daemon = True
    
    def run(self):
        while True:
            try:
                file_path = self.file_queue.get(timeout=3)
                print(f"[DEBUG] Analyzing {file_path}")
                
                metadata = get_file_metadata(file_path)
                metadata['file_type'] = categorize_file_type(file_path)
                metadata['sha256'] = compute_sha256(file_path)
                
                malware_flag, malware_msg = False, "Not scanned"
                if is_suspicious_file(file_path):
                    malware_flag, malware_msg = simulate_malware_signature_check(file_path)
                
                result = {
                    'file_path': file_path,
                    'metadata': metadata,
                    'malware_flag': malware_flag,
                    'malware_msg': malware_msg
                }
                
                self.result_queue.put(result)
                self.file_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                print(f"[ERROR] Exception in FileAnalyzer thread: {e}")
                self.file_queue.task_done()
                continue

# =================================================================================
# GUI APPLICATION
# =================================================================================

class DECAFApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DECAF Forensic Toolkit")
        self.root.geometry("750x600")
        
        # Widgets
        self.status_label = tk.Label(root, text="Select USB directory to analyze.", font=("Arial", 12), wraplength=700)
        self.status_label.pack(pady=10)
        
        self.select_usb_btn = tk.Button(root, text="Select USB Directory", command=self.select_usb_directory, width=30)
