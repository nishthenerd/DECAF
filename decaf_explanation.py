        # Button to select USB directory (simulated or real folder)
        self.select_usb_btn = tk.Button(root, text="Select USB Directory", command=self.select_usb_directory, width=30)
        self.select_usb_btn.pack(pady=5)

        # Button to generate the forensic PDF report
        self.report_btn = tk.Button(root, text="Generate PDF Report", command=self.generate_report, width=30)
        self.report_btn.pack(pady=5)

        # Text area to display log messages or file status
        self.output_area = scrolledtext.ScrolledText(root, width=90, height=25, font=("Courier", 9))
        self.output_area.pack(pady=10)

        # Internal state to store paths and analysis results
        self.selected_path = None              # Directory selected for analysis
        self.file_metadata = dict()            # Stores metadata for each file
        self.malware_results = dict()          # Stores malware scan results for each file

    def select_usb_directory(self):
        """Open a file dialog to select a USB or any folder and start file analysis."""
        path = filedialog.askdirectory(title="Select USB Drive or Folder to Scan")
        if not path:
            return
        
        self.status_label.config(text=f"Selected: {path}")
        self.selected_path = path
        self.output_area.insert(tk.END, f"\n[INFO] USB Directory Selected: {path}\n")
        
        self.analyze_files_in_directory(path)

    def analyze_files_in_directory(self, path):
        """Scan and analyze files using multithreaded processing."""
        self.output_area.insert(tk.END, f"[INFO] Starting analysis on: {path}\n")
        
        all_files = extract_files_from_usb(path)  # Recursively collect all file paths
        if not all_files:
            self.output_area.insert(tk.END, "[WARNING] No files found in the selected directory.\n")
            return

        file_q = queue.Queue()
        result_q = queue.Queue()

        # Enqueue all files for processing
        for file in all_files:
            file_q.put(file)

        # Start multiple threads to analyze files concurrently
        num_threads = min(6, len(all_files))
        threads = [FileAnalyzer(file_q, result_q) for _ in range(num_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Collect the results from the threads
        while not result_q.empty():
            result = result_q.get()
            file_path = result['file_path']
            self.file_metadata[file_path] = result['metadata']
            self.malware_results[file_path] = (result['malware_flag'], result['malware_msg'])

            # Display findings in GUI log
            self.output_area.insert(tk.END, f"\n[RESULT] File: {file_path}\n")
            self.output_area.insert(tk.END, f"         Type: {result['metadata'].get('file_type', 'Unknown')}\n")
            self.output_area.insert(tk.END, f"         Malware Scan: {result['malware_msg']}\n")

        self.output_area.insert(tk.END, "\n[INFO] Analysis complete.\n")

    def generate_report(self):
        """Trigger PDF report generation."""
        if not self.selected_path or not self.file_metadata:
            messagebox.showwarning("No Data", "Please analyze files before generating a report.")
            return
        
        report_filename = f"DECAF_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        report_path = os.path.join(os.getcwd(), report_filename)

        generate_pdf_report(self.selected_path, self.file_metadata, self.malware_results, report_path)

        self.output_area.insert(tk.END, f"\n[INFO] Report saved to: {report_path}\n")
        messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")

# =================================================================================
# MAIN FUNCTION TO START GUI
# =================================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = DECAFApp(root)
    root.mainloop()
