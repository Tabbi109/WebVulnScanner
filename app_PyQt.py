import sys
import threading
import os 
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QLabel, QTextEdit, QMessageBox, QFrame 
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject

# Import your scanner logic module
import scanner_logic 

# --- Signal class for thread-safe GUI updates ---
class ScannerSignals(QObject):
    update_progress = pyqtSignal(str)
    scan_finished = pyqtSignal(list, list, list, list, list)
    error_occurred = pyqtSignal(str)
    enable_buttons = pyqtSignal(bool)


# --- Main GUI Application Class ---
class WebScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Vulnerability Scanner (PyQt6)")
        self.setGeometry(100, 100, 900, 700)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # --- Input Widgets ---
        self.input_frame = QFrame(self.central_widget) 
        self.input_layout = QHBoxLayout(self.input_frame) 

        self.url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., http://testphp.vulnweb.com/")
        self.url_input.setText("http://testphp.vulnweb.com/") 

        self.depth_label = QLabel("Max Depth:")
        self.depth_input = QLineEdit()
        self.depth_input.setFixedWidth(50) 
        self.depth_input.setText("1") 

        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan_threaded) 

        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False) 

        self.input_layout.addWidget(self.url_label)
        self.input_layout.addWidget(self.url_input)
        self.input_layout.addWidget(self.depth_label)
        self.input_layout.addWidget(self.depth_input)
        self.input_layout.addWidget(self.start_button)
        self.input_layout.addWidget(self.stop_button)
        
        self.main_layout.addWidget(self.input_frame) 

        # --- Output Text Area ---
        self.output_text_area = QTextEdit()
        self.output_text_area.setReadOnly(True) 
        self.output_text_area.setText("Enter Target URL and Max Depth, then click 'Start Scan'.\n")
        self.main_layout.addWidget(self.output_text_area) 

        # --- Connect signals from the scanner thread to GUI slots (methods) ---
        self.signals = ScannerSignals()
        self.signals.update_progress.connect(self.update_output)
        self.signals.scan_finished.connect(self.display_final_results)
        self.signals.error_occurred.connect(self.show_error_message)
        self.signals.enable_buttons.connect(self._set_button_states)

        self.scan_thread = None 
        self.stop_event = None  

    def _set_button_states(self, enable_start):
        """Helper slot to enable/disable buttons safely from any thread."""
        self.start_button.setEnabled(enable_start)
        self.stop_button.setEnabled(not enable_start) 

    def update_output(self, message):
        """Appends a message to the output text area. This method is a SLOT."""
        self.output_text_area.append(message)
        self.output_text_area.verticalScrollBar().setValue(self.output_text_area.verticalScrollBar().maximum())

    def start_scan_threaded(self):
        """Method called when the Start Scan button is clicked. It validates input and starts the scan in a separate thread."""
        target_url = self.url_input.text().strip()
        try:
            max_depth = int(self.depth_input.text().strip())
            if max_depth < 0:
                raise ValueError("Max Depth cannot be negative.")
        except ValueError as e:
            QMessageBox.critical(self, "Invalid Input", f"Invalid Max Depth: {e}\nPlease enter a non-negative integer.")
            return

        if not target_url:
            QMessageBox.critical(self, "Invalid Input", "Target URL cannot be empty.")
            return

        self.output_text_area.clear()
        self.output_text_area.append(f"Initiating scan for: {target_url} (Depth: {max_depth})\n")
        
        self.signals.enable_buttons.emit(False) 

        self.stop_event = threading.Event() 

        self.scan_thread = threading.Thread(
            target=self._run_scan_logic, 
            args=(target_url, max_depth, self.signals, self.stop_event)
        )
        self.scan_thread.start()

    def _run_scan_logic(self, target_url, max_depth, signals, stop_event):
        """
        This method runs in the separate thread (background).
        It calls the scanner_logic's crawl_and_scan function.
        All communication back to the GUI is done by emitting signals.
        """
        # Create a single handler object to pass to scanner_logic
        # This handler has the update_text method that scanner_logic expects.
        class ScannerCallbackHandler:
            def update_text(self, msg):
                signals.update_progress.emit(msg)

        handler = ScannerCallbackHandler() # Create an instance of the handler

        try:
            crawled, params, xss_vulnerable, sqli_vulnerable, sensitive_files = \
                scanner_logic.crawl_and_scan(target_url, max_depth, 
                                            progress_callback=handler, # Pass the handler object here
                                            stop_event=stop_event) 
            
            if not stop_event.is_set():
                signals.scan_finished.emit(crawled, params, xss_vulnerable, sqli_vulnerable, sensitive_files)

        except Exception as e:
            signals.error_occurred.emit(f"An unexpected error occurred during scan: {e}")
        finally:
            signals.enable_buttons.emit(True) 


    def stop_scan(self):
        """Method called when the Stop Scan button is clicked. It signals the background thread to stop."""
        if self.scan_thread and self.scan_thread.is_alive() and self.stop_event:
            self.stop_event.set() # Signal the thread to stop
            self.update_output("Stopping scan...")
            self.stop_button.setEnabled(False) # Disable stop button immediately after clicking

    def display_final_results(self, crawled, params, xss_vulnerable, sqli_vulnerable, sensitive_files):
        """Displays the final summary and lists of found items. This method is a SLOT."""
        self.update_output("\n" + "="*70)
        self.update_output("Scan complete!")
        self.update_output(f"Total unique URLs crawled (within domain): {len(crawled)}")
        self.update_output(f"Total unique parameterized URLs found (within domain): {len(params)}")
        self.update_output(f"Total unique URLs potentially XSS vulnerable: {len(xss_vulnerable)}")
        self.update_output(f"Total unique URLs potentially SQL Injection vulnerable: {len(sqli_vulnerable)}")
        self.update_output(f"Total unique URLs potentially Sensitive File/Directory vulnerable: {len(sensitive_files)}")

        self.update_output("\n--- Crawled URLs (within domain): ---")
        if crawled:
            for url in sorted(list(crawled)):
                self.update_output(f"  - {url}")
        else:
            self.update_output("  No URLs crawled within the specified depth and domain.")

        self.update_output("\n--- Parameterized URLs Found (within domain): ---")
        if params:
            for url in sorted(list(params)):
                self.update_output(f"  - {url}")
        else:
            self.update_output("  No parameterized URLs found within the specified depth and domain.")
        
        self.update_output("\n--- Potentially XSS Vulnerable URLs Found: ---")
        if xss_vulnerable:
            for url in sorted(list(xss_vulnerable)):
                self.update_output(f"  [!!!] XSS - {url}")
        else:
            self.update_output("  No XSS vulnerabilities detected with the basic check.")

        self.update_output("\n--- Potentially SQL Injection Vulnerable URLs Found: ---")
        if sqli_vulnerable:
            for url in sorted(list(sqli_vulnerable)):
                self.update_output(f"  [!!!] SQLi - {url}")
        else:
            self.update_output("  No SQL Injection vulnerabilities detected with the basic check.")

        self.update_output("\nPotentially Sensitive File/Directory Vulnerable URLs Found:")
        if sensitive_files:
            for url in sorted(list(sensitive_files)):
                self.update_output(f"  [!!!] Sensitive File - {url}")
        else:
            self.update_output("  No Sensitive File/Directory vulnerabilities detected with the basic check.")

    def show_error_message(self, message):
        """Displays a critical error message using a QMessageBox. This method is a SLOT."""
        QMessageBox.critical(self, "Scan Error", message)
        self.update_output(message)


# --- Main Application Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv) 

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        qss_file_path = os.path.join(current_dir, "styles.qss")

        with open(qss_file_path, "r") as f:
            _style = f.read()
            app.setStyleSheet(_style) 
    except FileNotFoundError:
        print(f"Warning: styles.qss not found at {qss_file_path}. Running without custom style.")
    except Exception as e:
        print(f"Error loading stylesheet: {e}. Running without custom style.")

    window = WebScannerApp()     
    window.show()                
    sys.exit(app.exec())