import sys
import logging
import csv
import traceback
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QTableWidget, QTableWidgetItem, QLabel, QStatusBar, 
                           QFileDialog, QMessageBox)
from PyQt5.QtCore import pyqtSignal, QThread, QTimer
from scapy.all import ARP, Ether, srp, IP
from capture import PacketCaptureThread  

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Network Scanning Functions
def get_devices():
    devices = []
    ip_range = '192.168.91.0/24' #ensure this is set to users subnet ip addr
    
    try:
        logger.debug(f"Scanning IP range: {ip_range}")
        # makes an arp request
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Sends packet and captures responses
        logger.debug("Sending ARP broadcast")
        # Increase timeout and verbose for easier debugging
        result = srp(packet, timeout=5, verbose=1, retry=2)[0]
        
        logger.debug(f"Received {len(result)} responses")
        for sent, received in result:
            # Extract device name (using IP as placeholder)
            device_name = f"Device at {received.psrc}"
            device_info = {
                'Device': device_name,
                'IP Address': received.psrc,
                'MAC Address': received.hwsrc
            }
            devices.append(device_info)
            logger.debug(f"Found device: {device_name} at {received.psrc} ({received.hwsrc})")
    except Exception as e:
        logger.error(f"Error in get_devices: {e}")
        import traceback
        logger.error(traceback.format_exc())
    
    logger.info(f"Found {len(devices)} devices on the network")
    # Force at least one dummy device for testing if no devices found - error checking/handling
    if not devices:
        logger.warning("No devices found, adding localhost for testing")
        devices.append({
            'Device': 'Localhost (This Device)',
            'IP Address': '127.0.0.1',
            'MAC Address': '00:00:00:00:00:00'
        })
    
    return devices


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Network Analyzer')
        self.setGeometry(100, 100, 800, 600)

        main_widget = QWidget(self)
        main_layout = QVBoxLayout()

        # Toolbar with buttons
        toolbar_layout = QHBoxLayout()
        start_button = QPushButton("Start Capture")
        stop_button = QPushButton("Stop Capture")
        refresh_button = QPushButton("Refresh Devices")
        export_button = QPushButton("Export to CSV")  
        
        toolbar_layout.addWidget(start_button)
        toolbar_layout.addWidget(stop_button)
        toolbar_layout.addWidget(refresh_button)
        toolbar_layout.addWidget(export_button) 
        
        # Devices Table
        device_label = QLabel("Devices on Network")
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["Device", "IP Address", "MAC Address"])
        # Set table properties for better display
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Captured Packets Table
        packet_label = QLabel("Captured Packets")
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Size"])
        # Set table properties for better display
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        main_layout.addLayout(toolbar_layout)
        main_layout.addWidget(device_label)
        main_layout.addWidget(self.device_table)
        main_layout.addWidget(packet_label)
        main_layout.addWidget(self.packet_table)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Create and connect the packet capture thread
        self.capture_thread = PacketCaptureThread()
        self.capture_thread.packet_received.connect(self.update_packet_table)
        
        # Connect buttons to functions
        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)
        refresh_button.clicked.connect(self.refresh_devices)
        export_button.clicked.connect(self.export_to_csv)

        self.packets = []  #Store packets for export
        
        #Load devices on startup with a slight delay
        #This allows the UI to fully initialize before scanning
        QTimer.singleShot(1000, self.refresh_devices)

    def start_capture(self):
        try:
            self.status_bar.showMessage("Capturing packets...")
            self.capture_thread.start()
        except Exception as e:
            logger.error(f"Error in start_capture: {e}")
            self.status_bar.showMessage(f"Error starting capture: {str(e)}")

    def stop_capture(self):
        try:
            if self.capture_thread.isRunning():
                self.capture_thread.stop()
                self.status_bar.showMessage("Capture stopped")
            else:
                self.status_bar.showMessage("No capture in progress")
        except Exception as e:
            logger.error(f"Error in stop_capture: {e}")
            self.status_bar.showMessage(f"Error stopping capture: {str(e)}")

    def refresh_devices(self):
        try:
            self.status_bar.showMessage("Scanning for devices...")
            logger.info("Starting network scan")
            
            # Clear the existing device table
            self.device_table.setRowCount(0)
            
            # Get devices from the network
            devices = get_devices()
            
            # Update device table with the results
            if devices:
                # Pre-set the row count to match number of devices
                self.device_table.setRowCount(len(devices))
                
                for row, device in enumerate(devices):
                    # Create QTableWidgetItem objects for each cell
                    device_item = QTableWidgetItem(device['Device'])
                    ip_item = QTableWidgetItem(device['IP Address'])
                    mac_item = QTableWidgetItem(device['MAC Address'])
                    
                    # Set items in the table
                    self.device_table.setItem(row, 0, device_item)
                    self.device_table.setItem(row, 1, ip_item)
                    self.device_table.setItem(row, 2, mac_item)
                    
                    logger.debug(f"Added device to table: {device['Device']}, {device['IP Address']}, {device['MAC Address']}")
                
                # Resize columns to content
                self.device_table.resizeColumnsToContents()
                
                self.status_bar.showMessage(f"Found {len(devices)} devices on the network")
                logger.info(f"Completed scan, found {len(devices)} devices")
            else:
                self.status_bar.showMessage("No devices found on the network")
                logger.warning("No devices found in scan results")
                
        except Exception as e:
            logger.error(f"Error in refresh_devices: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.status_bar.showMessage(f"Error refreshing devices: {str(e)}")

    def update_packet_table(self, packet):
        try:
            # Add packet to table
            row_position = self.packet_table.rowCount()
            self.packet_table.insertRow(row_position)
            
            if IP in packet:
                self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(packet.time)))
                self.packet_table.setItem(row_position, 1, QTableWidgetItem(packet[IP].src))
                self.packet_table.setItem(row_position, 2, QTableWidgetItem(packet[IP].dst))
                self.packet_table.setItem(row_position, 3, QTableWidgetItem(str(packet[IP].proto)))
                self.packet_table.setItem(row_position, 4, QTableWidgetItem(str(len(packet))))
                
                # Save packet for export
                self.packets.append(packet)
                
        except Exception as e:
            logger.error(f"Error in update_packet_table: {e}")

    def export_to_csv(self):
        # Open a file dialog to save the CSV
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        
        if file_path:
            try:
                # Create a CSV file and write packet data
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Size"])  # Write headers
                    
                    # Write the packet details
                    for packet in self.packets:
                        if IP in packet:
                            writer.writerow([
                                str(packet.time), 
                                packet[IP].src, 
                                packet[IP].dst, 
                                str(packet[IP].proto), 
                                str(len(packet))
                            ])
                
                self.status_bar.showMessage(f"CSV exported successfully to {file_path}")
            except Exception as e:
                logger.error(f"Error exporting CSV: {e}")
                self.status_bar.showMessage(f"Failed to export CSV: {str(e)}")

# Mainloop
if __name__ == '__main__':
    try:
        app = QApplication(sys.argv)
        
        # Check if scapy is installed and has required permissions
        try:
            # Tests to create an ARP packet
            test_packet = ARP()
            logger.debug("Successfully imported scapy modules")
        except Exception as e:
            logger.critical(f"Error initializing scapy: {e}")
            QMessageBox.critical(None, "Error", 
                              "Scapy initialization failed. This application requires administrator/root privileges.\n\n"
                              f"Error: {str(e)}")
            sys.exit(1)
            
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.error(traceback.format_exc())
        QMessageBox.critical(None, "Fatal Error", f"An unexpected error occurred:\n{str(e)}")
        sys.exit(1)