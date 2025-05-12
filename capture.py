import logging
from scapy.all import sniff, IP
from PyQt5.QtCore import QThread, pyqtSignal
from time import sleep

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(object)  # Signal to send packets to the main thread

    def __init__(self):
        super().__init__()
        self._running = True  # A flag to control the capture thread's running state

    def run(self):
        try:
            logger.debug("Starting packet capture")
            # Start sniffing packets
            sniff(prn=self.packet_callback, store=0, filter="ip", stop_filter=self.should_stop)
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")

    def packet_callback(self, packet):
        try:
            if IP in packet: 
                self.packet_received.emit(packet)  
                sleep(0.1)  # Slow down the packet capture to avoid overwhelming the UI and crashes
        except Exception as e:
            logger.error(f"Error in packet_callback: {e}")

    def stop(self):
        """Stop the capture thread."""
        logger.debug("Stopping packet capture")
        self._running = False
        self.wait(1000)  # Wait for the thread to finish properly
        if self.isRunning():
            logger.warning("Thread did not stop gracefully, forcing termination")
            self.terminate()

    def should_stop(self, packet):
        """Condition to stop sniffing."""
        return not self._running
