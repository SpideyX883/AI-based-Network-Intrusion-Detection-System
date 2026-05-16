# core/file_monitor.py
import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileMonitor:
    def __init__(self, file_queue, watch_dir, controller):
        self.file_queue = file_queue
        self.watch_dir = watch_dir
        self.controller = controller
        self.observer = Observer()
        self.logger = logging.getLogger('FileMonitor')
        
    def start(self):
        """Start monitoring the download directory"""
        event_handler = FileEventHandler(self.file_queue, self.controller)
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()
        self.logger.info(f"Started monitoring {self.watch_dir}")

    def stop(self):
        """Stop the file monitoring"""
        self.observer.stop()
        self.observer.join()
        self.logger.info("File monitoring stopped")

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, file_queue, controller):
        self.file_queue = file_queue
        self.controller = controller
        self.logger = logging.getLogger('FileEventHandler')

    def on_created(self, event):
        """Handle new file creation events"""
        if not event.is_directory:
            self.logger.info(f"New file detected: {event.src_path}")
            self.controller.handle_downloaded_file(event.src_path)
