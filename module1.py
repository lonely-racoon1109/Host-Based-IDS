import os
import time
import subprocess

class FileSource:
    def __init__(self, path):
        self.path = path
        self.fd = None
        self.inode = None

    def validate_source(self):
        print(f"Validating : {self.path}")
        if not self.path:
            raise ValueError("Empty path provided.")
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"[ERROR] {self.path} does not exist")
            
        if not os.access(self.path, os.R_OK):
            raise PermissionError(f"[ERROR] No read permission: {self.path}")

        print(f"[OK] Valid source: {self.path}")
        

    def initialize(self):
        self.validate_source()

        try:
            self.fd = open(self.path, "r")
            self.inode = os.stat(self.path).st_ino
            print(f"[OPENED] {self.path} (inode={self.inode})")

        except Exception as e:
            print(f"[ERROR] Failed to open {self.path}: {e}")
            raise

    def check_rotation(self):
        try:
            current_inode = os.stat(path).st_ino
        except FileNotFoundError:
            print(f"[WARNING] {path} temporarily missing...")
            return 

        if current_inode != self.inode:
            print(f"[ROTATION DETECTED] {self.path}")

            try:
                self.fd.close()
            except Exception:
                pass

            try:
                self.fd = open(self.path, "r")
                self.inode = current_inode
                print(f"[REOPENED] {self.path} (new inode={self.inode})")
            except Exception as e:
                print(f"[ERROR] Failed to reopen {self.path}: {e}")

    def get_name(self):
        return f"FileSource({self.path})"

    def get_handle(self):
        return self.fd

class JournalSource:
    def __init__(self):
        self.process = None

    def initialize(self):
        print("Journalctl starting...")
        self.process = subprocess.Popen(
            ["journalctl", "-f", "-o", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        print("[OPENED] JOURNAL")
    
    def check_rotation(self):
        pass

    def get_name(self):
        return "JournalSource(systemd-journal)"

    def get_handle(self):
        return self.process.stdout

class LogSourceManager:
    def __init__(self, sources):
        self.sources = sources

    def initialize_sources(self):
        for source in self.sources:
            source.initialize()

    def check_sources(self):
        for source in self.sources:
            source.check_rotation()

    def get_names(self):
        return [source.get_name() for source in self.sources]

    def get_handle(self):
        return [source.get_handle() for source in self.sources]




