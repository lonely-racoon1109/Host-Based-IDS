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
            print("[SKIP] Empty path")
            return False

        if not os.path.exists(self.path):
            print(f"[SKIP] File does not exist: {self.path}")
            return False

        if not os.access(self.path, os.R_OK):
            print(f"[SKIP] No read permission: {self.path}")
            return False

        print(f"[OK] Valid source: {self.path}")
        return True
        

    def initialize(self):
        if not self.validate_source():
            self.fd = None
            return 

        try:
            self.fd = open(self.path, "r")
            self.inode = os.stat(self.path).st_ino
            print(f"[OPENED] {self.path} (inode={self.inode})")

        except Exception as e:
            print(f"[ERROR] Failed to open {self.path}: {e}")
            self.fd = None

    def check_rotation(self):
        try:
            current_inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            print(f"[WARNING] {self.path} temporarily missing...")
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
            ["journalctl", "-f", "-o", "short", "-u", "sshd", "-u", "sudo", "-p", "info..alert"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=0
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
        active_sources = []

        for source in self.sources:
            source.initialize()
            if source.get_handle() is not None:
                active_sources.append(source)

        self.sources = active_sources

    def check_sources(self):
        for source in self.sources:
            source.check_rotation()

    def get_names(self):
        return [source.get_name() for source in self.sources]

    def get_handle(self):
        return [source.get_handle() for source in self.sources]




