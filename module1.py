import os
import time
import subprocess

class FileSource:
    def __init__(self, file_paths):
        self.file_paths = file_paths
        self.valid_paths = []
        self.sources = {}

    def validate_sources(self):
        print("Validating log sources...")
        for path in self.file_paths:
            if not path:
                continue
            if not os.path.exists(path):
                print(f"[WARNING] {path} does not exist. Skipping.")
                continue
            if not os.access(path, os.R_OK):
                print(f"[WARNING] No read permission: {path} — Skipping.")
                continue
            print(f"[OK] Valid source: {path}")
            self.valid_paths.append(path)
        
        if not self.valid_paths:
            raise RuntimeError("No valid file log sources available. IDS cannot start.")

    def initialize(self):
        self.validate_sources()
        for path in self.valid_paths:
            try:
                fd = open(path, "r")
                inode = os.stat(path).st_ino

                self.sources[path] = {
                    "fd" : fd,
                    "inode" : inode
                }
                print(f"[OPENED] {path} (inode={inode})")
            except Exception as e:
                print(f"[ERROR] Failed to open {path}: {e}")

    def check_rotation(self):
        for path in self.sources:
            try:
                current_inode = os.stat(path).st_ino
            except FileNotFoundError:
                print(f"[WARNING] {path} temporarily missing...")
                continue
            if current_inode != self.sources[path]["inode"]:
                print(f"[ROTATION DETECTED] {path}")

                self.sources[path]["fd"].close()

                try:
                    new_fd = open(path, "r")
                    self.sources[path]["fd"] = new_fd
                    self.sources[path]["inode"] = current_inode
                    print(f"[REOPENED] {path} (new inode={current_inode})")
                except Exception as e:
                    print(f"[ERROR] Failed to reopen {path}: {e}")

    def get_names(self):
        for source in self.sources:
            return f"FileSource({self.sources[source]["fd"]})"

    def get_handle(self):
        return [data["fd"] for data in self.sources.values()]

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

    def get_names(self):
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
        for source in self.sources:
            source.get_names()

    def get_handle(self):
        return [source.get_handle() for source in self.sources]

if __name__ == "__main__":
    file_source = FileSource([" ", " "])
    journal_source = JournalSource()

    manager = LogSourceManager([file_source, journal_source])
    
    manager.initialize_sources()

    print("-----------------------------------------------")
    print("Sources initialized.\n")
    print(manager.sources[0])
    print(manager.sources[1])
    print("-----------------------------------------------")
    
    for source in manager.sources:
        print(source.get_names(), end="\n\n")
        print(f"Handle: {source.get_handle()}")
        print("-----------------------------------------------")

    print("Rotation check....")
    while True:
        try:
            manager.check_sources()
            time.sleep(2)  
        except KeyboardInterrupt:
            print("Stopping rotation")
            break


