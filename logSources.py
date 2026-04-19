import os
import subprocess

class FileSource:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.fd = None
        self.inode = None

    def validate_source(self):
        return os.path.exists(self.path) and os.access(self.path, os.R_OK)

    def initialize(self):
        if not self.validate_source():
            self.fd = None
            return

        self.fd = open(self.path, "r")
        self.inode = os.stat(self.path).st_ino

        # IMPORTANT: do NOT pre-seek here (watcher controls offset)
        print(f"[OPENED] {self.path}")

    def check_rotation(self):
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return

        # Only rotate if inode changed AND file shrank
        if self.inode and stat.st_ino != self.inode:
            print("[ROTATION DETECTED] reopening cleanly")
            try:
                self.fd.close()
            except:
                pass

            self.fd = open(self.path, "r")
            self.inode = stat.st_ino

            # IMPORTANT: jump to end to avoid re-reading old logs
            self.fd.seek(0, os.SEEK_END)

    def close(self):
        if self.fd:
            self.fd.close()
        self.fd = None

    def get_name(self):
        return f"File({os.path.basename(self.path)})"

    def get_handle(self):
        return self.fd


class JournalSource:
    def __init__(self, units=None, priority="info..alert"):
        """
        units: list of systemd unit names to follow, e.g. ["sshd", "sudo"]
               If None, follows all units (useful for auditd later).
        priority: journalctl priority filter string
        """
        self.units = units or ["sshd", "sudo"]
        self.priority = priority
        self.process = None

    def validate_source(self):
        print("[VALIDATING] JournalSource")
        # Check if journalctl binary exists and is executable
        result = subprocess.run(
            ["which", "journalctl"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            print("[SKIP] journalctl not found (non-systemd system?)")
            return False
        print("[OK] journalctl available")
        return True

    def initialize(self):
        if not self.validate_source():
            self.process = None
            return

        cmd = ["journalctl", "-f", "-n", "0", "-o", "short", "-p", self.priority]
        for unit in self.units:
            cmd += ["-u", unit]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1  # line-buffered; bufsize=0 is invalid in text mode
            )
            # Give it a moment and check it didn't immediately exit
            try:
                self.process.wait(timeout=0.3)
                # If wait() returns without timeout, process died immediately
                print(f"[ERROR] journalctl exited immediately "
                      f"(returncode={self.process.returncode})")
                self.process = None
                return
            except subprocess.TimeoutExpired:
                pass  # Still running — this is what we want

            print(f"[OPENED] JournalSource (units={self.units})")
        except Exception as e:
            print(f"[ERROR] Failed to start journalctl: {e}")
            self.process = None

    def check_rotation(self):
        # Journal doesn't rotate like files; but check if process died
        if self.process and self.process.poll() is not None:
            print(f"[WARNING] journalctl process died "
                  f"(returncode={self.process.returncode}), restarting...")
            self.close()
            self.initialize()

    def close(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                self.process.kill()
            self.process = None
            print("[CLOSED] JournalSource")

    def get_name(self):
        return f"JournalSource(units={self.units})"

    def get_handle(self):
        if self.process and self.process.stdout:
            return self.process.stdout
        return None


class LogSourceManager:
    def __init__(self, sources):
        self.sources = sources         # all configured sources
        self.active_sources = []       # sources with valid handles

    def initialize_sources(self):
        self.active_sources = []
        for source in self.sources:
            source.initialize()
            if source.get_handle() is not None:
                self.active_sources.append(source)
            else:
                print(f"[SKIPPED] {source.get_name()} failed to initialize")

        print(f"[MANAGER] {len(self.active_sources)}/{len(self.sources)} "
              f"sources active")

    def check_sources(self):
        """
        Call periodically (e.g., every 5s) from the watcher loop.
        Re-evaluates which sources are active after rotation/crash.
        """
        for source in self.sources:
            source.check_rotation()

        # Rebuild active list: a previously dead source may have recovered
        self.active_sources = [
            s for s in self.sources if s.get_handle() is not None
        ]

    def get_active_sources(self):
        """
        Returns list of (source_object, file_handle) tuples.
        The watcher needs both: handle for reading, source for rotation checks.
        """
        return [
            (source, source.get_handle())
            for source in self.active_sources
            if source.get_handle() is not None
        ]

    def get_names(self):
        return [source.get_name() for source in self.active_sources]

    def close_all(self):
        for source in self.sources:
            source.close()
        self.active_sources = []
        print("[MANAGER] All sources closed")