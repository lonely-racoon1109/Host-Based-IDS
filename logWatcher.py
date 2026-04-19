import os
import time
import select


class LogWatcher:

    def __init__(self, source_manager):
        self.source_manager = source_manager
        self.file_offsets = {}
        self.poll_interval = 1

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize_offsets(self):
        """
        Seek all file-based sources to EOF so we only read NEW lines,
        not the entire existing log on startup.
        Streams (journalctl) don't need offsets.
        """
        for source, handle in self.source_manager.get_active_sources():
            name = source.get_name()
            if self._is_seekable(handle):
                handle.seek(0, os.SEEK_END)
                self.file_offsets[name] = handle.tell()
                print(f"[OFFSET INIT] {name} -> {self.file_offsets[name]} bytes")
            else:
                self.file_offsets[name] = None  # stream: no offset tracking

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_seekable(self, handle):
        return hasattr(handle, "seekable") and handle.seekable()

    def _read_file(self, source, handle):
        name = source.get_name()

        if handle is None:
            return []

        try:
            last_offset = self.file_offsets.get(name, 0)

            handle.seek(0, os.SEEK_END)
            current_size = handle.tell()

            # file truncated
            if current_size < last_offset:
                print(f"[TRUNCATION] {name}")
                last_offset = 0

            if current_size == last_offset:
                return []

            handle.seek(last_offset)
            lines = handle.readlines()

            self.file_offsets[name] = handle.tell()
            merged = []
            buffer = ""

            for line in lines:
                line = line.rstrip("\n")

                if _SYSLOG_TS_RE.match(line):   # new log starts
                    if buffer:
                        merged.append(buffer)
                    buffer = line
                else:
                    buffer += " " + line.strip()

            if buffer:
                merged.append(buffer)

            return [(name, l) for l in merged if l.strip()]

        except Exception as e:
            print(f"[ERROR] reading {name}: {e}")
            return []   # 🔥 CRITICAL: NEVER return None

    def _read_stream(self, source, handle):
        name = source.get_name()
        lines = []

        try:
            line = handle.readline()
            if line:
                line = line.rstrip("\n")
                if line.strip():
                    lines.append((name, line))
        except Exception as e:
            print(f"[ERROR] Stream read failed on {name}: {e}")

        return lines

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def collect(self):
        self.source_manager.check_sources()

        all_lines = []
        for source, handle in self.source_manager.get_active_sources():
            if self._is_seekable(handle):
                all_lines.extend(self._read_file(source, handle))
            else:
                line = handle.readline()
                if line:
                    all_lines.append((source.get_name(), line.strip()))

        # IMPORTANT: force “heartbeat event” so pipeline doesn’t feel stuck
        if not all_lines:
            return [("__heartbeat__", f"tick:{time.time()}")]

        return all_lines

    def run(self, callback):
        """
        Continuous watch loop.

        callback : callable that receives list of (source_name, line) tuples
                   This is where you'll plug in the parser in Module 3.

        Example:
            watcher.run(lambda lines: parser.feed(lines))
        """
        print(f"[WATCHER] Starting — poll interval: {self.poll_interval}s")
        while True:
            try:
                lines = self.collect()
                if lines:
                    callback(lines)
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                print("[WATCHER] Interrupted, shutting down...")
                self.source_manager.close_all()
                break
            except Exception as e:
                print(f"[WATCHER] Unexpected error: {e}, continuing...")
                time.sleep(self.poll_interval)