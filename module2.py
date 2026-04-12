import time
import os

class LogWatcher:
    def __init__(self, sources):
        self.sources = sources
        self.file_offsets = {}

    def initialize_offsets(self):
        for source in self.sources:
            handle = source.get_handle()

            if hasattr(handle, "seekable") and handle.seekable():
                handle.seek(0, os.SEEK_END)
                self.file_offsets[handle] = handle.tell()
            else:
                self.file_offsets[handle] = None

    def _forward(self, line):
        print(line.strip())

    def _read_file(self, handle):
        try:
            current_size = os.path.getsize(handle.name)
        except FileNotFoundError:
            return

        last_offset = self.file_offsets.get(handle,0)

        if current_size < last_offset:
            print("[TRUNCATION DETECTED]")
            handle.seek(0)
            self.file_offsets[handle] = 0
            return
        
        handle.seek(last_offset)
        lines = handle.readlines()

        if lines:
            self.file_offsets[handle] = handle.tell()

        return lines;

    def _read_stream(self, handle):
        lines = []
        while True:
            line = handle.readline()
            if not line:
                break
            lines.append(line)

        return lines

    def watch(self):
        all_lines = []
        for source in self.sources:
            handle = source.get_handle()

            if hasattr(handle, "seekable") and handle.seekable():
                lines = self._read_file(handle)
            else:
                lines = self._read_stream(handle)

            if lines:
                all_lines.extend(lines)

        return all_lines