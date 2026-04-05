import time
import os

class LogWatcher:
    def __init__(self, sources):
        self.sources = sources
        self.file_offsets = {}

    def initialize_offsets(self):
        for source in self.sources:
            handle = source.get_handle()

            if hasattr(handle, "seek"):
                handle.seek(0, os.SEEK_END)
                self.file_offsets[handle] = handle.tell()

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
            for line in lines:
                self._forward(line)

            self.file_offsets[handle] = handle.tell()

    def _read_stream(self, handle):
        line = handle.readline()
        if line:
            self._forward(line)

    def watch(self):
        while True:
            for source in self.sources:
                handle = source.get_handle()

                if hasattr(handle, "seek"):
                    self._read_file(handle)
                else:
                    self._read_stream(handle)