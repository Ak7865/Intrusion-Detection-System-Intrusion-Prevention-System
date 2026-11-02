import csv
from typing import Protocol

import requests


class OutputWriter(Protocol):
    def write(self, data: dict) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class CSVWriter:
    def __init__(self, output_file) -> None:
        self.file = open(
            output_file,
            "w",
            newline="",
            encoding="utf-8",
            buffering=1024 * 1024,
        )
        self.line = 0
        self.writer = csv.writer(self.file)
        self.closed = False

    def write(self, data: dict) -> None:
        if self.closed:
            raise ValueError("Cannot write to a closed CSV file")

        if self.line == 0:
            self.writer.writerow(data.keys())

        self.writer.writerow(data.values())
        self.line += 1

    def close(self) -> None:
        if not self.closed:
            self.file.flush()
            self.file.close()
            self.closed = True

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class HttpWriter:
    def __init__(self, output_url) -> None:
        self.url = output_url
        self.session = requests.Session()
        self.closed = False

    def write(self, data: dict) -> None:
        if self.closed:
            raise ValueError("Cannot write using a closed HTTP writer")

        try:
            response = self.session.post(
                self.url,
                json=data,
                timeout=5,
            )
            response.raise_for_status()
        except Exception as exc:
            print(f"HTTPWriter failed posting flow: {exc}")

    def close(self) -> None:
        if not self.closed:
            self.session.close()
            self.closed = True

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def output_writer_factory(output_mode, output) -> OutputWriter:
    match output_mode:
        case "url":
            return HttpWriter(output)
        case "csv":
            return CSVWriter(output)
        case _:
            raise RuntimeError("no output_mode provided")