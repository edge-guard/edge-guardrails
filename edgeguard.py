import ctypes
import os
import sys
import yaml
from typing import Dict, Any

class ScanResult(ctypes.Structure):
    _fields_ = [
        ("is_safe", ctypes.c_bool),
        ("violation_code", ctypes.c_int),
    ]

class EdgeGuard:
    _DEFAULT_REASON_MAP = {
        0: "Safe",
        1: "PII - Email Address Detected",
        2: "Financial - Credit Card Detected",
        3: "Secrets - API Key / Token Detected",
        4: "Security - Prompt Injection Detected",
        5: "Secrets - High-Entropy Secret Detected",
        6: "Security - Base64 Encoded Injection Detected",
        -1: "Engine Error / Unhandled Panic"
    }

    def __init__(self, policy_path: str = None, lib_path: str = None):
        if lib_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            if sys.platform == "darwin":
                lib_name = "libedge_native_sdk.dylib"
            elif sys.platform == "win32":
                lib_name = "edge_native_sdk.dll"
            else:
                lib_name = "libedge_native_sdk.so"
            lib_path = os.path.join(base_dir, "target", "release", lib_name)

        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Native library not found at {lib_path}. Run `cargo build --lib --release` first.")

        self.lib = ctypes.CDLL(lib_path)
        self.reason_map = dict(self._DEFAULT_REASON_MAP)

        # 1. Policy FFI setup
        self.lib.edgeguard_load_policy_file.argtypes = [ctypes.c_char_p]
        self.lib.edgeguard_load_policy_file.restype = ctypes.c_int

        # 2. One-shot Scan FFI setup
        self.lib.scan_prompt_safe.argtypes = [ctypes.c_char_p]
        self.lib.scan_prompt_safe.restype = ScanResult

        # 3. Stream Engine FFI setup
        self.lib.stream_scanner_create.argtypes = [ctypes.c_size_t]
        self.lib.stream_scanner_create.restype = ctypes.c_void_p

        self.lib.stream_scanner_feed.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.stream_scanner_feed.restype = ScanResult

        self.lib.stream_scanner_reset.argtypes = [ctypes.c_void_p]
        self.lib.stream_scanner_reset.restype = None

        self.lib.stream_scanner_free.argtypes = [ctypes.c_void_p]
        self.lib.stream_scanner_free.restype = None

        if policy_path:
            self.load_policy(policy_path)

    def load_policy(self, file_path: str):
        """Dynamically loads and compiles a YAML policy into the native engine."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Policy file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    self.reason_map = dict(self._DEFAULT_REASON_MAP)
                    for r in data["rules"]:
                        self.reason_map[r["id"]] = r.get("name", f"Rule #{r['id']}")
        except Exception as e:
            raise ValueError(f"Failed to parse policy YAML: {e}")

        status = self.lib.edgeguard_load_policy_file(file_path.encode("utf-8"))
        if status != 0:
            error_codes = {
                -1: "Invalid path pointer",
                -2: "Failed to open file",
                -3: "Invalid YAML syntax",
                -4: "Invalid regular expression",
                -5: "Lock poisoned"
            }
            raise RuntimeError(f"Native engine failed to load policy. Status: {status} ({error_codes.get(status, 'Unknown')})")

    def scan(self, prompt: str) -> Dict[str, Any]:
        """One-shot scan of an entire string."""
        raw_res = self.lib.scan_prompt_safe(prompt.encode("utf-8"))
        return {
            "is_safe": bool(raw_res.is_safe),
            "violation_code": int(raw_res.violation_code),
            "reason": self.reason_map.get(raw_res.violation_code, "Unknown Violation")
        }

    def create_stream_scanner(self, window_size: int = 256):
        """Creates an isolated, stateful stream scanner instance."""
        return StreamGuardSession(self.lib, self.reason_map, window_size)


class StreamGuardSession:
    """Manages token-by-token streaming scan with automatic FFI memory cleanup."""
    def __init__(self, lib, reason_map: dict, window_size: int):
        self.lib = lib
        self.reason_map = reason_map
        self.handle = self.lib.stream_scanner_create(window_size)
        if not self.handle:
            raise MemoryError("Failed to initialize native stream scanner handle.")

    def feed_token(self, token: str) -> Dict[str, Any]:
        """Scans an incoming token chunk. Returns immediate violation if triggered."""
        raw_res = self.lib.stream_scanner_feed(self.handle, token.encode("utf-8"))
        return {
            "is_safe": bool(raw_res.is_safe),
            "violation_code": int(raw_res.violation_code),
            "reason": self.reason_map.get(raw_res.violation_code, "Unknown Violation")
        }

    def reset(self):
        """Clears the internal rolling window buffer."""
        self.lib.stream_scanner_reset(self.handle)

    def __del__(self):
        """Ensures Rust memory is safely freed on GC."""
        if hasattr(self, 'handle') and self.handle:
            self.lib.stream_scanner_free(self.handle)
            self.handle = None