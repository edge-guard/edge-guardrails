import ctypes
import os
import platform

class ScanResult(ctypes.Structure):
    _fields_ = [
        ("is_safe", ctypes.c_bool),
        ("violation_code", ctypes.c_int32)
    ]

class EdgeGuard:
    VIOLATIONS = {
        0: "Safe",
        1: "Email Address Detected",
        2: "Credit Card Detected",
        3: "API Key Detected",
        4: "Prompt Injection Detected",
        -1: "Engine Error / Memory Guard Tripped"
    }

    def __init__(self):
        system = platform.system()
        lib_name = "libedge_native_sdk.dylib" if system == "Darwin" else "libedge_native_sdk.so"
        lib_path = os.path.join(os.path.dirname(__file__), "target", "release", lib_name)
        
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Binary not found at {lib_path}. Run 'cargo build --lib --release' first.")

        self._lib = ctypes.CDLL(lib_path)
        self._lib.scan_prompt_safe.argtypes = [ctypes.c_char_p]
        self._lib.scan_prompt_safe.restype = ScanResult

    def scan(self, text: str):
        c_text = ctypes.c_char_p(text.encode("utf-8"))
        res = self._lib.scan_prompt_safe(c_text)
        return {
            "is_safe": res.is_safe,
            "violation_code": res.violation_code,
            "reason": self.VIOLATIONS.get(res.violation_code, "Unknown")
        }

if __name__ == "__main__":
    guard = EdgeGuard()
    clean_test = guard.scan("Hello world, tell me a joke.")
    print(f"Test 1 (Clean): {clean_test}")
    
    bad_test = guard.scan("My secret key is sk-1234567890abcdef1234567890")
    print(f"Test 2 (Violation): {bad_test}")
