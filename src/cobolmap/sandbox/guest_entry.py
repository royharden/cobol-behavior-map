"""Contained m10-run-case-v1 entry SOURCE. Never load foreign code on import.

Intended only as /stage/sdk/entry.py in an externally authorized Linux guest.
Checks and JSON here confer no containment, execution or receipt authority.
"""
import hashlib
import importlib.abc
import importlib.util
import json
import os
import re
import stat
import sys
import types

MAX_INPUT = 1048576 + 4096
MAX_CHANNELS = 1048576
MAX_FRAME = 2 * MAX_CHANNELS + 8192
ENTRY = "/stage/sdk/entry.py"
CANDIDATE = "/stage/candidate.py"
MODULES = {
    "cobolmap": ("cobolmap/__init__.py", True),
    "cobolmap.shared": ("cobolmap/shared/__init__.py", True),
    "cobolmap.shared.decimal_shim": ("cobolmap/shared/decimal_shim.py", False),
    "cobolmap.shared.codec": ("cobolmap/shared/codec.py", False),
    "cobolmap.translate": ("cobolmap/translate/__init__.py", True),
    "cobolmap.translate.runtime": ("cobolmap/translate/runtime.py", False),
    "cobolmap.translate.errors": ("cobolmap/translate/errors.py", False),
}


class GuestFault(ValueError):
    """Fixed adapter-owned refusal codes; never stringify a foreign exception."""


class GuestOutputCap(GuestFault):
    """Returned ordinary channels exceeded the declared bound."""


def _require(condition, code):
    if not condition:
        raise GuestFault(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result and len(result) < 3, "duplicate_or_excess_keys")
        result[key] = value
    return result


def _number(_text):
    raise GuestFault("case_has_number")


def _decode_case(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, "input_size")
    text = raw.decode("ascii")
    # Bound nesting before JSON decoding; strings do not contribute brackets.
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            _require(depth <= 2, "case_depth")
        elif character in "]}":
            depth -= 1
            _require(depth >= 0, "case_depth")
    _require(depth == 0 and not quoted, "case_framing")
    case = json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                      parse_float=_number, parse_constant=_number)
    _require(type(case) is dict and set(case) == {"case_sha256", "input_present", "records"}, "case_keys")
    present, encoded, digest = case["input_present"], case["records"], case["case_sha256"]
    _require(type(present) is bool and type(encoded) is list and len(encoded) <= 64,
             "case_presence_count")
    _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "case_hash_shape")
    _require(present or not encoded, "absent_with_records")
    records = []
    hasher = hashlib.sha256(b"M10-CASE-v1\0" + bytes([present]) + len(encoded).to_bytes(4, "big"))
    for item in encoded:
        _require(type(item) is str and 2 <= len(item) <= 16384 and len(item) % 2 == 0
                 and re.fullmatch(r"[0-9a-f]+", item) is not None, "record_hex")
        record = bytes.fromhex(item)
        _require(all(32 <= byte <= 126 for byte in record), "record_encoding")
        hasher.update(len(record).to_bytes(4, "big"))
        hasher.update(record)
        records.append(record)
    _require(hasher.hexdigest() == digest, "case_hash")
    _require(_canonical(case) == raw, "noncanonical_or_trailing_case")
    return present, tuple(records), digest


def _guest_only():
    _require(sys.platform == "linux" and sys.flags.isolated == 1
             and sys.flags.dont_write_bytecode == 1 and os.getuid() == 10001,
             "guest_interlock")
    _require(__file__ == ENTRY and sys.argv == [ENTRY] and os.getcwd() == "/work"
             and sys.base_prefix == "/opt/python" and sys.executable == "/opt/python/bin/python3",
             "fixed_guest_layout")
    _require(not any(name == "cobolmap" or name.startswith("cobolmap.") for name in sys.modules),
             "preloaded_sdk")
    _require("sitecustomize" not in sys.modules and "usercustomize" not in sys.modules,
             "ambient_startup")
    for directory in ("/stage", "/stage/sdk", "/stage/sdk/cobolmap",
                      "/stage/sdk/cobolmap/shared", "/stage/sdk/cobolmap/translate"):
        _require(stat.S_ISDIR(os.stat(directory, follow_symlinks=False).st_mode), "staged_directory")
    # Fixed interpreter-image stdlib roots only; no cwd, site packages, caller
    # paths, PYTHONPATH or ambient installed cobolmap fallback.
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    root = "/opt/python/lib/python" + version
    sys.path[:] = [root, root + "/lib-dynload"]


def _read_fixed(path, maximum):
    allowed = {ENTRY, CANDIDATE} | {"/stage/sdk/" + name for name, _ in MODULES.values()}
    _require(path in allowed, "unapproved_staged_path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "staged_file_bounds")
        chunks, remaining = [], maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        _require(0 < len(raw) <= maximum and len(raw) == info.st_size, "staged_file_changed")
        return raw
    finally:
        os.close(descriptor)


class _FixedLoader(importlib.abc.Loader):
    def __init__(self, fullname, raw, path):
        self.fullname, self.raw, self.path = fullname, raw, path

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        # This is foreign execution ONLY at the future contained guest boundary.
        # No loader or candidate is invoked during source construction/import.
        code = compile(self.raw, self.path, "exec", dont_inherit=True, optimize=0)
        module.__file__ = self.path
        exec(code, module.__dict__)


class _FixedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, staged):
        self.staged = staged

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cobolmap" or fullname.startswith("cobolmap."):
            _require(fullname in MODULES, "sdk_import_outside_closure")
            name, package = MODULES[fullname]
            loader = _FixedLoader(fullname, self.staged[name], "/stage/sdk/" + name)
            spec = importlib.util.spec_from_loader(fullname, loader, is_package=package)
            if package:
                spec.submodule_search_locations = []
            return spec
        return None


def _ordinary(result):
    # Never invoke a foreign mapping iterator/property/equality/str/repr method.
    _require(type(result) is dict and len(result) == 7, "return_shape")
    data = {}
    for key, value in dict.items(result):
        _require(type(key) is str, "return_key_type")
        data[key] = value
    _require(set(data) == {"output_present", "output_bytes", "stdout", "stderr",
                           "return_code", "semantics", "runtime_verified"}, "return_keys")
    present, output = data["output_present"], data["output_bytes"]
    _require(type(present) is bool and (output is None or type(output) is bytes)
             and present == (output is not None), "return_presence")
    _require(type(data["stdout"]) is bytes and type(data["stderr"]) is bytes
             and type(data["return_code"]) is int and 0 <= data["return_code"] <= 255,
             "return_channels")
    _require(type(data["semantics"]) is str and data["semantics"] == "construction_hypothesis"
             and data["runtime_verified"] is False, "return_semantics")
    if len(output or b"") + len(data["stdout"]) + len(data["stderr"]) > MAX_CHANNELS:
        raise GuestOutputCap("output_cap")
    return {"output": {"present": present, "data": output.hex() if output is not None else None},
            "stdout": data["stdout"].hex(), "stderr": data["stderr"].hex(),
            "return_code": data["return_code"]}


def _emit(frame):
    wire = _canonical(frame)
    _require(len(wire) <= MAX_FRAME, "protocol_output_cap")
    view = memoryview(wire)
    offset = 0
    while offset < len(wire):
        written = os.write(3, view[offset:])
        _require(written > 0, "protocol_transport")
        offset += written


def main():
    """Future one-case guest process, no caller path/options or host integration."""
    frame = {"abi": "m10-run-case-v1", "status": "adapter_fault", "fault": "adapter_setup",
             "case_sha256": None, "candidate_sha256": None, "staged": {}, "ordinary": None,
             "semantics": "construction_hypothesis", "runtime_verified": False}
    exit_code = 3
    try:
        _guest_only()
        frame["fault"] = "case_protocol"
        raw_input = sys.stdin.buffer.read(MAX_INPUT + 1)
        present, records, frame["case_sha256"] = _decode_case(raw_input)
        frame["fault"] = "staging"
        staged = {name: _read_fixed("/stage/sdk/" + name, 1048576) for name, _ in MODULES.values()}
        staged["entry.py"] = _read_fixed(ENTRY, 1048576)
        candidate = _read_fixed(CANDIDATE, 65536)
        frame["candidate_sha256"] = hashlib.sha256(candidate).hexdigest()
        frame["staged"] = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "byte_length": len(raw)}
                           for name, raw in staged.items()}
        sys.meta_path.insert(0, _FixedFinder(staged))
        frame["fault"] = "sdk_load"
        # Eagerly load the approved SDK closure before foreign candidate code.
        import cobolmap.translate.runtime as runtime
        runtime_fault = runtime.RuntimeFault
        frame["status"], frame["fault"] = "candidate_fault", "candidate_load"
        exit_code = 2
        try:
            loader = _FixedLoader("_m10_candidate", candidate, CANDIDATE)
            spec = importlib.util.spec_from_loader("_m10_candidate", loader)
            module = importlib.util.module_from_spec(spec)
            sys.modules["_m10_candidate"] = module
            loader.exec_module(module)
            _require(type(module) is types.ModuleType, "candidate_module_type")
            function = dict.get(types.ModuleType.__getattribute__(module, "__dict__"), "run_case")
            _require(type(function) is types.FunctionType, "candidate_entry_type")
            result = function(present, records)
        except BaseException as error:
            frame["fault"] = "runtime_fault" if type(error) is runtime_fault else "candidate_exception"
        else:
            try:
                frame["ordinary"] = _ordinary(result)
            except BaseException as error:
                frame["fault"] = "output_cap" if type(error) is GuestOutputCap else "invalid_candidate_return"
            else:
                frame["status"], frame["fault"], exit_code = "returned", None, 0
    except BaseException:
        # Adapter/protocol failures remain fault frames, never empty ordinary data.
        frame["ordinary"] = None
    try:
        _emit(frame)
    except BaseException:
        return 3  # Missing/truncated frame is a backend protocol fault, never pass.
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
