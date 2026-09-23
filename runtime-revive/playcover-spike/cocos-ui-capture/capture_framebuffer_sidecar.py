#!/usr/bin/env python3

"""Capture one framebuffer before/after pair from an already running game PID.

The host is intentionally independent from capture.py.  It owns only the
Frida session and script that it creates, publishes evidence only after a
clean detach, and never terminates or mutates the target process.

The matching Frida agent is a separate implementation unit.  This host fixes
the RPC and message contract so all identity, durability, and cleanup behavior
can be tested offline before a live agent is introduced.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import math
import os
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
DEFAULT_PROCESS = "ArcherCatXFacebook"
DEFAULT_LOCK_NAME = "archercat-playcover-framebuffer.lock"
SCHEMA_VERSION = 1
POINTER_PATTERN = re.compile(r"^0x[1-9a-f][0-9a-f]*$", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UUID_PATTERN = re.compile(r"UUID: ([0-9A-Fa-f-]+) \(([^)]+)\)")
BATCH_TOKEN_PATTERN = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)
RENAME_EXCL = 0x00000004
AT_FDCWD = -2
MAX_TRANSPORT_DRAIN_SECONDS = 1.0
PROC_PIDPATHINFO_MAXSIZE = 4096
REQUIRED_DYLD_TEXT_PATH = "/usr/lib/libSystem.B.dylib"
VMMAP_TIMEOUT_SECONDS = 2.0
ALLOWED_HOOKS = {
    "navigation": (
        "getaddrinfo",
        "connect",
        "post_response_process",
        "response_decrypt",
    ),
    "light": (
        "getaddrinfo",
        "connect",
        "post_response_process",
        "request_encrypt",
        "response_decrypt",
    ),
}
PROFILE_FACT_FIELDS = (
    "profileFixture",
    "profileBasePoint",
    "profileMapClearTuples",
    "profileEventIds",
    "profileDungeonRecords",
    "profileSkillRecords",
    "profileItemRecords",
    "profileCalendar",
)
READBACK_DESCRIPTOR_FIELDS = (
    "stage",
    "sequence",
    "frameSequence",
    "drawIndex",
    "viewport",
    "width",
    "height",
    "rowStride",
    "byteLength",
    "origin",
    "format",
    "type",
)
REQUIRED_GL_EXPORTS = (
    "glDrawArrays",
    "glReadPixels",
    "glGetIntegerv",
    "glGetBooleanv",
    "glIsEnabled",
    "glCheckFramebufferStatus",
    "glGetFramebufferAttachmentParameteriv",
    "glGetRenderbufferParameteriv",
    "glGetProgramiv",
    "glGetActiveAttrib",
    "glGetAttribLocation",
    "glGetActiveUniform",
    "glGetUniformLocation",
    "glGetUniformfv",
    "glGetUniformiv",
    "glGetTexParameteriv",
    "glGetVertexAttribiv",
    "glGetVertexAttribPointerv",
    "glGetString",
)


class SidecarError(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


class ScriptExports(Protocol):
    def prepare(self, config: Mapping[str, Any]) -> Any: ...

    def arm(self) -> Any: ...

    def stop(self) -> Any: ...


class ScriptProtocol(Protocol):
    exports_sync: ScriptExports

    def on(self, signal: str, callback: Callable[..., None]) -> None: ...

    def load(self) -> None: ...

    def unload(self) -> None: ...


class SessionProtocol(Protocol):
    def on(self, signal: str, callback: Callable[..., None]) -> None: ...

    def create_script(self, source: str) -> ScriptProtocol: ...

    def detach(self) -> None: ...


class DeviceProtocol(Protocol):
    def attach(self, pid: int) -> SessionProtocol: ...


class BackendProtocol(Protocol):
    def get_local_device(self) -> DeviceProtocol: ...

    def shutdown(self) -> None: ...


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    executable: Path
    executable_sha256: str
    command: str
    process_state: str
    start_token: str
    start_epoch: float
    identities: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "executable": str(self.executable),
            "executableSha256": self.executable_sha256,
            "command": self.command,
            "processState": self.process_state,
            "startToken": self.start_token,
            "startEpoch": self.start_epoch,
            "identities": [dict(item) for item in self.identities],
        }


@dataclass(frozen=True)
class LayoutSelection:
    path: Path
    value: dict[str, Any]
    sha256: str
    uuid: str
    arch: str


@dataclass(frozen=True)
class SnapshotBinding:
    path: Path
    sha256: str
    captured_at: str
    captured_epoch: float
    node: dict[str, Any]
    node_sha256: str
    texture_cache: dict[str, Any]


@dataclass(frozen=True)
class SessionProof:
    path: Path
    prefix_byte_length: int
    prefix_sha256: str
    ready: dict[str, Any]
    injection: dict[str, Any]
    consumption: dict[str, Any] | None
    ignored_line_count: int
    source_records: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "consumedPrefixByteLength": self.prefix_byte_length,
            "consumedPrefixSha256": self.prefix_sha256,
            "ignoredLineCount": self.ignored_line_count,
            "ready": self.ready,
            "loginInjection": self.injection,
            "loginConsumption": self.consumption,
            "sourceRecords": [dict(item) for item in self.source_records],
        }


@dataclass(frozen=True)
class AtlasEvidence:
    resource_name: str
    atlas_id: str
    image_name: str
    plist_path: Path
    plist_sha256: str
    image_path: Path
    image_sha256: str
    hd_scale: int
    atlas_size: dict[str, int]
    logical_rect: dict[str, int | float]
    physical_frame: dict[str, int]
    texture_cache_entry: dict[str, Any]
    resource_cross_check: dict[str, Any] | None
    plist_frame: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "resourceName": self.resource_name,
            "atlasId": self.atlas_id,
            "imageName": self.image_name,
            "plist": {"path": str(self.plist_path), "sha256": self.plist_sha256},
            "image": {"path": str(self.image_path), "sha256": self.image_sha256},
            "hdScale": self.hd_scale,
            "atlasSize": self.atlas_size,
            "logicalRect": self.logical_rect,
            "physicalFrame": self.physical_frame,
            "textureCacheEntry": self.texture_cache_entry,
            "resourceCrossCheck": self.resource_cross_check,
            "plistFrame": self.plist_frame,
        }


@dataclass(frozen=True)
class RawCapture:
    phase: str
    payload: dict[str, Any]
    data: bytes
    sha256: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def batch_token_sha256(expected_token: str | None) -> str:
    if not isinstance(expected_token, str) or BATCH_TOKEN_PATTERN.fullmatch(
        expected_token
    ) is None:
        raise SidecarError(
            "batch_token_required",
            "A valid --expected-batch-token from the owning launcher is required.",
        )
    return sha256_bytes(expected_token.encode("ascii"))


def process_image_path(pid: int) -> Path:
    if type(pid) is not int or pid <= 0:
        raise SidecarError("invalid_arguments", "--pid must be a positive integer.")
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidpath = libproc.proc_pidpath
    except (AttributeError, OSError) as error:
        raise SidecarError(
            "process_image_unavailable",
            "Could not load the macOS proc_pidpath process-image API.",
        ) from error
    proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
    ctypes.set_errno(0)
    length = proc_pidpath(pid, buffer, ctypes.sizeof(buffer))
    if length <= 0:
        code = ctypes.get_errno()
        detail = os.strerror(code) if code else "no process image returned"
        status = (
            "target_exited"
            if code in {errno.ENOENT, errno.ESRCH}
            else "process_image_unavailable"
        )
        raise SidecarError(
            status,
            f"Could not resolve the live process image for pid={pid}: {detail}.",
        )
    try:
        return Path(os.fsdecode(buffer.value)).expanduser().resolve()
    except (OSError, UnicodeError) as error:
        raise SidecarError(
            "process_image_unavailable",
            f"Could not normalize the live process image for pid={pid}.",
        ) from error


def require_archercat_process_image(pid: int) -> Path:
    image = process_image_path(pid)
    if image.name != DEFAULT_PROCESS:
        raise SidecarError(
            "target_not_exec_ready",
            f"Refusing to attach to pid={pid} before xpcproxy exec completes; "
            f"live process image is {image}.",
        )
    return image


def vmmap_has_required_dyld_text(value: str) -> bool:
    if not isinstance(value, str):
        return False
    for line in value.splitlines():
        fields = line.split()
        if (
            len(fields) >= 2
            and fields[0] == "__TEXT"
            and fields[-1] == REQUIRED_DYLD_TEXT_PATH
        ):
            return True
    return False


def require_archercat_dyld_ready(pid: int) -> None:
    if type(pid) is not int or pid <= 0:
        raise SidecarError("invalid_arguments", "--pid must be a positive integer.")
    try:
        result = subprocess.run(
            ["vmmap", "-wide", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=VMMAP_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise SidecarError(
            "dyld_readiness_unavailable",
            "vmmap is required to verify target dyld readiness.",
        ) from error
    except subprocess.TimeoutExpired as error:
        raise SidecarError(
            "dyld_readiness_unavailable",
            f"vmmap timed out while checking dyld readiness for pid={pid}.",
        ) from error
    if result.returncode != 0:
        detail = result.stderr.strip() or f"vmmap exited with status {result.returncode}"
        raise SidecarError(
            "dyld_readiness_unavailable",
            f"Could not inspect dyld mappings for pid={pid}: {detail}.",
        )
    if not vmmap_has_required_dyld_text(result.stdout):
        raise SidecarError(
            "target_not_dyld_ready",
            f"Refusing to attach to pid={pid} before dyld maps the __TEXT segment "
            f"for {REQUIRED_DYLD_TEXT_PATH}.",
        )


def require_archercat_process_ready(pid: int) -> Path:
    image = require_archercat_process_image(pid)
    require_archercat_dyld_ready(pid)
    return image


def verify_process_batch_token(pid: int, expected_token: str | None) -> str:
    token_sha256 = batch_token_sha256(expected_token)
    if type(pid) is not int or pid <= 0:
        raise SidecarError("invalid_arguments", "--pid must be a positive integer.")
    require_archercat_process_ready(pid)
    result = subprocess.run(
        ["ps", "eww", "-p", str(pid), "-o", "command="],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise SidecarError(
            "batch_token_unreadable",
            f"Could not read the launch environment for pid={pid}.",
        )
    matches = re.findall(
        r"(?:^|\s)ARCHERCAT_BATCH_TOKEN=([^\s]+)", result.stdout
    )
    if matches != [expected_token]:
        raise SidecarError(
            "batch_token_mismatch",
            f"Refusing to attach to pid={pid}; its launch token is not the current batch token.",
        )
    return token_sha256


def parse_timestamp(value: Any, field: str) -> float:
    if not isinstance(value, str) or not value:
        raise SidecarError("invalid_timestamp", f"{field} must be a timestamp string.")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise SidecarError("invalid_timestamp", f"{field} is invalid: {value!r}") from error
    if parsed.tzinfo is None:
        raise SidecarError("invalid_timestamp", f"{field} must include a timezone.")
    return parsed.timestamp()


def require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SidecarError("contract_invalid", f"{field} must be an object.")
    return value


def require_array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise SidecarError("contract_invalid", f"{field} must be an array.")
    return value


def require_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SidecarError("contract_invalid", f"{field} must be a non-empty string.")
    return value


def require_pointer(value: Any, field: str) -> str:
    if not isinstance(value, str) or POINTER_PATTERN.fullmatch(value) is None:
        raise SidecarError("contract_invalid", f"{field} must be a non-zero pointer.")
    return value.lower()


def pointer_integer(value: Any, field: str) -> int:
    return int(require_pointer(value, field), 16)


def offset_integer(value: Any, field: str) -> int:
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]+", value, re.IGNORECASE):
        return int(value, 16)
    if type(value) is int and value >= 0:
        return value
    raise SidecarError("contract_invalid", f"{field} must be a non-negative offset.")


def read_json_object(path: Path, field: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SidecarError(f"{field}_not_found", f"{field} does not exist: {resolved}")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SidecarError(f"{field}_invalid", f"Could not read {field}: {error}") from error
    return require_object(value, field)


def _require_regular_source_file(path: Path, field: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        details = resolved.lstat()
    except FileNotFoundError as error:
        raise SidecarError(f"{field}_not_found", f"{field} does not exist: {resolved}") from error
    if not stat.S_ISREG(details.st_mode):
        raise SidecarError(f"{field}_invalid", f"{field} must be a regular file: {resolved}")
    return resolved


def _plist_numbers(value: Any, count: int, field: str) -> list[int]:
    if not isinstance(value, str):
        raise SidecarError("atlas_plist_invalid", f"{field} must be a plist geometry string.")
    numbers = [int(item) for item in re.findall(r"-?[0-9]+", value)]
    if len(numbers) != count:
        raise SidecarError("atlas_plist_invalid", f"{field} geometry is invalid.")
    return numbers


def layout_hd_scale(layout: Mapping[str, Any]) -> int:
    expected_runtime = require_object(layout.get("expectedRuntime"), "layout.expectedRuntime")
    hd_scale = expected_runtime.get("hdScale")
    if type(hd_scale) is not int or hd_scale <= 0:
        raise SidecarError(
            "snapshot_resource_mismatch", "layout.expectedRuntime.hdScale is invalid."
        )
    return hd_scale


def _logical_and_physical_rect(
    node: Mapping[str, Any], hd_scale: int
) -> tuple[dict[str, int | float], dict[str, int]]:
    visual = require_object(node.get("visual"), "snapshot target visual")
    rect = require_object(visual.get("rect"), "snapshot target visual.rect")
    logical: dict[str, int | float] = {}
    physical: dict[str, int] = {}
    for field in ("x", "y", "width", "height"):
        value = rect.get(field)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or (field in {"x", "y"} and value < 0)
            or (field in {"width", "height"} and value <= 0)
        ):
            raise SidecarError(
                "snapshot_resource_mismatch", f"Target logical rect {field} is invalid."
            )
        scaled = value * hd_scale
        if not float(scaled).is_integer():
            raise SidecarError(
                "snapshot_resource_mismatch",
                f"Target logical rect {field} does not map to an integer atlas coordinate.",
            )
        logical[field] = value
        physical[field] = int(scaled)
    return logical, physical


def _unique_texture_cache_entry(
    texture_cache: Mapping[str, Any], node_texture: Mapping[str, Any]
) -> dict[str, Any]:
    if texture_cache.get("status") != "ok":
        raise SidecarError(
            "snapshot_texture_cache_incomplete",
            "Framebuffer promotion requires snapshot.textureCache.status=ok.",
        )
    entries = require_array(texture_cache.get("entries"), "snapshot.textureCache.entries")
    target_pointer = require_pointer(node_texture.get("pointer"), "snapshot target texture.pointer")
    matches: list[dict[str, Any]] = []
    for index, value in enumerate(entries):
        entry = require_object(value, f"snapshot.textureCache.entries[{index}]")
        texture = require_object(
            entry.get("texture"), f"snapshot.textureCache.entries[{index}].texture"
        )
        pointer = require_pointer(
            texture.get("pointer"),
            f"snapshot.textureCache.entries[{index}].texture.pointer",
        )
        if pointer == target_pointer:
            matches.append(entry)
    if len(matches) != 1:
        raise SidecarError(
            "snapshot_texture_cache_mismatch",
            "Target texture pointer must join exactly one textureCache entry.",
        )
    entry = matches[0]
    cache_texture = require_object(entry.get("texture"), "target textureCache entry.texture")
    if cache_texture.get("type") != "cocos2d::CCTexture2D":
        raise SidecarError(
            "snapshot_texture_cache_mismatch", "Target textureCache type is not CCTexture2D."
        )
    for field in ("pixelFormat", "glName", "pixelWidth", "pixelHeight"):
        if cache_texture.get(field) != node_texture.get(field):
            raise SidecarError(
                "snapshot_texture_cache_mismatch",
                f"Target node and textureCache {field} differ.",
            )
    cache_key = require_non_empty_string(entry.get("cacheKey"), "target textureCache cacheKey")
    byte_length = entry.get("cacheKeyByteLength")
    if type(byte_length) is not int or byte_length != len(cache_key.encode("utf-8")):
        raise SidecarError(
            "snapshot_texture_cache_mismatch", "Target textureCache key length is invalid."
        )
    return json.loads(json.dumps(entry))


def _optional_resource_cross_check(
    node: Mapping[str, Any],
    *,
    resource_name: str,
    atlas_id: str,
    image_name: str,
    plist_frame: Mapping[str, Any],
) -> dict[str, Any] | None:
    resource_value = node.get("resource")
    if resource_value is None:
        return None
    resource = require_object(resource_value, "snapshot target resource")
    if resource.get("status") != "unique":
        raise SidecarError(
            "snapshot_resource_mismatch",
            "Present target resource evidence must have one unique atlas match.",
        )
    match = require_object(resource.get("match"), "snapshot target resource.match")
    expected = {
        "name": resource_name,
        "atlas": atlas_id,
        "image": image_name,
        "frame": plist_frame["frame"],
        "offset": plist_frame["offset"],
        "sourceSize": plist_frame["sourceSize"],
    }
    mismatches = [field for field, value in expected.items() if match.get(field) != value]
    if mismatches:
        raise SidecarError(
            "snapshot_resource_mismatch",
            "Target resource evidence differs from the requested atlas identity: "
            + ", ".join(mismatches),
        )
    return json.loads(json.dumps(match))


def resolve_atlas_evidence(
    node: Mapping[str, Any],
    *,
    texture_cache: Mapping[str, Any],
    hd_scale: int,
    resource_name: str,
    atlas_id: str,
    plist_path: Path | None = None,
    image_path: Path | None = None,
) -> AtlasEvidence:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", atlas_id):
        raise SidecarError("snapshot_resource_mismatch", "Atlas ID is not path-safe.")
    if type(hd_scale) is not int or hd_scale <= 0:
        raise SidecarError("snapshot_resource_mismatch", "HD scale is invalid.")
    visual = require_object(node.get("visual"), "snapshot target visual")
    node_texture = require_object(visual.get("texture"), "snapshot target visual.texture")
    cache_entry = _unique_texture_cache_entry(texture_cache, node_texture)
    cache_key = require_non_empty_string(cache_entry.get("cacheKey"), "target textureCache cacheKey")
    image_name = Path(cache_key).name
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.png", image_name):
        raise SidecarError(
            "snapshot_texture_cache_mismatch",
            "Target textureCache basename is not a path-safe PNG name.",
        )
    derived_atlas_id = image_name.removesuffix(".png")
    if derived_atlas_id != atlas_id:
        raise SidecarError(
            "snapshot_texture_cache_mismatch",
            "Requested atlas ID differs from the runtime textureCache identity.",
        )
    resolved_plist = _require_regular_source_file(
        plist_path if plist_path is not None else PROJECT_ROOT / "assets" / f"{atlas_id}.plist",
        "atlas_plist",
    )
    if resolved_plist.name != f"{atlas_id}.plist":
        raise SidecarError("atlas_plist_mismatch", "Atlas plist basename changed.")
    try:
        plist = plistlib.loads(resolved_plist.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise SidecarError("atlas_plist_invalid", f"Could not parse atlas plist: {error}") from error
    root = require_object(plist, "atlas plist")
    metadata = require_object(root.get("metadata"), "atlas plist metadata")
    if metadata.get("textureFileName") != image_name or metadata.get(
        "realTextureFileName"
    ) != image_name:
        raise SidecarError("atlas_plist_mismatch", "Atlas plist image identity changed.")
    atlas_dimensions = _plist_numbers(metadata.get("size"), 2, "atlas size")
    atlas_size = {"width": atlas_dimensions[0], "height": atlas_dimensions[1]}
    cache_texture = require_object(cache_entry.get("texture"), "target textureCache entry.texture")
    if (
        atlas_size["width"] != cache_texture.get("pixelWidth")
        or atlas_size["height"] != cache_texture.get("pixelHeight")
    ):
        raise SidecarError(
            "atlas_plist_mismatch", "Atlas plist size differs from the runtime texture."
        )
    logical_rect, physical_frame = _logical_and_physical_rect(node, hd_scale)
    frames = require_object(root.get("frames"), "atlas plist frames")
    physical_matches: list[tuple[str, dict[str, Any]]] = []
    for frame_name, frame_value in frames.items():
        if not isinstance(frame_name, str) or not frame_name:
            raise SidecarError("atlas_plist_invalid", "Atlas plist frame name is invalid.")
        candidate = require_object(frame_value, f"atlas plist frame {frame_name!r}")
        candidate_frame = _plist_numbers(candidate.get("frame"), 4, "atlas frame")
        if candidate_frame == [
            physical_frame["x"],
            physical_frame["y"],
            physical_frame["width"],
            physical_frame["height"],
        ]:
            physical_matches.append((frame_name, candidate))
    if len(physical_matches) != 1:
        raise SidecarError(
            "atlas_plist_mismatch",
            "Runtime Sprite rect must join exactly one atlas plist frame.",
        )
    derived_resource_name, plist_frame_value = physical_matches[0]
    if derived_resource_name != resource_name:
        raise SidecarError(
            "atlas_plist_mismatch",
            "Requested resource name differs from the unique runtime-rect plist match.",
        )
    frame_numbers = _plist_numbers(plist_frame_value.get("frame"), 4, "atlas frame")
    offset_numbers = _plist_numbers(plist_frame_value.get("offset"), 2, "atlas offset")
    source_numbers = _plist_numbers(
        plist_frame_value.get("sourceSize"), 2, "atlas sourceSize"
    )
    plist_frame = {
        "frame": {
            "x": frame_numbers[0],
            "y": frame_numbers[1],
            "width": frame_numbers[2],
            "height": frame_numbers[3],
        },
        "offset": {"x": offset_numbers[0], "y": offset_numbers[1]},
        "sourceSize": {"x": source_numbers[0], "y": source_numbers[1]},
        "rotated": plist_frame_value.get("rotated"),
    }
    if plist_frame["rotated"] is not False:
        raise SidecarError("atlas_plist_mismatch", "Rotated target frames are unsupported.")
    if physical_frame != plist_frame["frame"]:
        raise SidecarError(
            "atlas_plist_mismatch",
            "Target logical rect does not map exactly to the requested plist frame.",
        )
    resource_cross_check = _optional_resource_cross_check(
        node,
        resource_name=resource_name,
        atlas_id=atlas_id,
        image_name=image_name,
        plist_frame=plist_frame,
    )
    resolved_image = _require_regular_source_file(
        image_path if image_path is not None else PROJECT_ROOT / "assets" / image_name,
        "atlas_image",
    )
    if resolved_image.name != image_name:
        raise SidecarError("atlas_plist_mismatch", "Atlas image basename changed.")
    return AtlasEvidence(
        resource_name=resource_name,
        atlas_id=atlas_id,
        image_name=image_name,
        plist_path=resolved_plist,
        plist_sha256=sha256_file(resolved_plist),
        image_path=resolved_image,
        image_sha256=sha256_file(resolved_image),
        hd_scale=hd_scale,
        atlas_size=atlas_size,
        logical_rect=logical_rect,
        physical_frame=physical_frame,
        texture_cache_entry=cache_entry,
        resource_cross_check=resource_cross_check,
        plist_frame=plist_frame,
    )


def _run_ps(pid: int, field: str) -> str:
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", f"{field}="],
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        raise SidecarError("target_exited", f"Process {pid} has no {field} value.")
    return value


def binary_uuids(path: Path) -> tuple[dict[str, str], ...]:
    result = subprocess.run(
        ["dwarfdump", "--uuid", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SidecarError(
            "binary_identity_failed",
            f"dwarfdump failed for {path}: {result.stderr.strip()}",
        )
    records: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        match = UUID_PATTERN.search(line)
        if match:
            records.append({"uuid": match.group(1).upper(), "arch": match.group(2)})
    if not records:
        raise SidecarError("binary_identity_failed", f"No Mach-O UUID found for {path}.")
    return tuple(records)


def _parse_ps_start_epoch(value: str) -> float:
    normalized = " ".join(value.split())
    try:
        parsed = datetime.strptime(normalized, "%a %b %d %H:%M:%S %Y")
    except ValueError as error:
        raise SidecarError(
            "process_start_identity_failed",
            f"Could not parse process start token: {value!r}",
        ) from error
    return parsed.astimezone().timestamp()


def read_process_identity(pid: int) -> ProcessIdentity:
    if type(pid) is not int or pid <= 0:
        raise SidecarError("invalid_arguments", "--pid must be a positive integer.")
    require_archercat_process_image(pid)
    command = _run_ps(pid, "command")
    state = _run_ps(pid, "stat")
    if state.startswith("Z"):
        raise SidecarError("target_exited", f"Process {pid} is a zombie.")
    start_token = _run_ps(pid, "lstart")
    try:
        executable = Path(shlex.split(command)[0]).expanduser().resolve()
    except (ValueError, IndexError) as error:
        raise SidecarError("binary_not_found", f"Invalid target command: {command!r}") from error
    if not executable.is_file():
        raise SidecarError("binary_not_found", f"Executable does not exist: {executable}")
    identities = binary_uuids(executable)
    return ProcessIdentity(
        pid=pid,
        executable=executable,
        executable_sha256=sha256_file(executable),
        command=command,
        process_state=state,
        start_token=start_token,
        start_epoch=_parse_ps_start_epoch(start_token),
        identities=identities,
    )


def process_identity_mismatches(
    expected: ProcessIdentity, actual: ProcessIdentity
) -> list[str]:
    fields = (
        "pid",
        "executable",
        "executable_sha256",
        "start_token",
        "identities",
    )
    return [field for field in fields if getattr(expected, field) != getattr(actual, field)]


def select_layout(
    explicit_path: Path | None, identities: Sequence[Mapping[str, str]]
) -> LayoutSelection:
    candidates = (
        [explicit_path.expanduser().resolve()]
        if explicit_path is not None
        else sorted((SCRIPT_DIR / "layouts").glob("*.json"))
    )
    matches: list[LayoutSelection] = []
    for path in candidates:
        if not path.is_file():
            continue
        value = read_json_object(path, "layout")
        binary = require_object(value.get("binary"), "layout.binary")
        uuid = require_non_empty_string(binary.get("uuid"), "layout.binary.uuid").upper()
        arch = require_non_empty_string(binary.get("arch"), "layout.binary.arch")
        if any(
            item.get("uuid", "").upper() == uuid and item.get("arch") == arch
            for item in identities
        ):
            matches.append(
                LayoutSelection(
                    path=path.resolve(),
                    value=value,
                    sha256=sha256_file(path),
                    uuid=uuid,
                    arch=arch,
                )
            )
    if not matches:
        raise SidecarError(
            "binary_mismatch",
            "No layout matched the live Mach-O identities.",
        )
    if len(matches) != 1:
        raise SidecarError(
            "layout_ambiguous",
            "Multiple layouts matched the live Mach-O identities: "
            + ", ".join(str(item.path) for item in matches),
        )
    return matches[0]


def _identity_present(identities: Sequence[Any], uuid: str, arch: str) -> bool:
    return any(
        isinstance(item, dict)
        and str(item.get("uuid", "")).upper() == uuid
        and item.get("arch") == arch
        for item in identities
    )


def validate_snapshot_binding(
    path: Path,
    *,
    node_id: str,
    process: ProcessIdentity,
    layout: LayoutSelection,
    expected_batch_token_sha256: str,
    now_epoch: float,
    max_age_seconds: float,
) -> SnapshotBinding:
    resolved = path.expanduser().resolve()
    snapshot = read_json_object(resolved, "snapshot")
    if (
        snapshot.get("schemaVersion") != SCHEMA_VERSION
        or snapshot.get("kind") != "cocos_ui_snapshot"
        or snapshot.get("status") != "ok"
    ):
        raise SidecarError(
            "snapshot_incomplete",
            "Framebuffer capture requires a complete schemaVersion 1 Cocos snapshot.",
        )
    if snapshot.get("layoutProfile") != layout.value.get("id"):
        raise SidecarError("snapshot_layout_mismatch", "Snapshot layout profile changed.")
    module = require_object(snapshot.get("module"), "snapshot.module")
    if module.get("pid") != process.pid:
        raise SidecarError("snapshot_pid_mismatch", "Snapshot PID does not match live PID.")
    if module.get("name") != DEFAULT_PROCESS or module.get("arch") != layout.arch:
        raise SidecarError("snapshot_binary_mismatch", "Snapshot module identity is invalid.")
    module_path = Path(
        require_non_empty_string(module.get("path"), "snapshot.module.path")
    ).expanduser().resolve()
    if module_path != process.executable:
        raise SidecarError("snapshot_binary_mismatch", "Snapshot executable path changed.")

    host_binary = require_object(snapshot.get("hostBinary"), "snapshot.hostBinary")
    if host_binary.get("sha256") != process.executable_sha256:
        raise SidecarError("snapshot_binary_mismatch", "Snapshot executable hash changed.")
    if host_binary.get("batchTokenSha256") != expected_batch_token_sha256:
        raise SidecarError(
            "snapshot_batch_token_mismatch",
            "Snapshot launch token does not match the live target ownership token.",
        )
    identities = require_array(host_binary.get("identities"), "snapshot.hostBinary.identities")
    if not _identity_present(identities, layout.uuid, layout.arch):
        raise SidecarError("snapshot_binary_mismatch", "Snapshot UUID/arch is invalid.")
    selected_layout = Path(
        require_non_empty_string(
            host_binary.get("selectedLayout"), "snapshot.hostBinary.selectedLayout"
        )
    ).expanduser().resolve()
    if selected_layout != layout.path:
        raise SidecarError("snapshot_layout_mismatch", "Snapshot selected layout path changed.")

    captured_at = require_non_empty_string(snapshot.get("capturedAt"), "snapshot.capturedAt")
    captured_epoch = parse_timestamp(captured_at, "snapshot.capturedAt")
    age = now_epoch - captured_epoch
    if age < -5:
        raise SidecarError("snapshot_from_future", "Snapshot timestamp is in the future.")
    if age > max_age_seconds:
        raise SidecarError(
            "snapshot_stale",
            f"Snapshot age {age:.3f}s exceeds {max_age_seconds:.3f}s.",
        )
    if captured_epoch + 2 < process.start_epoch:
        raise SidecarError("snapshot_pid_reused", "Snapshot predates the live process start.")
    if resolved.stat().st_mtime + 2 < process.start_epoch:
        raise SidecarError("snapshot_pid_reused", "Snapshot file predates the live process start.")

    nodes = require_array(snapshot.get("nodes"), "snapshot.nodes")
    matches = [item for item in nodes if isinstance(item, dict) and item.get("id") == node_id]
    if len(matches) != 1:
        raise SidecarError(
            "snapshot_target_ambiguous",
            f"Expected exactly one snapshot node {node_id!r}; found {len(matches)}.",
        )
    node = matches[0]
    require_pointer(node.get("runtimePointer"), "snapshot target runtimePointer")
    if node.get("type") != "cocos2d::CCSprite":
        raise SidecarError("snapshot_target_not_sprite", "Target node is not a CCSprite.")
    state_value = require_object(node.get("state"), "snapshot target state")
    if state_value.get("visible") is not True or state_value.get("running") is not True:
        raise SidecarError("snapshot_target_not_drawable", "Target is not visible and running.")
    visual = require_object(node.get("visual"), "snapshot target visual")
    if visual.get("kind") != "sprite":
        raise SidecarError("snapshot_target_not_sprite", "Target has no Sprite visual.")
    texture = require_object(visual.get("texture"), "snapshot target visual.texture")
    require_pointer(texture.get("pointer"), "snapshot target texture.pointer")
    for field in ("pixelWidth", "pixelHeight"):
        if type(texture.get(field)) is not int or texture[field] <= 0:
            raise SidecarError(
                "snapshot_target_texture_invalid", f"Target texture {field} is invalid."
            )
    if type(texture.get("pixelFormat")) is not int or not 0 <= texture["pixelFormat"] <= 7:
        raise SidecarError(
            "snapshot_target_texture_invalid", "Target texture pixelFormat is invalid."
        )
    if type(texture.get("glName")) is not int or texture["glName"] <= 0:
        raise SidecarError(
            "snapshot_target_texture_invalid", "Target texture glName is invalid."
        )
    texture_cache = require_object(snapshot.get("textureCache"), "snapshot.textureCache")
    if texture_cache.get("status") != "ok":
        raise SidecarError(
            "snapshot_texture_cache_incomplete",
            "Framebuffer promotion requires snapshot.textureCache.status=ok.",
        )
    node_copy = json.loads(json.dumps(node))
    return SnapshotBinding(
        path=resolved,
        sha256=sha256_file(resolved),
        captured_at=captured_at,
        captured_epoch=captured_epoch,
        node=node_copy,
        node_sha256=sha256_bytes(canonical_json_bytes(node_copy)),
        texture_cache=json.loads(json.dumps(texture_cache)),
    )


def _normalize_profile_facts(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    fixture = value.get("profileFixture")
    base_point = value.get("profileBasePoint")
    map_tuples = value.get("profileMapClearTuples")
    event_ids = value.get("profileEventIds")
    dungeon_records = value.get("profileDungeonRecords")
    skill_records = value.get("profileSkillRecords")
    item_records = value.get("profileItemRecords")
    calendar = value.get("profileCalendar")
    if not isinstance(fixture, str) or not fixture:
        raise SidecarError("session_proof_invalid", f"{field} fixture is invalid.")
    if type(base_point) is not int or base_point < 0:
        raise SidecarError("session_proof_invalid", f"{field} base point is invalid.")
    for name, item in (
        ("map tuples", map_tuples),
        ("event IDs", event_ids),
        ("dungeon records", dungeon_records),
        ("skill records", skill_records),
        ("item records", item_records),
    ):
        if not isinstance(item, list):
            raise SidecarError("session_proof_invalid", f"{field} {name} is invalid.")
    if not isinstance(calendar, dict) or set(calendar) != {
        "curTick",
        "lastDailyRewardTick",
        "cumulativeDailyRewardCounter",
    }:
        raise SidecarError("session_proof_invalid", f"{field} calendar is invalid.")
    cur_tick = calendar.get("curTick")
    last_tick = calendar.get("lastDailyRewardTick")
    counter = calendar.get("cumulativeDailyRewardCounter")
    if (
        type(cur_tick) is not int
        or cur_tick <= 86400001
        or cur_tick > (1 << 53) - 1
        or type(last_tick) is not int
        or last_tick < 0
        or last_tick > cur_tick
        or type(counter) is not int
        or counter < 0
        or counter > 0xFFFFFFFF
    ):
        raise SidecarError("session_proof_invalid", f"{field} calendar is invalid.")
    if fixture == "calendar-day1-available" and (last_tick != 0 or counter != 0):
        raise SidecarError("session_proof_invalid", f"{field} day-1 calendar is invalid.")
    if fixture == "calendar-day2-with-day1-readonly" and (
        counter != 1 or cur_tick - last_tick != 86400001
    ):
        raise SidecarError("session_proof_invalid", f"{field} day-2 calendar is invalid.")
    if fixture in {
        "calendar-claimed-today-suppressed",
        "training-just-unlocked",
        "inventory-type19-hat-ready",
        "inventory-type20-boots-ready",
        "story-map1-stage1-clear",
        "story-map1-stage4-clear",
    } and (
        counter != 1 or last_tick != cur_tick
    ):
        raise SidecarError(
            "session_proof_invalid", f"{field} claimed-today calendar is invalid."
        )
    if fixture == "training-just-unlocked" and (
        base_point != 0
        or map_tuples != []
        or event_ids != [902]
        or dungeon_records != []
        or skill_records != []
        or item_records != []
    ):
        raise SidecarError(
            "session_proof_invalid",
            f"{field} Training just-unlocked profile facts are invalid.",
        )
    return {name: json.loads(json.dumps(value[name])) for name in PROFILE_FACT_FIELDS}


def _event_payload(record: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    timestamp = record.get("capturedAt") or record.get("t")
    kind = record.get("kind")
    if kind == "frida_network_hook_ready" and isinstance(record.get("ready"), dict):
        return dict(record["ready"]), timestamp if isinstance(timestamp, str) else None
    if kind == "frida_network_message":
        message = record.get("message")
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                return dict(payload), timestamp if isinstance(timestamp, str) else None
    return dict(record), timestamp if isinstance(timestamp, str) else None


def _semantic_event(payload: Mapping[str, Any]) -> tuple[str | None, dict[str, Any]]:
    kind = payload.get("kind")
    if kind == "network_redirect_hook_ready":
        normalized = dict(payload)
        # The direct hook JSON carries its event time at top level, while the
        # Frida CLI mirror puts the same ready payload under `message.payload`.
        # The timestamp is bound separately as `_evidenceTimestamp`; retaining
        # it here would make one live event look like two distinct ready facts.
        normalized.pop("t", None)
        normalized.pop("capturedAt", None)
        return "ready", normalized
    if kind == "network_redirect_audit":
        event_kind = payload.get("eventKind")
        if event_kind in {"archercat_response_decrypt_mocked", "archercat_request_encrypt"}:
            normalized = dict(payload)
            # The hook's direct JSON names the event with `kind`; its Frida
            # CLI mirror uses `network_redirect_audit` plus `eventKind`.
            # Normalize that envelope distinction before semantic dedupe so
            # proof cardinality remains one event, not one per transport.
            normalized["kind"] = str(event_kind)
            normalized.pop("eventKind", None)
            normalized.pop("t", None)
            normalized.pop("capturedAt", None)
            return str(event_kind), normalized
    if kind in {"archercat_response_decrypt_mocked", "archercat_request_encrypt"}:
        normalized = dict(payload)
        normalized.pop("t", None)
        normalized.pop("capturedAt", None)
        if kind == "archercat_response_decrypt_mocked":
            # The hook's direct JSON retains the transient output allocation
            # pointer, while its audit mirror intentionally omits it. The
            # pointer is not part of LoginUser fixture identity; retaining it
            # here would count one injection twice in production JSONL.
            normalized.pop("outputPointer", None)
        return str(kind), normalized
    return None, dict(payload)


def _dedupe_semantic_records(
    records: Sequence[tuple[dict[str, Any], dict[str, Any]]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    seen: set[bytes] = set()
    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for payload, source in records:
        identity_payload = dict(payload)
        identity_payload.pop("_evidenceTimestamp", None)
        canonical = canonical_json_bytes(identity_payload)
        if canonical in seen:
            continue
        seen.add(canonical)
        result.append((payload, source))
    return result


def validate_session_proof(
    path: Path,
    *,
    pid: int,
    arch: str,
    expected_fixture: str,
    expected_hook_mode: str,
    process_start_epoch: float,
    snapshot_epoch: float,
    prefix_byte_length: int | None = None,
) -> SessionProof:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SidecarError("session_proof_not_found", f"Network log does not exist: {resolved}")
    raw = resolved.read_bytes()
    if prefix_byte_length is not None:
        if type(prefix_byte_length) is not int or prefix_byte_length <= 0:
            raise SidecarError(
                "session_proof_invalid", "Network proof prefix length is invalid."
            )
        if len(raw) < prefix_byte_length:
            raise SidecarError(
                "session_proof_invalid", "Network log is shorter than its bound prefix."
            )
        raw = raw[:prefix_byte_length]
    prefix_length = raw.rfind(b"\n") + 1
    if prefix_length <= 0:
        raise SidecarError("session_proof_invalid", "Network log has no complete JSONL record.")
    prefix = raw[:prefix_length]
    try:
        text = prefix.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SidecarError("session_proof_invalid", "Network log prefix is not UTF-8.") from error

    semantic: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {
        "ready": [],
        "archercat_response_decrypt_mocked": [],
        "archercat_request_encrypt": [],
    }
    ignored_line_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            ignored_line_count += 1
            continue
        if not isinstance(record, dict):
            ignored_line_count += 1
            continue
        payload, envelope_timestamp = _event_payload(record)
        if payload is None:
            continue
        category, normalized = _semantic_event(payload)
        if category is None:
            continue
        if envelope_timestamp is not None and "_evidenceTimestamp" not in normalized:
            normalized["_evidenceTimestamp"] = envelope_timestamp
        source = {
            "line": line_number,
            "lineSha256": sha256_bytes((line + "\n").encode("utf-8")),
            "category": category,
        }
        evidence_timestamp = normalized.get("_evidenceTimestamp")
        if isinstance(evidence_timestamp, str):
            source["capturedAt"] = evidence_timestamp
        semantic[category].append((normalized, source))

    ready_records = _dedupe_semantic_records(semantic["ready"])
    matching_ready: list[tuple[dict[str, Any], dict[str, Any]]] = []
    required_hooks = list(ALLOWED_HOOKS[expected_hook_mode])
    for ready, source in ready_records:
        if (
            ready.get("status") == "ok"
            and ready.get("pid") == pid
            and ready.get("arch") == arch
            and ready.get("platform") == "darwin"
            and ready.get("profileFixture") == expected_fixture
            and ready.get("hookMode") == expected_hook_mode
            and ready.get("persistentHooks") == required_hooks
        ):
            matching_ready.append((ready, source))
    if len(matching_ready) != 1:
        raise SidecarError(
            "session_ready_mismatch",
            f"Expected one matching network ready fact; found {len(matching_ready)}.",
        )
    ready, ready_source = matching_ready[0]
    ready_facts = _normalize_profile_facts(ready, "ready")
    count_fields = (
        ("profileMapClearCount", "profileMapClearTuples"),
        ("profileEventCount", "profileEventIds"),
        ("profileDungeonRecordCount", "profileDungeonRecords"),
        ("profileSkillRecordCount", "profileSkillRecords"),
        ("profileItemRecordCount", "profileItemRecords"),
    )
    for count_field, array_field in count_fields:
        if ready.get(count_field) != len(ready_facts[array_field]):
            raise SidecarError(
                "session_ready_mismatch", f"Ready {count_field} does not reconcile."
            )
    expected_length = ready.get("expectedLoginProfileLength")
    if type(expected_length) is not int or expected_length <= 0:
        raise SidecarError("session_ready_mismatch", "Ready profile length is invalid.")

    injection_records = _dedupe_semantic_records(
        semantic["archercat_response_decrypt_mocked"]
    )
    matching_injections: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for injection, source in injection_records:
        try:
            facts = _normalize_profile_facts(injection, "login injection")
        except SidecarError:
            continue
        if (
            injection.get("requestType") == 3
            and facts == ready_facts
            and injection.get("outputLength") == expected_length
            and injection.get("expectedOutputLength") == expected_length
            and injection.get("containsLocalUserId") is True
            and injection.get("containsLocalGuest") is True
        ):
            matching_injections.append((injection, source))
    if len(matching_injections) != 1:
        raise SidecarError(
            "session_fixture_not_injected",
            f"Expected one matching LoginUser fixture injection; found {len(matching_injections)}.",
        )
    injection, injection_source = matching_injections[0]

    consumption: dict[str, Any] | None = None
    consumption_source: dict[str, Any] | None = None
    if expected_hook_mode == "light":
        consumption_records = _dedupe_semantic_records(
            semantic["archercat_request_encrypt"]
        )
        matches = [
            item for item in consumption_records if item[0].get("consumedLocalUserId") is True
        ]
        if not matches:
            raise SidecarError(
                "session_fixture_not_consumed",
                "Light mode did not prove local-user-ID consumption.",
            )
        consumption, consumption_source = matches[0]

    if not isinstance(snapshot_epoch, (int, float)) or isinstance(snapshot_epoch, bool):
        raise SidecarError("session_proof_invalid", "Snapshot epoch is invalid.")

    ordered_evidence: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
        ("ready", ready, ready_source),
        ("login injection", injection, injection_source),
    ]
    if consumption is not None and consumption_source is not None:
        ordered_evidence.append(("login consumption", consumption, consumption_source))
    evidence_epochs: list[float] = []
    for field, payload, source in ordered_evidence:
        captured_at = payload.get("_evidenceTimestamp")
        if not isinstance(captured_at, str) or source.get("capturedAt") != captured_at:
            raise SidecarError(
                "session_proof_timestamp_missing",
                f"{field} has no bound capture timestamp.",
            )
        evidence_epochs.append(parse_timestamp(captured_at, f"network {field} timestamp"))
    if evidence_epochs[0] < process_start_epoch:
        raise SidecarError("session_pid_reused", "Network ready predates process start.")
    if evidence_epochs != sorted(evidence_epochs):
        raise SidecarError(
            "session_proof_order_invalid",
            "Network ready, injection, and consumption evidence is out of order.",
        )
    evidence_lines = [source["line"] for _, _, source in ordered_evidence]
    if any(
        type(line) is not int or line <= 0
        for line in evidence_lines
    ) or any(
        later <= earlier for earlier, later in zip(evidence_lines, evidence_lines[1:])
    ):
        raise SidecarError(
            "session_proof_order_invalid",
            "Network source records are not in strict ready/injection/consumption order.",
        )
    if evidence_epochs[-1] > snapshot_epoch:
        raise SidecarError(
            "session_proof_order_invalid",
            "Network fixture evidence postdates the bound snapshot.",
        )

    def clean(value: dict[str, Any]) -> dict[str, Any]:
        result = json.loads(json.dumps(value))
        result.pop("_evidenceTimestamp", None)
        return result

    sources = [ready_source, injection_source]
    if consumption_source is not None:
        sources.append(consumption_source)
    return SessionProof(
        path=resolved,
        prefix_byte_length=prefix_length,
        prefix_sha256=sha256_bytes(prefix),
        ready=clean(ready),
        injection=clean(injection),
        consumption=clean(consumption) if consumption is not None else None,
        ignored_line_count=ignored_line_count,
        source_records=tuple(sources),
    )


class PersistentFramebufferLock:
    """A persistent inode lock.  The path is deliberately never unlinked."""

    def __init__(self, path: Path | None = None):
        requested = path if path is not None else Path(tempfile.gettempdir()) / DEFAULT_LOCK_NAME
        # Keep the final component unresolved so O_NOFOLLOW can reject a lock
        # path that was replaced with a symlink.
        self.path = Path(os.path.abspath(os.path.expanduser(str(requested))))
        self._descriptor: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise SidecarError("capture_lock_invalid", str(error)) from error
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size != 0:
                raise SidecarError(
                    "capture_lock_invalid",
                    f"Framebuffer lock must be a persistent zero-byte regular file: {self.path}",
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise SidecarError(
                    "capture_lock_busy",
                    "Another framebuffer sidecar owns the persistent lock.",
                ) from error
            self._descriptor = descriptor
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def close(self) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        os.close(descriptor)

    def __enter__(self) -> "PersistentFramebufferLock":
        self.acquire()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new_file_durable(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, f"Short write to {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_exclusive(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise SidecarError(
            "output_exists", f"Refusing to overwrite framebuffer evidence: {destination}"
        )
    if sys.platform != "darwin":
        raise SidecarError(
            "exclusive_publish_unavailable",
            "Exclusive directory publication requires macOS renameatx_np.",
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = getattr(libc, "renameatx_np", None)
    if renameatx_np is None:
        raise SidecarError(
            "exclusive_publish_unavailable", "renameatx_np is unavailable on this host."
        )
    renameatx_np.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_EXCL,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise SidecarError(
                "output_exists", f"Refusing to overwrite framebuffer evidence: {destination}"
            )
        raise SidecarError(
            "exclusive_publish_failed",
            f"renameatx_np failed: {os.strerror(code)}",
        )


class EvidenceBundlePublisher:
    def __init__(
        self,
        output_dir: Path,
        *,
        rename_exclusive: Callable[[Path, Path], None] = _rename_directory_exclusive,
    ):
        self.output_dir = output_dir.expanduser().resolve()
        self._rename_exclusive = rename_exclusive

    def publish(self, before: bytes, after: bytes, metadata: Mapping[str, Any]) -> None:
        parent = self.output_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        if self.output_dir.exists() or self.output_dir.is_symlink():
            raise SidecarError(
                "output_exists", f"Refusing to overwrite framebuffer evidence: {self.output_dir}"
            )
        staging = Path(
            tempfile.mkdtemp(prefix=f".{self.output_dir.name}.partial.", dir=parent)
        )
        published = False
        try:
            _write_new_file_durable(staging / "before.rgba", before)
            _write_new_file_durable(staging / "after.rgba", after)
            encoded_metadata = (
                json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            _write_new_file_durable(staging / "metadata.json", encoded_metadata)
            _fsync_directory(staging)
            self._rename_exclusive(staging, self.output_dir)
            published = True
            _fsync_directory(parent)
        finally:
            if not published and staging.exists():
                shutil.rmtree(staging)


class ReadbackCollector:
    def __init__(self, *, pid: int, uuid: str, layout_profile: str, max_bytes: int):
        self.pid = pid
        self.uuid = uuid.upper()
        self.layout_profile = layout_profile
        self.max_bytes = max_bytes
        self._condition = threading.Condition()
        self._captures: dict[str, RawCapture] = {}
        self._errors: list[str] = []
        self._sealed = False

    @property
    def errors(self) -> list[str]:
        with self._condition:
            return list(self._errors)

    def submit(self, message: Mapping[str, Any], data: bytes | None) -> None:
        try:
            with self._condition:
                if self._sealed:
                    raise SidecarError(
                        "readback_after_seal", "Readback message arrived after transport seal."
                    )
            if message.get("type") != "send":
                raise SidecarError("agent_message_invalid", "Agent emitted a non-send message.")
            payload = require_object(message.get("payload"), "agent message payload")
            if payload.get("kind") != "cocos_sprite_framebuffer_pixels":
                return
            if payload.get("schemaVersion") != SCHEMA_VERSION:
                raise SidecarError("agent_message_invalid", "Readback schemaVersion is invalid.")
            phase = payload.get("stage")
            if phase not in {"before", "after"}:
                raise SidecarError("agent_message_invalid", "Readback phase is invalid.")
            if payload.get("pid") != self.pid:
                raise SidecarError("agent_pid_mismatch", "Readback PID is invalid.")
            if str(payload.get("binaryUuid", "")).upper() != self.uuid:
                raise SidecarError("agent_binary_mismatch", "Readback UUID is invalid.")
            if payload.get("layoutProfile") != self.layout_profile:
                raise SidecarError("agent_layout_mismatch", "Readback layout is invalid.")
            if data is None:
                raise SidecarError("readback_missing", "Readback message has no binary data.")
            binary = bytes(data)
            if not binary or len(binary) > self.max_bytes:
                raise SidecarError("readback_budget_exhausted", "Readback byte budget is invalid.")
            if payload.get("byteLength") != len(binary):
                raise SidecarError("readback_length_mismatch", "Readback byteLength is invalid.")
            with self._condition:
                if phase in self._captures:
                    raise SidecarError("readback_duplicate", f"Duplicate {phase} readback.")
                self._captures[phase] = RawCapture(
                    phase=phase,
                    payload=json.loads(json.dumps(payload)),
                    data=binary,
                    sha256=sha256_bytes(binary),
                )
                self._condition.notify_all()
        except SidecarError as error:
            with self._condition:
                self._errors.append(f"{error.status}:{error}")
                self._condition.notify_all()

    def finalize(
        self, result: Mapping[str, Any], *, timeout_seconds: float
    ) -> tuple[RawCapture, RawCapture]:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= MAX_TRANSPORT_DRAIN_SECONDS
        ):
            raise SidecarError(
                "readback_timeout_invalid", "Readback transport drain timeout is invalid."
            )
        # Frida delivers send() payloads through the message callback, while the
        # synchronous RPC result uses a separate host dispatch path. Do not rely
        # on their relative callback scheduling at the RPC return boundary.
        with self._condition:
            self._condition.wait_for(
                lambda: bool(self._errors)
                or set(self._captures) == {"before", "after"},
                timeout=float(timeout_seconds),
            )
            if self._errors:
                raise SidecarError("agent_message_invalid", "; ".join(self._errors))
            if set(self._captures) != {"before", "after"}:
                raise SidecarError("readback_incomplete", "Before/after readbacks are incomplete.")
            before = self._captures["before"]
            after = self._captures["after"]
        capture_id = require_non_empty_string(result.get("captureId"), "result.captureId")
        for item in (before, after):
            if item.payload.get("captureId") != capture_id:
                raise SidecarError("readback_capture_mismatch", "Readback captureId changed.")
            if item.payload.get("rawSha256") not in (None, item.sha256):
                raise SidecarError("readback_hash_mismatch", "Agent readback hash is invalid.")
        if before.payload.get("sequence") != 0 or after.payload.get("sequence") != 1:
            raise SidecarError("readback_order_mismatch", "Readback sequence must be before=0, after=1.")
        if before.data == after.data:
            raise SidecarError("readback_no_delta", "Before and after framebuffer bytes are equal.")
        return before, after

    def drain_and_seal(self, *, timeout_seconds: float) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= MAX_TRANSPORT_DRAIN_SECONDS
        ):
            raise SidecarError(
                "readback_timeout_invalid", "Readback transport drain timeout is invalid."
            )
        deadline = time.monotonic() + float(timeout_seconds)
        with self._condition:
            if self._sealed:
                raise SidecarError("readback_already_sealed", "Readback transport is already sealed.")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            self._sealed = True
            if self._errors:
                raise SidecarError("agent_message_invalid", "; ".join(self._errors))
            if set(self._captures) != {"before", "after"}:
                raise SidecarError("readback_incomplete", "Before/after readbacks are incomplete.")


def validate_agent_module(value: Any, process: ProcessIdentity, field: str) -> dict[str, Any]:
    module = require_object(value, field)
    if module.get("name") != DEFAULT_PROCESS:
        raise SidecarError("agent_module_mismatch", f"{field} module name changed.")
    module_path = Path(
        require_non_empty_string(module.get("path"), f"{field}.path")
    ).expanduser().resolve()
    if module_path != process.executable:
        raise SidecarError("agent_module_mismatch", f"{field} module path changed.")
    pointer_integer(module.get("base"), f"{field}.base")
    if type(module.get("size")) is not int or module["size"] <= 0:
        raise SidecarError("agent_module_mismatch", f"{field} module size is invalid.")
    return json.loads(json.dumps(module))


def validate_agent_ready(
    value: Any,
    *,
    pid: int,
    layout: LayoutSelection,
    process: ProcessIdentity,
    expected_target: Mapping[str, Any],
    expected_budgets: Mapping[str, Any],
) -> dict[str, Any]:
    ready = require_object(value, "agent ready")
    expected = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cocos_sprite_framebuffer_agent_ready",
        "status": "ok",
        "pid": pid,
        "binaryUuid": layout.uuid,
        "arch": layout.arch,
        "layoutProfile": layout.value.get("id"),
    }
    mismatches = [field for field, expected_value in expected.items() if ready.get(field) != expected_value]
    if mismatches:
        raise SidecarError(
            "agent_ready_mismatch", "Agent ready mismatch: " + ", ".join(mismatches)
        )
    module = validate_agent_module(ready.get("module"), process, "agent ready.module")
    if ready.get("target") != expected_target:
        raise SidecarError("agent_target_mismatch", "Agent ready target changed.")
    if ready.get("budgets") != expected_budgets:
        raise SidecarError("agent_budget_mismatch", "Agent ready budgets changed.")
    hooks = require_object(ready.get("hooks"), "agent ready.hooks")
    expected_hook_fields = {
        "drawScene",
        "spriteDraw",
        "spriteDrawCallReturn",
        "glDrawArrays",
    }
    if set(hooks) != expected_hook_fields:
        raise SidecarError(
            "agent_hook_identity_mismatch",
            "Agent ready must report exactly three Hook addresses plus the draw return guard.",
        )
    module_base = pointer_integer(module.get("base"), "agent ready.module.base")
    contract = require_object(
        layout.value.get("spriteFramebufferCapture"),
        "layout.spriteFramebufferCapture",
    )
    targets = require_object(contract.get("targets"), "layout sprite framebuffer targets")
    draw_scene = require_object(targets.get("drawScene"), "layout target drawScene")
    sprite_draw = require_object(targets.get("spriteDraw"), "layout target spriteDraw")
    expected_addresses = {
        "drawScene": module_base
        + offset_integer(draw_scene.get("offset"), "drawScene.offset"),
        "spriteDraw": module_base
        + offset_integer(sprite_draw.get("offset"), "spriteDraw.offset"),
        "spriteDrawCallReturn": module_base
        + offset_integer(
            sprite_draw.get("drawCallReturnOffset"),
            "spriteDraw.drawCallReturnOffset",
        ),
    }
    for name, expected_address in expected_addresses.items():
        if pointer_integer(hooks.get(name), f"agent ready.hooks.{name}") != expected_address:
            raise SidecarError(
                "agent_hook_identity_mismatch", f"Agent Hook address {name} changed."
            )

    if ready.get("requiredGlExports") != list(REQUIRED_GL_EXPORTS):
        raise SidecarError(
            "agent_gl_export_mismatch", "Agent required GL export list changed."
        )
    provider = require_object(ready.get("glExportProvider"), "agent ready.glExportProvider")
    provider_identity = (
        require_non_empty_string(provider.get("moduleName"), "GL provider moduleName"),
        require_non_empty_string(provider.get("modulePath"), "GL provider modulePath"),
    )
    exports = require_object(ready.get("glExports"), "agent ready.glExports")
    if set(exports) != set(REQUIRED_GL_EXPORTS):
        raise SidecarError("agent_gl_export_mismatch", "Agent GL export set changed.")
    common_providers: set[tuple[str, str]] | None = None
    for name in REQUIRED_GL_EXPORTS:
        export = require_object(exports.get(name), f"agent GL export {name}")
        pointer_integer(export.get("address"), f"agent GL export {name}.address")
        providers = require_array(export.get("providers"), f"agent GL export {name}.providers")
        normalized_providers: set[tuple[str, str]] = set()
        for index, item_value in enumerate(providers):
            item = require_object(item_value, f"agent GL export {name}.providers[{index}]")
            normalized_providers.add(
                (
                    require_non_empty_string(item.get("moduleName"), "GL provider moduleName"),
                    require_non_empty_string(item.get("modulePath"), "GL provider modulePath"),
                )
            )
        if not normalized_providers:
            raise SidecarError("agent_gl_export_mismatch", f"{name} has no GL provider.")
        common_providers = (
            normalized_providers
            if common_providers is None
            else common_providers & normalized_providers
        )
    if common_providers != {provider_identity}:
        raise SidecarError(
            "agent_gl_export_mismatch",
            "Required GL exports do not have exactly one common provider.",
        )
    if pointer_integer(hooks.get("glDrawArrays"), "agent ready.hooks.glDrawArrays") != pointer_integer(
        require_object(exports.get("glDrawArrays"), "agent GL export glDrawArrays").get(
            "address"
        ),
        "agent GL export glDrawArrays.address",
    ):
        raise SidecarError(
            "agent_hook_identity_mismatch", "glDrawArrays Hook/export addresses differ."
        )
    return json.loads(json.dumps(ready))


def validate_agent_result(
    value: Any,
    *,
    pid: int,
    layout: LayoutSelection,
    snapshot: SnapshotBinding,
    process: ProcessIdentity,
    expected_target: Mapping[str, Any],
) -> dict[str, Any]:
    result = require_object(value, "agent result")
    expected = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cocos_sprite_framebuffer_capture_complete",
        "status": "ok",
        "pid": pid,
        "binaryUuid": layout.uuid,
        "arch": layout.arch,
        "layoutProfile": layout.value.get("id"),
    }
    mismatches = [field for field, expected_value in expected.items() if result.get(field) != expected_value]
    if mismatches:
        raise SidecarError(
            "agent_result_incomplete", "Agent result mismatch: " + ", ".join(mismatches)
        )
    validate_agent_module(result.get("module"), process, "agent result.module")
    target = require_object(result.get("target"), "agent result.target")
    if target != expected_target:
        raise SidecarError("agent_target_mismatch", "Agent result target changed.")
    if target.get("nodeId") != snapshot.node.get("id"):
        raise SidecarError("agent_target_mismatch", "Agent target node ID changed.")
    if require_pointer(target.get("pointer"), "agent target pointer") != require_pointer(
        snapshot.node.get("runtimePointer"), "snapshot target pointer"
    ):
        raise SidecarError("agent_target_mismatch", "Agent target pointer changed.")
    if target.get("snapshotSha256") != snapshot.sha256:
        raise SidecarError("agent_target_mismatch", "Agent full snapshot hash changed.")
    frame = require_object(result.get("frame"), "agent result.frame")
    if type(frame.get("sequence")) is not int or frame["sequence"] <= 0:
        raise SidecarError("agent_frame_invalid", "Agent frame sequence is invalid.")
    if type(frame.get("threadId")) is not int or frame["threadId"] <= 0:
        raise SidecarError("agent_frame_invalid", "Agent frame thread is invalid.")
    counts = require_object(result.get("counts"), "agent result.counts")
    if (
        counts.get("targetSpriteEntries") != 1
        or counts.get("crossThreadTargetEntries") != 0
        or counts.get("targetDraws") != 1
    ):
        raise SidecarError(
            "agent_draw_count_invalid", "Capture must contain one target draw and one GL draw."
        )
    if result.get("stopReason") != "draw_scene_leave" or result.get("partialReasons") != []:
        raise SidecarError("agent_result_incomplete", "Agent frame completion is partial.")
    capture = require_object(result.get("capture"), "agent result.capture")
    draw = require_object(capture.get("draw"), "agent result.capture.draw")
    if draw != {"mode": 5, "first": 0, "count": 4}:
        raise SidecarError("agent_draw_shape_invalid", "Agent GL draw shape changed.")
    before_payload = require_object(
        capture.get("beforePayload"), "agent result.capture.beforePayload"
    )
    after_payload = require_object(
        capture.get("afterPayload"), "agent result.capture.afterPayload"
    )
    if before_payload.get("stage") != "before" or after_payload.get("stage") != "after":
        raise SidecarError("agent_readback_invalid", "Agent capture payload stages changed.")
    readback = {
        "x": before_payload.get("viewport", [None, None])[0],
        "y": before_payload.get("viewport", [None, None])[1],
        "width": before_payload.get("width"),
        "height": before_payload.get("height"),
        "rowStride": before_payload.get("rowStride"),
        "byteLength": before_payload.get("byteLength"),
        "pixelFormat": "RGBA8",
        "origin": before_payload.get("origin"),
        "format": before_payload.get("format"),
        "type": before_payload.get("type"),
        "viewport": before_payload.get("viewport"),
    }
    width = readback.get("width")
    height = readback.get("height")
    row_stride = readback.get("rowStride")
    byte_length = readback.get("byteLength")
    if (
        type(width) is not int
        or type(height) is not int
        or width <= 0
        or height <= 0
        or readback.get("pixelFormat") != "RGBA8"
        or readback.get("origin") != "bottom_left"
        or readback.get("format") != 0x1908
        or readback.get("type") != 0x1401
        or row_stride != width * 4
        or byte_length != row_stride * height
    ):
        raise SidecarError("agent_readback_invalid", "Agent readback geometry is invalid.")
    payloads = result.get("payloads")
    if not isinstance(payloads, list) or payloads != [before_payload, after_payload]:
        raise SidecarError("agent_readback_invalid", "Agent payload summaries do not reconcile.")
    require_object(capture.get("beforeState"), "agent result.capture.beforeState")
    require_object(capture.get("afterState"), "agent result.capture.afterState")
    normalized = json.loads(json.dumps(result))
    normalized["hostReadbackGeometry"] = readback
    return normalized


def validate_stop_result(value: Any, *, pid: int, capture_id: str) -> dict[str, Any]:
    result = require_object(value, "agent stop result")
    expected = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cocos_sprite_framebuffer_capture_complete",
        "status": "ok",
        "pid": pid,
        "captureId": capture_id,
    }
    mismatches = [field for field, expected_value in expected.items() if result.get(field) != expected_value]
    if mismatches:
        raise SidecarError(
            "agent_stop_failed", "Agent stop mismatch: " + ", ".join(mismatches)
        )
    if result.get("listenerDetachComplete") is not True or result.get("cleanupIssues") != []:
        raise SidecarError("agent_stop_failed", "Agent listener detach did not complete.")
    return json.loads(json.dumps(result))


def compute_delta(before: bytes, after: bytes, *, width: int, height: int) -> dict[str, Any]:
    expected_length = width * height * 4
    if len(before) != expected_length or len(after) != expected_length:
        raise SidecarError("readback_length_mismatch", "Readback geometry does not match bytes.")
    changed_bytes = 0
    changed_pixels = 0
    min_x = width
    min_y = height
    max_x = -1
    max_y = -1
    for offset in range(0, expected_length, 4):
        left = before[offset : offset + 4]
        right = after[offset : offset + 4]
        if left == right:
            continue
        changed_pixels += 1
        changed_bytes += sum(a != b for a, b in zip(left, right))
        pixel_index = offset // 4
        x = pixel_index % width
        y = pixel_index // width
        min_x = min(min_x, x)
        min_y = min(min_y, y)
        max_x = max(max_x, x)
        max_y = max(max_y, y)
    if changed_pixels == 0:
        raise SidecarError("readback_no_delta", "Framebuffer delta is empty.")
    return {
        "changedByteCount": changed_bytes,
        "changedPixelCount": changed_pixels,
        "bounds": {
            "x": min_x,
            "y": min_y,
            "width": max_x - min_x + 1,
            "height": max_y - min_y + 1,
            "origin": "bottom_left",
        },
    }


class FridaBackend:
    def __init__(self):
        try:
            import frida  # type: ignore
        except ImportError as error:
            raise SidecarError(
                "frida_unavailable",
                "The live framebuffer host requires the project Frida runtime.",
            ) from error
        self._frida = frida

    def get_local_device(self) -> DeviceProtocol:
        return self._frida.get_local_device()

    def shutdown(self) -> None:
        self._frida.shutdown()


def build_agent_config(
    *,
    layout: LayoutSelection,
    timeout_ms: int,
    max_readback_bytes: int,
    snapshot: SnapshotBinding,
    capture_id: str,
    resource_name: str,
    atlas_id: str,
) -> dict[str, Any]:
    contract = layout.value.get("spriteFramebufferCapture")
    if not isinstance(contract, dict):
        raise SidecarError(
            "framebuffer_layout_missing",
            "Selected layout has no spriteFramebufferCapture contract.",
        )
    value = json.loads(json.dumps(contract))
    binary = require_object(value.get("binary"), "layout.framebufferCapture.binary")
    expected_binary = {
        "uuid": layout.uuid,
        "arch": layout.arch,
        "layoutProfile": layout.value.get("id"),
    }
    for field, expected in expected_binary.items():
        actual = binary.get(field)
        if field == "uuid" and isinstance(actual, str):
            actual = actual.upper()
        if actual != expected:
            raise SidecarError(
                "framebuffer_layout_mismatch",
                f"spriteFramebufferCapture binary {field} does not match the layout.",
            )
    budgets = require_object(value.get("budgets"), "layout.spriteFramebufferCapture.budgets")
    if timeout_ms > budgets.get("timeoutMs", 0):
        raise SidecarError(
            "framebuffer_budget_exceeded", "Requested timeout exceeds the layout cap."
        )
    if max_readback_bytes > budgets.get("maxBytesPerImage", 0):
        raise SidecarError(
            "framebuffer_budget_exceeded", "Requested readback bytes exceed the layout cap."
        )
    budgets["timeoutMs"] = timeout_ms
    budgets["maxBytesPerImage"] = max_readback_bytes
    budgets["maxTotalReadbackBytes"] = max_readback_bytes * 2
    texture = require_object(
        require_object(snapshot.node.get("visual"), "snapshot target visual").get("texture"),
        "snapshot target visual.texture",
    )
    value["target"] = {
        "captureId": capture_id,
        "nodeId": snapshot.node.get("id"),
        "pointer": require_pointer(
            snapshot.node.get("runtimePointer"), "snapshot target pointer"
        ),
        "texturePointer": require_pointer(
            texture.get("pointer"), "snapshot target texture.pointer"
        ),
        "textureFormat": texture.get("pixelFormat"),
        "textureWidth": texture.get("pixelWidth"),
        "textureHeight": texture.get("pixelHeight"),
        "textureGlName": texture.get("glName"),
        "resourceName": resource_name,
        "atlasId": atlas_id,
        "snapshotSha256": snapshot.sha256,
    }
    return value


def _same_identity_or_raise(
    expected: ProcessIdentity,
    reader: Callable[[int], ProcessIdentity],
    stage: str,
) -> ProcessIdentity:
    actual = reader(expected.pid)
    mismatches = process_identity_mismatches(expected, actual)
    if mismatches:
        raise SidecarError(
            "same_pid_identity_failed",
            f"Target identity changed at {stage}: {', '.join(mismatches)}",
        )
    return actual


def execute_capture(
    args: argparse.Namespace,
    *,
    backend: BackendProtocol | None = None,
    identity_reader: Callable[[int], ProcessIdentity] = read_process_identity,
    batch_token_verifier: Callable[[int, str | None], str] = verify_process_batch_token,
    now: Callable[[], float] = lambda: datetime.now(timezone.utc).timestamp(),
    lock_factory: Callable[[], PersistentFramebufferLock] | None = None,
    publisher_factory: Callable[[Path], EvidenceBundlePublisher] = EvidenceBundlePublisher,
    transport_drain_seconds: float | None = None,
) -> dict[str, Any]:
    output_dir = args.output.expanduser().resolve()
    if output_dir.exists() or output_dir.is_symlink():
        raise SidecarError("output_exists", f"Output already exists: {output_dir}")
    agent_path = _require_regular_source_file(args.agent, "agent")
    try:
        agent_bytes = agent_path.read_bytes()
        agent_source = agent_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise SidecarError("agent_invalid", f"Could not read framebuffer agent: {error}") from error
    agent_sha256 = sha256_bytes(agent_bytes)
    host_path = Path(__file__).resolve()
    host_sha256 = sha256_file(host_path)
    if args.expected_hook_mode not in ALLOWED_HOOKS:
        raise SidecarError("invalid_arguments", "Hook mode must be navigation or light.")
    if not args.expected_fixture:
        raise SidecarError("invalid_arguments", "Expected fixture cannot be empty.")
    if args.max_snapshot_age_seconds <= 0 or args.max_snapshot_age_seconds > 600:
        raise SidecarError(
            "invalid_arguments", "Snapshot age limit must be in the range 0..600 seconds."
        )
    if args.timeout_ms <= 0 or args.timeout_ms > 30000:
        raise SidecarError("invalid_arguments", "Timeout must be in the range 1..30000 ms.")
    if args.max_readback_bytes <= 0 or args.max_readback_bytes > 4 * 1024 * 1024:
        raise SidecarError(
            "invalid_arguments", "Readback budget must be in the range 1..4194304 bytes."
        )
    if not args.resource_name or not args.atlas_id:
        raise SidecarError(
            "invalid_arguments", "Resource name and atlas ID must be non-empty."
        )
    expected_batch_token_sha256 = batch_token_sha256(args.expected_batch_token)
    requested_transport_drain = (
        min(args.timeout_ms / 1000.0, MAX_TRANSPORT_DRAIN_SECONDS)
        if transport_drain_seconds is None
        else transport_drain_seconds
    )
    if (
        not isinstance(requested_transport_drain, (int, float))
        or isinstance(requested_transport_drain, bool)
        or not 0 < requested_transport_drain <= MAX_TRANSPORT_DRAIN_SECONDS
    ):
        raise SidecarError(
            "invalid_arguments", "Transport drain must be in the range 0..1 seconds."
        )

    lock = lock_factory() if lock_factory is not None else PersistentFramebufferLock()
    session: SessionProtocol | None = None
    script: ScriptProtocol | None = None
    script_loaded = False
    session_attached = False
    stop_completed = False
    unload_completed = False
    detach_completed = False
    backend_shutdown = False
    detached_state: dict[str, Any] = {"reason": None, "details": [], "expected": False}
    result: dict[str, Any] | None = None
    before: RawCapture | None = None
    after: RawCapture | None = None
    ready: dict[str, Any] | None = None
    stop_result: dict[str, Any] | None = None
    pre_detach_identity: ProcessIdentity | None = None
    post_detach_identity: ProcessIdentity | None = None
    post_token_identity: ProcessIdentity | None = None
    selected_backend: BackendProtocol | None = backend
    lock.acquire()
    try:
        pre_attach_identity = identity_reader(args.pid)
        if pre_attach_identity.executable.name != DEFAULT_PROCESS:
            raise SidecarError(
                "binary_mismatch",
                f"Target executable must be {DEFAULT_PROCESS}, got {pre_attach_identity.executable.name}.",
            )
        verified_batch_token_sha256 = batch_token_verifier(
            args.pid, args.expected_batch_token
        )
        if verified_batch_token_sha256 != expected_batch_token_sha256:
            raise SidecarError(
                "batch_token_verification_invalid",
                "Batch-token verifier returned an unexpected ownership digest.",
            )
        post_token_identity = _same_identity_or_raise(
            pre_attach_identity, identity_reader, "after_batch_token_verification"
        )
        layout = select_layout(args.layout, pre_attach_identity.identities)
        snapshot = validate_snapshot_binding(
            args.snapshot,
            node_id=args.node_id,
            process=pre_attach_identity,
            layout=layout,
            expected_batch_token_sha256=verified_batch_token_sha256,
            now_epoch=now(),
            max_age_seconds=args.max_snapshot_age_seconds,
        )
        atlas_evidence = resolve_atlas_evidence(
            snapshot.node,
            texture_cache=snapshot.texture_cache,
            hd_scale=layout_hd_scale(layout.value),
            resource_name=args.resource_name,
            atlas_id=args.atlas_id,
            plist_path=args.atlas_plist,
            image_path=args.atlas_image,
        )
        session_proof = validate_session_proof(
            args.network_log,
            pid=args.pid,
            arch=layout.arch,
            expected_fixture=args.expected_fixture,
            expected_hook_mode=args.expected_hook_mode,
            process_start_epoch=pre_attach_identity.start_epoch,
            snapshot_epoch=snapshot.captured_epoch,
        )
        capture_id = (
            f"framebuffer-{args.pid}-{args.node_id}-{snapshot.sha256[:12]}".lower()
        )
        agent_config = build_agent_config(
            layout=layout,
            timeout_ms=args.timeout_ms,
            max_readback_bytes=args.max_readback_bytes,
            snapshot=snapshot,
            capture_id=capture_id,
            resource_name=args.resource_name,
            atlas_id=args.atlas_id,
        )
        selected_backend = backend if backend is not None else FridaBackend()
        device = selected_backend.get_local_device()
        final_batch_token_sha256 = batch_token_verifier(
            args.pid, args.expected_batch_token
        )
        if final_batch_token_sha256 != verified_batch_token_sha256:
            raise SidecarError(
                "batch_token_verification_invalid",
                "Final pre-attach batch-token verification returned an unexpected ownership digest.",
            )
        _same_identity_or_raise(
            pre_attach_identity, identity_reader, "immediately_before_attach"
        )
        session = device.attach(args.pid)
        session_attached = True

        def on_detached(reason: str, *details: Any) -> None:
            detached_state["reason"] = reason
            detached_state["details"] = [str(item) for item in details]

        session.on("detached", on_detached)
        script = session.create_script(agent_source)
        collector = ReadbackCollector(
            pid=args.pid,
            uuid=layout.uuid,
            layout_profile=str(layout.value.get("id")),
            max_bytes=args.max_readback_bytes,
        )
        script.on("message", collector.submit)
        script.load()
        script_loaded = True
        ready = validate_agent_ready(
            script.exports_sync.prepare(agent_config),
            pid=args.pid,
            layout=layout,
            process=pre_attach_identity,
            expected_target=agent_config["target"],
            expected_budgets=agent_config["budgets"],
        )
        result = validate_agent_result(
            script.exports_sync.arm(),
            pid=args.pid,
            layout=layout,
            snapshot=snapshot,
            process=pre_attach_identity,
            expected_target=agent_config["target"],
        )
        if detached_state["reason"] is not None:
            raise SidecarError(
                "target_detached",
                f"Target detached during capture: {detached_state['reason']}",
            )
        before, after = collector.finalize(
            result,
            timeout_seconds=float(requested_transport_drain),
        )
        capture_record = require_object(result.get("capture"), "agent result.capture")
        for raw_capture, descriptor_name in (
            (before, "beforePayload"),
            (after, "afterPayload"),
        ):
            descriptor = require_object(
                capture_record.get(descriptor_name), f"agent result.capture.{descriptor_name}"
            )
            observed_descriptor = {
                field: raw_capture.payload.get(field) for field in READBACK_DESCRIPTOR_FIELDS
            }
            if observed_descriptor != descriptor:
                raise SidecarError(
                    "readback_descriptor_mismatch",
                    f"{raw_capture.phase} transport/result descriptors differ.",
                )
        readback = require_object(
            result.get("hostReadbackGeometry"), "agent result.hostReadbackGeometry"
        )
        if len(before.data) != readback["byteLength"] or len(after.data) != readback["byteLength"]:
            raise SidecarError("readback_length_mismatch", "Result/readback byte length changed.")
        delta = compute_delta(
            before.data,
            after.data,
            width=readback["width"],
            height=readback["height"],
        )
        pre_detach_identity = _same_identity_or_raise(
            pre_attach_identity, identity_reader, "before_detach"
        )
        stop_result = validate_stop_result(
            script.exports_sync.stop(),
            pid=args.pid,
            capture_id=require_non_empty_string(result.get("captureId"), "result.captureId"),
        )
        stop_completed = True
        script.unload()
        script_loaded = False
        unload_completed = True
        collector.drain_and_seal(timeout_seconds=float(requested_transport_drain))
        detached_state["expected"] = True
        session.detach()
        session_attached = False
        detach_completed = True
        post_detach_identity = _same_identity_or_raise(
            pre_attach_identity, identity_reader, "after_detach"
        )
        selected_backend.shutdown()
        backend_shutdown = True

        window_screenshot: dict[str, Any] | None = None
        if args.window_screenshot is not None:
            screenshot_path = args.window_screenshot.expanduser().resolve()
            if not screenshot_path.is_file():
                raise SidecarError(
                    "window_screenshot_not_found", f"Screenshot does not exist: {screenshot_path}"
                )
            window_screenshot = {
                "path": str(screenshot_path),
                "sha256": sha256_file(screenshot_path),
                "association": "same_pid_adjacent_not_same_frame",
            }

        completed_at = utc_now()
        metadata = {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "cocos_framebuffer_sidecar_bundle",
            "status": "ok",
            "completedAt": completed_at,
            "pid": args.pid,
            "binary": {
                "uuid": layout.uuid,
                "arch": layout.arch,
                "executable": str(pre_attach_identity.executable),
                "executableSha256": pre_attach_identity.executable_sha256,
                "batchTokenSha256": verified_batch_token_sha256,
            },
            "tooling": {
                "host": {"path": str(host_path), "sha256": host_sha256},
            },
            "layout": {
                "id": layout.value.get("id"),
                "path": str(layout.path),
                "sha256": layout.sha256,
            },
            "fixture": {
                "name": args.expected_fixture,
                "hookMode": args.expected_hook_mode,
                "persistentHooks": list(ALLOWED_HOOKS[args.expected_hook_mode]),
                "proof": session_proof.as_dict(),
            },
            "snapshot": {
                "path": str(snapshot.path),
                "sha256": snapshot.sha256,
                "capturedAt": snapshot.captured_at,
                "maxAgeSeconds": args.max_snapshot_age_seconds,
            },
            "target": {
                "nodeId": snapshot.node.get("id"),
                "pointer": snapshot.node.get("runtimePointer"),
                "type": snapshot.node.get("type"),
                "snapshotNodeSha256": snapshot.node_sha256,
                "snapshotNode": snapshot.node,
                "resourceName": args.resource_name,
                "atlasId": args.atlas_id,
                "textureFormat": snapshot.node["visual"]["texture"]["pixelFormat"],
                "textureGlName": snapshot.node["visual"]["texture"]["glName"],
            },
            "atlasEvidence": atlas_evidence.as_dict(),
            "processIdentity": {
                "samePidAndStartIdentity": True,
                "preAttach": pre_attach_identity.as_dict(),
                "postTokenVerification": post_token_identity.as_dict(),
                "preDetach": pre_detach_identity.as_dict(),
                "postDetach": post_detach_identity.as_dict(),
            },
            "agent": {
                "path": str(agent_path),
                "sha256": agent_sha256,
                "config": agent_config,
                "ready": ready,
                "result": result,
                "stop": stop_result,
            },
            "readbacks": {
                "before": {
                    "path": "before.rgba",
                    "sha256": before.sha256,
                    "byteLength": len(before.data),
                    "payload": before.payload,
                },
                "after": {
                    "path": "after.rgba",
                    "sha256": after.sha256,
                    "byteLength": len(after.data),
                    "payload": after.payload,
                },
                "geometry": result["hostReadbackGeometry"],
                "delta": delta,
            },
            "cleanup": {
                "agentStop": "ok",
                "scriptUnload": "ok",
                "sessionDetach": "ok",
                "backendShutdown": "ok",
                "targetTerminated": False,
                "postDetachSamePidAlive": True,
            },
            "windowScreenshot": window_screenshot,
        }
        publisher_factory(output_dir).publish(before.data, after.data, metadata)
        return {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "cocos_framebuffer_sidecar_host_complete",
            "status": "ok",
            "pid": args.pid,
            "output": str(output_dir),
            "snapshotSha256": snapshot.sha256,
            "beforeSha256": before.sha256,
            "afterSha256": after.sha256,
            "changedPixelCount": delta["changedPixelCount"],
        }
    finally:
        cleanup_errors: list[str] = []
        if script is not None and script_loaded and not stop_completed:
            try:
                script.exports_sync.stop()
            except Exception as error:
                cleanup_errors.append(f"stop:{error}")
        if script is not None and script_loaded:
            try:
                script.unload()
                unload_completed = True
            except Exception as error:
                cleanup_errors.append(f"unload:{error}")
        if session is not None and session_attached:
            detached_state["expected"] = True
            try:
                session.detach()
                detach_completed = True
            except Exception as error:
                cleanup_errors.append(f"detach:{error}")
        if selected_backend is not None and not backend_shutdown:
            try:
                selected_backend.shutdown()
            except Exception as error:
                cleanup_errors.append(f"shutdown:{error}")
        lock.close()
        # Cleanup failures are deliberately not raised from finally because a
        # primary capture exception must retain its status.  Success is already
        # impossible unless stop/unload/detach completed before publication.
        if cleanup_errors and result is None:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture one UUID/layout/fixture-guarded framebuffer draw pair."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--expected-batch-token", default=os.environ.get("PLAYCOVER_BATCH_TOKEN")
    )
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--network-log", type=Path, required=True)
    parser.add_argument("--expected-fixture", required=True)
    parser.add_argument("--expected-hook-mode", choices=tuple(ALLOWED_HOOKS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--agent", type=Path, default=SCRIPT_DIR / "cocos-sprite-framebuffer-agent.js"
    )
    parser.add_argument("--layout", type=Path)
    parser.add_argument("--resource-name", required=True)
    parser.add_argument("--atlas-id", required=True)
    parser.add_argument("--atlas-plist", type=Path)
    parser.add_argument("--atlas-image", type=Path)
    parser.add_argument("--window-screenshot", type=Path)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--max-readback-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-snapshot-age-seconds", type=float, default=120.0)
    return parser.parse_args(argv)


def error_payload(status: str, message: str) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "cocos_framebuffer_sidecar_host_error",
        "status": status,
        "message": message,
        "capturedAt": utc_now(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = execute_capture(parse_args(argv))
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except SidecarError as error:
        print(
            json.dumps(error_payload(error.status, str(error)), ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    except Exception as error:
        print(
            json.dumps(error_payload("framebuffer_sidecar_host_error", str(error)), ensure_ascii=False),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
