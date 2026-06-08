#!/usr/bin/env python3
"""Read EMV Track 1/2 data through PC/SC."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 0x0001
SCARD_PROTOCOL_T1 = 0x0002
SCARD_LEAVE_CARD = 0
MAX_APDU_RESPONSE = 65536

DWORD = ctypes.c_uint32
LONG = ctypes.c_long
SCARDCONTEXT = ctypes.c_size_t if sys.platform == "win32" else ctypes.c_ulong
SCARDHANDLE = ctypes.c_size_t if sys.platform == "win32" else ctypes.c_ulong
SCARDPROTOCOL = DWORD

COMMON_AIDS: tuple[tuple[str, str], ...] = (
    ("Visa", "A0000000031010"),
    ("Visa Electron", "A0000000032010"),
    ("V PAY", "A0000000032020"),
    ("Mastercard", "A0000000041010"),
    ("Maestro", "A0000000043060"),
    ("Maestro UK", "A000000004306001"),
    ("American Express", "A00000002501"),
    ("Discover", "A0000001523010"),
    ("JCB", "A0000000651010"),
    ("UnionPay debit", "A000000333010101"),
    ("UnionPay credit", "A000000333010102"),
)

class PcscError(RuntimeError):
    pass


class ScardIoRequest(ctypes.Structure):
    _fields_ = [("dwProtocol", DWORD), ("cbPciLength", DWORD)]


@dataclass(frozen=True)
class ApduResponse:
    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> str:
        return f"{self.sw1:02X}{self.sw2:02X}"

    @property
    def ok(self) -> bool:
        return self.sw == "9000"


@dataclass(frozen=True)
class Tlv:
    tag: str
    value: bytes
    children: tuple["Tlv", ...]


@dataclass(frozen=True)
class DolEntry:
    tag: str
    length: int


class PcscCard:
    def __init__(self, preferred_reader: str | None = None) -> None:
        self.lib = self._load_pcsc_library()
        self.reader_encoding = "mbcs" if sys.platform == "win32" else "utf-8"
        self._configure_ctypes()
        self.context = SCARDCONTEXT()
        self.card = SCARDHANDLE()
        self.protocol = SCARDPROTOCOL()
        self.reader_name = ""
        self._establish_context()
        self._connect(preferred_reader)

    def _load_pcsc_library(self) -> ctypes.CDLL:
        if sys.platform == "win32":
            return ctypes.WinDLL("winscard.dll")
        if sys.platform == "darwin":
            return ctypes.CDLL("/System/Library/Frameworks/PCSC.framework/PCSC")
        return ctypes.CDLL(ctypes.util.find_library("pcsclite") or "libpcsclite.so.1")

    def _configure_ctypes(self) -> None:
        self.SCardEstablishContext = self.lib.SCardEstablishContext
        self.SCardListReaders = getattr(self.lib, "SCardListReadersA", None) or self.lib.SCardListReaders
        self.SCardConnect = getattr(self.lib, "SCardConnectA", None) or self.lib.SCardConnect
        self.SCardTransmit = self.lib.SCardTransmit
        self.SCardDisconnect = self.lib.SCardDisconnect
        self.SCardReleaseContext = self.lib.SCardReleaseContext

        self.SCardEstablishContext.argtypes = [
            DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(SCARDCONTEXT),
        ]
        self.SCardEstablishContext.restype = LONG
        self.SCardListReaders.argtypes = [
            SCARDCONTEXT,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(DWORD),
        ]
        self.SCardListReaders.restype = LONG
        self.SCardConnect.argtypes = [
            SCARDCONTEXT,
            ctypes.c_char_p,
            DWORD,
            DWORD,
            ctypes.POINTER(SCARDHANDLE),
            ctypes.POINTER(SCARDPROTOCOL),
        ]
        self.SCardConnect.restype = LONG
        self.SCardTransmit.argtypes = [
            SCARDHANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(DWORD),
        ]
        self.SCardTransmit.restype = LONG
        self.SCardDisconnect.argtypes = [SCARDHANDLE, DWORD]
        self.SCardDisconnect.restype = LONG
        self.SCardReleaseContext.argtypes = [SCARDCONTEXT]
        self.SCardReleaseContext.restype = LONG

    def _check(self, rv: int, what: str) -> None:
        if rv != 0:
            raise PcscError(f"{what} failed: 0x{rv & 0xFFFFFFFF:08X}")

    def _establish_context(self) -> None:
        rv = self.SCardEstablishContext(
            SCARD_SCOPE_SYSTEM, None, None, ctypes.byref(self.context)
        )
        self._check(rv, "SCardEstablishContext")

    def list_readers(self) -> list[str]:
        size = DWORD(0)
        rv = self.SCardListReaders(self.context, None, None, ctypes.byref(size))
        self._check(rv, "SCardListReaders(size)")

        buf = ctypes.create_string_buffer(size.value)
        rv = self.SCardListReaders(self.context, None, buf, ctypes.byref(size))
        self._check(rv, "SCardListReaders")

        return [
            part.decode(self.reader_encoding, "replace")
            for part in buf.raw[: size.value].split(b"\0")
            if part
        ]

    def _connect(self, preferred_reader: str | None) -> None:
        readers = self.list_readers()
        if not readers:
            raise PcscError("No PC/SC readers found")

        candidates = readers
        if preferred_reader:
            candidates = [r for r in readers if preferred_reader.lower() in r.lower()]
            if not candidates:
                raise PcscError(
                    f"No reader matching {preferred_reader!r}; found: {', '.join(readers)}"
                )

        last_error: Exception | None = None
        for reader in candidates:
            rv = self.SCardConnect(
                self.context,
                reader.encode(self.reader_encoding, "replace"),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                ctypes.byref(self.card),
                ctypes.byref(self.protocol),
            )
            if rv == 0:
                self.reader_name = reader
                return
            last_error = PcscError(f"SCardConnect({reader}) failed: 0x{rv & 0xFFFFFFFF:08X}")

        raise last_error or PcscError("Unable to connect to a card")

    def _protocol_name(self) -> str:
        if self.protocol.value == SCARD_PROTOCOL_T0:
            return "T=0"
        if self.protocol.value == SCARD_PROTOCOL_T1:
            return "T=1"
        return f"unknown({self.protocol.value})"

    def _send_pci(self) -> ctypes.c_void_p:
        if self.protocol.value == SCARD_PROTOCOL_T0:
            exported_name = "g_rgSCardT0Pci"
        elif self.protocol.value == SCARD_PROTOCOL_T1:
            exported_name = "g_rgSCardT1Pci"
        else:
            raise PcscError(f"Unsupported active protocol: {self._protocol_name()}")

        try:
            pci = ScardIoRequest.in_dll(self.lib, exported_name)
        except ValueError:
            pci = ScardIoRequest(self.protocol.value, ctypes.sizeof(ScardIoRequest))
        return ctypes.cast(ctypes.byref(pci), ctypes.c_void_p)

    def transmit(self, apdu: bytes) -> ApduResponse:
        response = self._transmit_once(apdu)
        if response.sw1 == 0x6C:
            response = self._transmit_once(apdu[:-1] + bytes([response.sw2]))
        while response.sw1 == 0x61:
            le = response.sw2 if response.sw2 else 0x00
            response = self._transmit_once(bytes.fromhex("00 C0 00 00") + bytes([le]))
        return response

    def _transmit_once(self, apdu: bytes) -> ApduResponse:
        send = (ctypes.c_ubyte * len(apdu)).from_buffer_copy(apdu)
        recv = (ctypes.c_ubyte * MAX_APDU_RESPONSE)()
        recv_len = DWORD(MAX_APDU_RESPONSE)
        rv = self.SCardTransmit(
            self.card,
            self._send_pci(),
            send,
            DWORD(len(apdu)),
            None,
            recv,
            ctypes.byref(recv_len),
        )
        if rv != 0:
            raise PcscError(
                f"SCardTransmit failed: 0x{rv & 0xFFFFFFFF:08X} "
                f"(protocol {self._protocol_name()}, apdu_len {len(apdu)})"
            )
        raw = bytes(recv[: recv_len.value])
        if len(raw) < 2:
            raise PcscError(f"APDU returned too few bytes: {raw.hex().upper()}")
        return ApduResponse(raw[:-2], raw[-2], raw[-1])

    def close(self) -> None:
        if self.card.value:
            self.SCardDisconnect(self.card, SCARD_LEAVE_CARD)
            self.card = SCARDHANDLE()
        if self.context.value:
            self.SCardReleaseContext(self.context)
            self.context = SCARDCONTEXT()

    def __enter__(self) -> "PcscCard":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def parse_tlv(data: bytes, *, strict: bool = True) -> list[Tlv]:
    pos = 0
    nodes: list[Tlv] = []
    while pos < len(data):
        first = data[pos]
        pos += 1
        tag_bytes = [first]
        if first & 0x1F == 0x1F:
            while pos < len(data):
                tag_bytes.append(data[pos])
                cont = data[pos] & 0x80
                pos += 1
                if not cont:
                    break
            else:
                if strict:
                    raise ValueError("unterminated tag")
                break
        if pos >= len(data):
            if strict:
                raise ValueError("missing length")
            break

        first_len = data[pos]
        pos += 1
        if first_len & 0x80:
            len_len = first_len & 0x7F
            if len_len == 0 or pos + len_len > len(data):
                if strict:
                    raise ValueError("invalid long length")
                break
            length = int.from_bytes(data[pos : pos + len_len], "big")
            pos += len_len
        else:
            length = first_len

        if pos + length > len(data):
            if strict:
                raise ValueError("value overruns buffer")
            break
        value = data[pos : pos + length]
        pos += length
        children: tuple[Tlv, ...] = ()
        if tag_bytes[0] & 0x20:
            try:
                children = tuple(parse_tlv(value, strict=True))
            except ValueError:
                children = ()
        nodes.append(Tlv(bytes(tag_bytes).hex().upper(), value, children))
    return nodes


def try_parse_tlv(data: bytes) -> list[Tlv]:
    try:
        return parse_tlv(data, strict=True)
    except ValueError:
        return []


def flatten_tlv(nodes: Iterable[Tlv]) -> list[Tlv]:
    flat: list[Tlv] = []
    for node in nodes:
        flat.append(node)
        flat.extend(flatten_tlv(node.children))
    return flat


def find_first(nodes: Iterable[Tlv], tag: str) -> bytes | None:
    tag = tag.upper()
    for node in flatten_tlv(nodes):
        if node.tag == tag:
            return node.value
    return None


def parse_dol(data: bytes) -> list[DolEntry]:
    pos = 0
    entries: list[DolEntry] = []
    while pos < len(data):
        first = data[pos]
        pos += 1
        tag_bytes = [first]
        if first & 0x1F == 0x1F:
            while pos < len(data):
                tag_bytes.append(data[pos])
                cont = data[pos] & 0x80
                pos += 1
                if not cont:
                    break
        if pos >= len(data):
            raise ValueError("missing DOL length")
        length = data[pos]
        pos += 1
        entries.append(DolEntry(bytes(tag_bytes).hex().upper(), length))
    return entries


def encode_ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def fixed_hex(hex_value: str, length: int) -> bytes:
    raw = bytes.fromhex(hex_value)
    if len(raw) >= length:
        return raw[:length]
    return raw + (b"\x00" * (length - len(raw)))


def default_dol_value(tag: str, length: int) -> bytes:
    today = datetime.now(timezone.utc).strftime("%y%m%d")
    defaults = {
        "9F66": "36000000",
        "9F02": "000000000000",
        "9F03": "000000000000",
        "9F1A": "0616",
        "5F2A": "0985",
        "9A": today,
        "9C": "00",
        "9F37": "12345678",
    }
    return fixed_hex(defaults.get(tag, ""), length)


def bcd_track2_text(value: bytes) -> str:
    chars: list[str] = []
    for byte in value:
        for nibble in ((byte >> 4) & 0x0F, byte & 0x0F):
            if 0 <= nibble <= 9:
                chars.append(str(nibble))
            elif nibble == 0xD:
                chars.append("D")
            elif nibble == 0xF:
                continue
            else:
                chars.append(f"{nibble:X}")
    return "".join(chars)


def decode_track1_data(value: bytes) -> dict[str, Any]:
    text = value.decode("ascii", "ignore").strip("\x00")
    base: dict[str, Any] = {
        "parse_status": "unknown_format",
        "raw_length_bytes": len(value),
        "track1": text,
    }

    pan_start = 2 if text.startswith("%B") else 1 if text.startswith("B") else -1
    if pan_start < 0:
        return base

    first_sep = text.find("^", pan_start)
    if first_sep < 0:
        return base

    second_sep = text.find("^", first_sep + 1)
    pan = text[pan_start:first_sep]
    name = text[first_sep + 1 : second_sep if second_sep >= 0 else len(text)]
    tail = text[second_sep + 1 :] if second_sep >= 0 else ""
    tail = tail[:-1] if tail.endswith("?") else tail
    expiry = tail[:4]
    service = tail[4:7]
    discretionary = tail[7:] if len(tail) >= 7 else ""
    return {
        "parse_status": "ok",
        "raw_length_bytes": len(value),
        "track1": text,
        "pan": pan,
        "pan_length": len(pan),
        "name": name,
        "expiry_yymm": expiry,
        "service_code": service,
        "discretionary_len": len(discretionary),
        "discretionary": discretionary,
    }


def decode_track2_equivalent(value: bytes) -> dict[str, Any]:
    text = bcd_track2_text(value)
    sep_index = text.find("D")
    separator = "D"
    if sep_index < 0:
        sep_index = text.find("=")
        separator = "="

    if sep_index < 0:
        return {
            "parse_status": "separator_not_found",
            "raw_length_bytes": len(value),
            "track2": bcd_track2_text(value),
        }

    pan = text[:sep_index]
    tail = text[sep_index + 1 :]
    expiry = tail[:4]
    service = tail[4:7]
    discretionary = tail[7:] if len(tail) >= 7 else ""
    return {
        "parse_status": "ok",
        "raw_length_bytes": len(value),
        "separator": separator,
        "track2": f"{pan}{separator}{tail}",
        "pan": pan,
        "pan_length": len(pan),
        "expiry_yymm": expiry,
        "service_code": service,
        "discretionary_len": len(discretionary),
        "discretionary": discretionary,
    }


def select_file(card: PcscCard, name: bytes) -> ApduResponse:
    return card.transmit(bytes.fromhex("00 A4 04 00") + bytes([len(name)]) + name + b"\x00")


def read_record(card: PcscCard, sfi: int, record_no: int) -> ApduResponse:
    p2 = ((sfi & 0x1F) << 3) | 0x04
    return card.transmit(bytes([0x00, 0xB2, record_no & 0xFF, p2, 0x00]))


def get_processing_options(card: PcscCard, fci_nodes: list[Tlv]) -> ApduResponse:
    pdol = find_first(fci_nodes, "9F38")
    pdol_value = b""
    if pdol:
        for entry in parse_dol(pdol):
            pdol_value += default_dol_value(entry.tag, entry.length)

    data = b"\x83" + encode_ber_length(len(pdol_value)) + pdol_value
    if len(data) > 255:
        raise ValueError(f"GPO data too long: {len(data)} bytes")
    return card.transmit(bytes.fromhex("80 A8 00 00") + bytes([len(data)]) + data + b"\x00")


def extract_afl(gpo_data: bytes) -> bytes | None:
    nodes = try_parse_tlv(gpo_data)
    afl = find_first(nodes, "94")
    if afl is not None:
        return afl
    for node in nodes:
        if node.tag == "80" and len(node.value) >= 2:
            return node.value[2:]
    return None


def parse_afl_entries(afl: bytes) -> list[dict[str, int]]:
    entries: list[dict[str, int]] = []
    for pos in range(0, len(afl) - (len(afl) % 4), 4):
        raw_sfi, first_record, last_record, _offline_auth_records = afl[pos : pos + 4]
        sfi = (raw_sfi >> 3) & 0x1F
        if sfi and first_record <= last_record:
            entries.append({"sfi": sfi, "first_record": first_record, "last_record": last_record})
    return entries


def read_pse_apps(card: PcscCard, sfi: int) -> list[dict[str, str]]:
    apps: list[dict[str, str]] = []
    for record_no in range(1, 32):
        response = read_record(card, sfi, record_no)
        if response.sw in {"6A83", "6A82"}:
            break
        if not response.ok:
            continue
        for template in flatten_tlv(try_parse_tlv(response.data)):
            if template.tag != "61":
                continue
            children = parse_tlv(template.value, strict=False)
            aid = find_first(children, "4F")
            if aid:
                apps.append({"aid": aid.hex().upper(), "source": f"PSE record {record_no}"})
    return apps


def discover_apps(card: PcscCard) -> list[dict[str, str]]:
    apps: list[dict[str, str]] = []
    for pse_name in (b"1PAY.SYS.DDF01", b"2PAY.SYS.DDF01"):
        response = select_file(card, pse_name)
        if not response.ok:
            continue
        directory_sfi = find_first(try_parse_tlv(response.data), "88")
        if directory_sfi:
            apps.extend(read_pse_apps(card, directory_sfi[0] & 0x1F))

    seen = {app["aid"] for app in apps}
    for label, aid_hex in COMMON_AIDS:
        if aid_hex in seen:
            continue
        response = select_file(card, bytes.fromhex(aid_hex))
        if response.ok:
            apps.append({"aid": aid_hex, "source": f"common AID fallback: {label}"})
            seen.add(aid_hex)

    unique: list[dict[str, str]] = []
    seen.clear()
    for app in apps:
        if app["aid"] not in seen:
            unique.append(app)
            seen.add(app["aid"])
    return unique


def scan_app_for_tracks(card: PcscCard, app: dict[str, str]) -> list[dict[str, Any]]:
    response = select_file(card, bytes.fromhex(app["aid"]))
    if not response.ok:
        return []

    fci_nodes = try_parse_tlv(response.data)
    try:
        gpo = get_processing_options(card, fci_nodes)
    except (PcscError, ValueError):
        return []
    if not gpo.ok:
        return []

    afl = extract_afl(gpo.data)
    if not afl:
        return []

    found: list[dict[str, Any]] = []
    for entry in parse_afl_entries(afl):
        for record_no in range(entry["first_record"], entry["last_record"] + 1):
            record = read_record(card, entry["sfi"], record_no)
            if not record.ok:
                continue
            nodes = try_parse_tlv(record.data)
            track1_value = find_first(nodes, "56")
            if track1_value is not None:
                found.append(
                    {
                        "track": "track1",
                        "tag": "56",
                        "aid": app["aid"],
                        "source": app["source"],
                        "sfi": entry["sfi"],
                        "record": record_no,
                        "track1_data": decode_track1_data(track1_value),
                    }
                )

            for tag in ("57", "9F6B"):
                track2_value = find_first(nodes, tag)
                if track2_value is None:
                    continue
                found.append(
                    {
                        "track": "track2",
                        "tag": tag,
                        "aid": app["aid"],
                        "source": app["source"],
                        "sfi": entry["sfi"],
                        "record": record_no,
                        "track2_equivalent": decode_track2_equivalent(track2_value),
                    }
                )
    return found


def run(args: argparse.Namespace) -> int:
    with PcscCard(args.reader) as card:
        reader_name = card.reader_name
        apps = discover_apps(card)
        tracks: list[dict[str, Any]] = []
        for app in apps:
            tracks.extend(scan_app_for_tracks(card, app))

        report = {
            "tracks_found": bool(tracks),
            "track1_count": sum(1 for item in tracks if item["track"] == "track1"),
            "track2_count": sum(1 for item in tracks if item["track"] == "track2"),
            "tracks": tracks,
        }

    json_path = Path(args.json)
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    print(f"Reader: {reader_name}")
    print(f"Tracks found: {report['tracks_found']}")
    print(f"Track 1 entries: {report['track1_count']}")
    print(f"Track 2 entries: {report['track2_count']}")
    print(f"JSON: {json_path}")
    return 0 if tracks else 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read EMV Track 1/2 data through PC/SC."
    )
    parser.add_argument("--reader", help="Reader name substring to use")
    parser.add_argument("--json", default="trlog_output.json", help="JSON output path")
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(run(parse_args(sys.argv[1:])))
    except PcscError as exc:
        print(f"PC/SC error: {exc}", file=sys.stderr)
        raise SystemExit(2)
