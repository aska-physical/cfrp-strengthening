#!/usr/bin/env python3
"""Replay the Track 1 result and compare it with its certificate.

Run from anywhere:
    python3 results/track-1-flexure/verify.py
        Recompute every number from tracks/track-1/input.json with the
        hash-verified checker loaded directly from its verified bytes,
        compare canonical bytes with certificate.json in this folder,
        verify commitment/SHA256SUMS against commitment/ROOT, and check
        the ten printed values from the worked example.
    python3 results/track-1-flexure/verify.py --write
        Regenerate certificate.json, but only if the result passes.
        A failing result is never certified: the run prints the failures
        and exits non-zero without writing.

Checker lock: the checker hash recorded in the unique `## Checker` section
of tracks/track-1-flexure-example.md is the lock. If src/flexure440.py
differs from that hash by one byte, both modes fail without executing it.
A checker change must land in its own pull request, which updates the lock
there, before any result can be certified against it.

The printed-value match compares unrounded checker output with the
printed values, the same comparison the unit tests make. Rounded values
in the certificate are for reading, not for matching.

A pass proves the numbers in the certificate replay from the input file
with the locked checker. It does not prove the ACI method is right, and
it does not prove any real beam is safe. See PROOF.md for what is
claimed.
"""

import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import types
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

CERT = os.path.join(HERE, "certificate.json")
INPUT = os.path.join(ROOT, "tracks", "track-1", "input.json")
EXPECTED = os.path.join(ROOT, "tracks", "track-1", "expected.json")
CHECKER = os.path.join(ROOT, "src", "flexure440.py")
TRACK = os.path.join(ROOT, "tracks", "track-1-flexure-example.md")
COMMITMENT_SUMS = os.path.join(ROOT, "commitment", "SHA256SUMS")
COMMITMENT_ROOT = os.path.join(ROOT, "commitment", "ROOT")

MAX_FILE_BYTES = 1_048_576
MAX_INT_DIGITS = 100
_ISO_DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z", re.ASCII)
_CHECKER_SECTION_RE = re.compile(r"(?ms)^## Checker[ \t]*$.*?(?=^## |\Z)")
_SHA256_LOCK_RE = re.compile(r"\bsha256: ([0-9a-f]{64})\b", re.ASCII)
_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z", re.ASCII)


class VerificationError(RuntimeError):
    """Raised when certificate I/O, date/JSON validation, lock, or finiteness checks fail."""


def require(ok, message):
    if not ok:
        raise VerificationError(message)


def strict_finite(value, name):
    require(type(value) in (int, float), f"{name} must be finite number, got {type(value).__name__}")
    val = float(value)
    require(math.isfinite(val), f"{name} must be finite, got {value!r}")
    return val


def strict_finite_min(a, b, name):
    fa = strict_finite(a, f"{name}.a")
    fb = strict_finite(b, f"{name}.b")
    return fa if fa <= fb else fb


def validate_iso_date(when):
    require(type(when) is str, "certificate date must be an ISO-8601 string")
    require(_ISO_DATE_RE.fullmatch(when) is not None, f"certificate date must match YYYY-MM-DD, got {when!r}")
    try:
        date.fromisoformat(when)
    except ValueError as exc:
        raise VerificationError(f"certificate date is not a valid calendar date: {when!r}") from exc
    return when


def _require_no_symlink_target(path, label):
    cur = os.path.abspath(path)
    while True:
        require(not os.path.islink(cur), f"{label}: symlink path or ancestor forbidden")
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent


def read_regular_bytes(path, label):
    _require_no_symlink_target(path, label)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise VerificationError(f"cannot stat {label}: {exc}") from exc
    require(stat.S_ISREG(st.st_mode), f"{label} is not a regular file")
    require(st.st_size <= MAX_FILE_BYTES, f"{label} exceeds size limit")
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc


def _strict_pairs_no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def _strict_parse_int(token):
    digits = token[1:] if token.startswith("-") else token
    require(len(digits) <= MAX_INT_DIGITS, "JSON integer exceeds digit limit")
    return int(token)


def _strict_parse_float(token):
    val = float(token)
    require(math.isfinite(val), f"non-finite JSON float forbidden: {token!r}")
    return val


def _reject_json_constant(token):
    raise VerificationError(f"non-standard JSON constant forbidden: {token!r}")


def parse_strict_json_bytes(raw, label):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{label} is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_pairs_no_duplicates,
            parse_int=_strict_parse_int,
            parse_float=_strict_parse_float,
            parse_constant=_reject_json_constant,
        )
    except VerificationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise VerificationError(f"{label} invalid JSON: {exc}") from exc


def render_canonical_cert_bytes(cert):
    return (json.dumps(cert, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def write_canonical_cert_bytes(path, payload):
    _require_no_symlink_target(path, "certificate.json")
    if os.path.lexists(path):
        st = os.lstat(path)
        require(stat.S_ISREG(st.st_mode), "certificate.json is not a regular file")
    with open(path, "wb") as fh:
        fh.write(payload)


def sha256(path):
    return hashlib.sha256(read_regular_bytes(path, os.path.basename(path))).hexdigest()


def locked_checker_hash():
    raw = read_regular_bytes(TRACK, "track file")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("track file is not valid UTF-8") from exc
    sections = _CHECKER_SECTION_RE.findall(text)
    if len(sections) != 1:
        return None
    matches = _SHA256_LOCK_RE.findall(sections[0])
    if len(matches) != 1:
        return None
    return matches[0]


def load_locked_checker(checker_path=None):
    """Hash src/flexure440.py bytes first, check the lock, and execute directly from those bytes."""
    path = CHECKER if checker_path is None else checker_path
    locked = locked_checker_hash()
    require(locked is not None, "no unique checker hash locked in the ## Checker section of the track file")
    raw = read_regular_bytes(path, "src/flexure440.py")
    digest = hashlib.sha256(raw).hexdigest()
    require(hmac.compare_digest(digest, locked), "checker differs from the hash locked in the track file")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("src/flexure440.py is not valid UTF-8") from exc
    mod = types.ModuleType("flexure440_locked")
    mod.__file__ = os.path.abspath(path)
    try:
        code = compile(source, mod.__file__, "exec")
        exec(code, mod.__dict__)  # noqa: S102
    except Exception as exc:
        raise VerificationError(f"failed to load locked checker: {exc}") from exc
    require(callable(getattr(mod, "run", None)), "locked checker missing callable run()")
    return mod, digest


def committed_cert_hash():
    raw_sums = read_regular_bytes(COMMITMENT_SUMS, "commitment/SHA256SUMS")
    raw_root = read_regular_bytes(COMMITMENT_ROOT, "commitment/ROOT")
    try:
        root_text = raw_root.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise VerificationError("commitment/ROOT is not valid UTF-8") from exc
    require(_HEX64_RE.fullmatch(root_text) is not None, "commitment/ROOT is not a valid 64-hex sha256 digest")
    actual_sums_sha = hashlib.sha256(raw_sums).hexdigest()
    require(
        hmac.compare_digest(actual_sums_sha, root_text),
        "commitment/SHA256SUMS digest differs from commitment/ROOT",
    )
    try:
        text = raw_sums.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("commitment/SHA256SUMS is not valid UTF-8") from exc
    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "results/track-1-flexure/certificate.json":
            require(_HEX64_RE.fullmatch(parts[0]) is not None, "invalid sha256 entry in commitment/SHA256SUMS")
            found.append(parts[0])
    require(len(found) == 1, "commitment/SHA256SUMS must list exactly one results/track-1-flexure/certificate.json digest")
    return found[0]


def resolve(out, dotted):
    node = out
    for part in dotted.split("."):
        require(isinstance(node, dict) and part in node, f"missing checker field {dotted!r}")
        node = node[part]
    return node


def build(when):
    when = validate_iso_date(when)
    raw_inp = read_regular_bytes(INPUT, "input.json")
    inp = parse_strict_json_bytes(raw_inp, "input.json")
    exp_doc = parse_strict_json_bytes(read_regular_bytes(EXPECTED, "expected.json"), "expected.json")
    require(isinstance(inp, dict) and "source" in inp, "input.json missing required 'source' field")
    require(isinstance(exp_doc, dict) and isinstance(exp_doc.get("values"), dict), "expected.json missing 'values' mapping")
    exp = exp_doc["values"]
    checker_mod, checker_sha = load_locked_checker()
    try:
        out = checker_mod.run(inp)
    except Exception as exc:
        raise VerificationError(f"checker execution failed: {exc}") from exc
    require(isinstance(out, dict), "checker output must be a dict")
    try:
        st = out["section"]
        values = {
            "As_min_in2": round(strict_finite(out["As_min_in2"], "As_min_in2"), 2),
            "Mu_kipft": round(strict_finite(out["design_demand_Mu_kipft"], "Mu_kipft"), 1),
            "design_ffu_ksi": round(strict_finite(out["design_material"]["ffu_ksi"], "design_ffu_ksi"), 1),
            "efd": round(strict_finite(out["efd"], "efd"), 4),
            "existing_phiMn_kipft": round(strict_finite(out["existing"]["phiMn_kipft"], "existing_phiMn_kipft"), 1),
            "limit_demand_kipft": round(strict_finite(out["strengthening_limit"]["limit_demand_kipft"], "limit_demand_kipft"), 1),
            "phiMn_kipft": round(strict_finite(out["phiMn_kipft"], "phiMn_kipft"), 1),
            "section_Mn_kipft": round(strict_finite(out["Mn_kipft"], "section_Mn_kipft"), 1),
            "section_c_in": round(strict_finite(st["c_in"], "section_c_in"), 2),
            "section_ec": round(strict_finite(st["ec"], "section_ec"), 4),
            "section_efe": round(strict_finite(st["efe"], "section_efe"), 4),
            "section_es": round(strict_finite(st["es"], "section_es"), 4),
            "section_ffe_ksi": round(strict_finite(st["ffe_ksi"], "section_ffe_ksi"), 1),
            "section_fs_ksi": round(strict_finite(st["fs_ksi"], "section_fs_ksi"), 1),
            "section_mode": st["mode"],
            "service_ff_ksi": round(strict_finite(out["service"]["ff_service_ksi"], "service_ff_ksi"), 1),
            "service_fs_ksi": round(strict_finite(out["service"]["fs_service_ksi"], "service_fs_ksi"), 1),
            "service_k": round(strict_finite(out["service"]["k"], "service_k"), 4),
            "service_kd_in": round(strict_finite(out["service"]["kd_in"], "service_kd_in"), 2),
        }
        printed = {}
        for key, spec in exp.items():
            raw = strict_finite(resolve(out, spec["field"]), f"printed.{key}.raw")
            printed_val = strict_finite(spec["printed"], f"printed.{key}.printed")
            tol_val = strict_finite(spec["tol"], f"printed.{key}.tol")
            printed[key] = {
                "printed": spec["printed"],
                "checker": round(raw, 6),
                "tol": spec["tol"],
                "match": abs(raw - printed_val) <= tol_val,
            }
        checks = {name: bool(ok) for name, _v, _l, ok in out["checks"]
                  if not name.startswith("Debonding strain")}
        cap = 0.9 * strict_finite(out["design_material"]["efu"], "design_material.efu")
        efd_val = strict_finite(out["efd"], "efd")
        efd_cap = strict_finite_min(out["efd_uncapped"], cap, "efd_cap")
        checks["Debonding cap applied, efd = min(formula, 0.9 efu)"] = abs(efd_val - efd_cap) < 1e-12
    except VerificationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError(f"malformed checker or expected output: {exc}") from exc
    return {
        "result": "track-1-flexure",
        "date": when,
        "checker": {"path": "src/flexure440.py", "sha256": checker_sha},
        "input": {"path": "tracks/track-1/input.json", "sha256": hashlib.sha256(raw_inp).hexdigest()},
        "source": inp["source"],
        "values": values,
        "checks_pass": checks,
        "printed_match": printed,
    }


def failures(cert):
    """Every reason this certificate must not be trusted or written."""
    bad = []
    locked = locked_checker_hash()
    if locked is None:
        bad.append("no unique checker hash locked in the ## Checker section of the track file")
    elif not hmac.compare_digest(cert["checker"]["sha256"], locked):
        bad.append("checker differs from the hash locked in the track file")
    for key, row in cert["printed_match"].items():
        if not row["match"]:
            bad.append(f"printed {key}: checker {row['checker']} "
                       f"vs printed {row['printed']} (tol {row['tol']})")
    for name, passed in cert["checks_pass"].items():
        if not passed:
            bad.append(f"check failed: {name}")
    return bad


def _verify_saved_certificate():
    raw_cert = read_regular_bytes(CERT, "certificate.json")
    saved = parse_strict_json_bytes(raw_cert, "certificate.json")
    require(isinstance(saved, dict), "certificate.json must be a JSON object")
    when = validate_iso_date(saved.get("date"))
    fresh = build(when)
    expected_bytes = render_canonical_cert_bytes(fresh)
    ok = True
    if not hmac.compare_digest(raw_cert, expected_bytes):
        ok = False
        print("FAIL  certificate does not replay canonically from the input file")
        for key in sorted(set(fresh) | set(saved)):
            if fresh.get(key) != saved.get(key):
                print(f"  differs: {key}")
    committed = committed_cert_hash()
    actual_sha = hashlib.sha256(raw_cert).hexdigest()
    if not hmac.compare_digest(actual_sha, committed):
        ok = False
        print("FAIL  certificate digest differs from commitment/SHA256SUMS")
    for line in failures(fresh):
        ok = False
        print(f"FAIL  {line}")
    for key, row in fresh["printed_match"].items():
        print(f"{'PASS' if row['match'] else 'FAIL'}  printed {key}: "
              f"checker {row['checker']} vs printed {row['printed']} (tol {row['tol']})")
    for name, passed in fresh["checks_pass"].items():
        print(f"{'PASS' if passed else 'FAIL'}  check {name}")
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


def _write_certificate():
    _require_no_symlink_target(CERT, "certificate.json")
    existing_raw = None
    preserved_date = None
    if os.path.lexists(CERT):
        existing_raw = read_regular_bytes(CERT, "certificate.json")
        try:
            committed = committed_cert_hash()
            if hmac.compare_digest(hashlib.sha256(existing_raw).hexdigest(), committed):
                saved = parse_strict_json_bytes(existing_raw, "certificate.json")
                if isinstance(saved, dict):
                    preserved_date = validate_iso_date(saved.get("date"))
        except VerificationError:
            preserved_date = None
    cert = build(preserved_date if preserved_date is not None else date.today().isoformat())
    bad = failures(cert)
    if bad:
        for line in bad:
            print(f"FAIL  {line}")
        print("certificate not written")
        return 1
    rendered = render_canonical_cert_bytes(cert)
    if existing_raw is not None and not hmac.compare_digest(existing_raw, rendered):
        cert = build(date.today().isoformat())
        rendered = render_canonical_cert_bytes(cert)
    write_canonical_cert_bytes(CERT, rendered)
    print(f"wrote {CERT}")
    return 0


def main(argv):
    try:
        require(argv in ([], ["--write"]), f"unexpected arguments: {argv!r}")
        if argv == ["--write"]:
            return _write_certificate()
        return _verify_saved_certificate()
    except VerificationError as exc:
        print(f"FAIL  {exc}")
        print("RESULT: FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
