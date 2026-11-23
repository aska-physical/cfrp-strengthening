"""
Zone-B, DATE_ECHO_FORGERY, NaN-clamping, hash-before-exec checker-lock,
and commitment/ROOT hardening tests for results/track-1-flexure/verify.py.

Pure Python 3 stdlib. Zero bare assert statements (100% R4 parity under
-I -B, -I -O -B, and -I -B -W error).
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
VERIFY_PATH = ROOT / "results" / "track-1-flexure" / "verify.py"


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _load_verify_module():
    spec = importlib.util.spec_from_file_location("track1_verify_mod", VERIFY_PATH)
    _req(spec is not None and spec.loader is not None, "could not load verify.py spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_vmod(vmod, argv: list[str], **patches: str) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.ExitStack() as stack:
        for attr, val in patches.items():
            stack.enter_context(mock.patch.object(vmod, attr, val))
        stack.enter_context(contextlib.redirect_stdout(buf))
        rc = vmod.main(argv)
    return rc, buf.getvalue()


class Track1VerifyZoneBTests(unittest.TestCase):
    def test_01_three_mode_isolated_parity_and_idempotent_write(self) -> None:
        outputs: list[str] = []
        for flags in (["-I", "-B"], ["-I", "-O", "-B"], ["-I", "-B", "-W", "error"]):
            proc = subprocess.run(
                [sys.executable, *flags, "results/track-1-flexure/verify.py"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            _req(proc.returncode == 0, f"flags={flags} rc={proc.returncode} out={proc.stdout} err={proc.stderr}")
            _req("RESULT: PASS" in proc.stdout, f"missing PASS marker: {proc.stdout!r}")
            outputs.append(proc.stdout)
        _req(outputs[0] == outputs[1] == outputs[2], "verify.py stdout differed across isolated R4 modes")

        vmod = _load_verify_module()
        orig_bytes = (ROOT / "results" / "track-1-flexure" / "certificate.json").read_bytes()
        with tempfile.TemporaryDirectory() as td:
            cert_path = Path(td).resolve() / "certificate.json"
            cert_path.write_bytes(orig_bytes)
            rc_w, out_w = _run_vmod(vmod, ["--write"], CERT=str(cert_path))
            _req(rc_w == 0 and "wrote " in out_w, f"--write failed: {rc_w} {out_w}")
            _req(cert_path.read_bytes() == orig_bytes, "--write drifted from committed canonical bytes")

            rc_bad, out_bad = _run_vmod(vmod, ["--bogus"], CERT=str(cert_path))
            _req(rc_bad == 1 and "RESULT: FAIL" in out_bad, f"--bogus failed: {rc_bad} {out_bad}")

    def test_02_date_echo_forgery_commitment_root_and_write_date_policy(self) -> None:
        vmod = _load_verify_module()
        orig_text = (ROOT / "results" / "track-1-flexure" / "certificate.json").read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            cert_path = base / "certificate.json"
            for label, bad_date in (
                ("invalid_9999", '"9999-99-99"'),
                ("invalid_feb30", '"2026-02-30"'),
                ("trailing_newline", '"2026-10-25\\n"'),
                ("non_string_int", "20261025"),
                ("valid_iso_but_forged_date", '"2099-01-01"'),
            ):
                cert_path.write_text(orig_text.replace('"2026-10-25"', bad_date, 1), encoding="utf-8")
                rc, out = _run_vmod(vmod, [], CERT=str(cert_path))
                _req(rc == 1 and "RESULT: FAIL" in out, f"{label}: rc={rc} out={out}")

            # --write MUST NOT echo an unverified/forged valid ISO date (DeepSeek Finding C)
            cert_path.write_text(orig_text.replace('"2026-10-25"', '"2099-01-01"', 1), encoding="utf-8")
            rc_w, out_w = _run_vmod(vmod, ["--write"], CERT=str(cert_path))
            _req(rc_w == 0, f"--write on forged date failed: {rc_w} {out_w}")
            written_text = cert_path.read_text(encoding="utf-8")
            _req('"2099-01-01"' not in written_text, "--write echoed unverified forged date 2099-01-01")
            _req(f'"{datetime.date.today().isoformat()}"' in written_text, "--write did not stamp today's ISO date")

            # Tampering commitment/SHA256SUMS to match forged cert is caught by commitment/ROOT!
            forged_bytes = orig_text.replace('"2026-10-25"', '"2099-01-01"', 1).encode("utf-8")
            cert_path.write_bytes(forged_bytes)
            forged_sha = hashlib.sha256(forged_bytes).hexdigest()
            orig_sums = (ROOT / "commitment" / "SHA256SUMS").read_text(encoding="utf-8")
            fake_sums = base / "SHA256SUMS"
            fake_sums.write_text(
                orig_sums.replace(
                    "6d827c5911e7e8e270d4fa31533913d73097324e2018016a2994a706a3416055",
                    forged_sha,
                ),
                encoding="utf-8",
            )
            rc_root, out_root = _run_vmod(vmod, [], CERT=str(cert_path), COMMITMENT_SUMS=str(fake_sums))
            _req(rc_root == 1 and "commitment/ROOT" in out_root, f"ROOT mismatch not caught: {rc_root} {out_root}")

            # Corrupt / non-UTF-8 / invalid-hex commitment/ROOT fails closed
            bad_root = base / "ROOT"
            bad_root.write_text("not-a-hex-digest\n", encoding="utf-8")
            rc_rh, out_rh = _run_vmod(vmod, [], COMMITMENT_ROOT=str(bad_root))
            _req(rc_rh == 1 and "64-hex" in out_rh, f"bad ROOT hex: {rc_rh} {out_rh}")
            bad_root.write_bytes(b"\xff\xfe")
            rc_ru, out_ru = _run_vmod(vmod, [], COMMITMENT_ROOT=str(bad_root))
            _req(rc_ru == 1 and "not valid UTF-8" in out_ru, f"bad ROOT utf8: {rc_ru} {out_ru}")

        # Live subprocess check of exact S21c witness ("9999-99-99")
        with tempfile.TemporaryDirectory() as td:
            work = Path(td).resolve() / "repo"
            shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            (work / "results" / "track-1-flexure" / "certificate.json").write_text(
                orig_text.replace('"2026-10-25"', '"9999-99-99"', 1), encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, "-I", "-O", "-B", "results/track-1-flexure/verify.py"],
                cwd=work,
                text=True,
                capture_output=True,
                check=False,
            )
            _req(proc.returncode == 1 and "RESULT: FAIL" in proc.stdout and "Traceback" not in proc.stderr, proc.stderr)

        _req(vmod.validate_iso_date("2026-10-25") == "2026-10-25", "valid ISO date rejected")
        for bad in (None, 123, "2026-10-25\n", "9999-99-99", "2026-02-30", "2026/10/25", "20261025", "2026-W43-7"):
            try:
                vmod.validate_iso_date(bad)
            except vmod.VerificationError:
                pass
            else:
                raise AssertionError(f"validate_iso_date({bad!r}) did not reject")

    def test_03_zoneb_certificate_bypasses_and_crashes_rejected_cleanly(self) -> None:
        vmod = _load_verify_module()
        orig_bytes = (ROOT / "results" / "track-1-flexure" / "certificate.json").read_bytes()
        orig_text = orig_bytes.decode("utf-8")

        cases = {
            "ZB03_5000_digit_int": orig_text.replace('"As_min_in2": 1.12', '"As_min_in2": ' + ("9" * 5000), 1),
            "ZB06_bool_as_int": orig_text.replace('"match": true', '"match": 1', 1),
            "ZB07_duplicate_key": orig_text.replace('"result": "track-1-flexure",', '"result": "x",\n  "result": "track-1-flexure",', 1),
            "ZB08_int_as_float_style": orig_text.replace('"section_fs_ksi": 60.0', '"section_fs_ksi": 60', 1),
            "ZB10_crlf": orig_text.replace("\n", "\r\n"),
            "ZB16_truncated": orig_text[:45],
            "non_object_list": "[]\n",
            "json_nan_constant": orig_text.replace('"As_min_in2": 1.12', '"As_min_in2": NaN', 1),
            "json_overflow_float_1e999": orig_text.replace('"As_min_in2": 1.12', '"As_min_in2": 1e999', 1),
        }
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            cert_path = base / "certificate.json"

            for label, bad_text in cases.items():
                cert_path.write_bytes(bad_text.encode("utf-8"))
                rc, out = _run_vmod(vmod, [], CERT=str(cert_path))
                _req(rc == 1 and "RESULT: FAIL" in out, f"{label}: rc={rc} out={out}")

            # ZB16 invalid UTF-8
            cert_path.write_bytes(b"\xff\xfe\x00")
            rc, out = _run_vmod(vmod, [], CERT=str(cert_path))
            _req(rc == 1 and "not valid UTF-8" in out, f"invalid utf8: {rc} {out}")

            # --write rebuilds an unparseable regular certificate cleanly (#10 item 10)
            rc, out = _run_vmod(vmod, ["--write"], CERT=str(cert_path))
            _req(rc == 0 and cert_path.read_text(encoding="utf-8").startswith("{\n"), f"--write rebuild failed: {rc} {out}")

            # Oversized certificate
            cert_path.write_bytes(b" " * (vmod.MAX_FILE_BYTES + 1))
            rc, out = _run_vmod(vmod, [], CERT=str(cert_path))
            _req(rc == 1 and "size limit" in out, f"oversized: {rc} {out}")

            # Missing certificate (verify fails; --write creates cleanly)
            cert_path.unlink()
            rc, out = _run_vmod(vmod, [], CERT=str(cert_path))
            _req(rc == 1 and "cannot stat" in out, f"missing: {rc} {out}")
            rc, out = _run_vmod(vmod, ["--write"], CERT=str(cert_path))
            _req(rc == 0 and cert_path.is_file(), f"--write create failed: {rc} {out}")
            cert_path.unlink()

            # ZB15 directory at certificate path (both verify and --write)
            cert_path.mkdir()
            for argv in ([], ["--write"]):
                rc, out = _run_vmod(vmod, argv, CERT=str(cert_path))
                _req(rc == 1 and "not a regular file" in out, f"dir {argv}: {rc} {out}")
            cert_path.rmdir()

            # ZB14 symlinked certificate file (both verify and --write)
            outside = base / "outside.json"
            outside.write_bytes(orig_bytes)
            cert_path.symlink_to(outside)
            for argv in ([], ["--write"]):
                rc, out = _run_vmod(vmod, argv, CERT=str(cert_path))
                _req(rc == 1 and "symlink" in out, f"symlink {argv}: {rc} {out}")
            cert_path.unlink()

            # ZB14 deep grandparent symlink (multi-level ancestor walk, DeepSeek Finding D)
            real_top = base / "real_top"
            (real_top / "nested").mkdir(parents=True)
            (real_top / "nested" / "certificate.json").write_bytes(orig_bytes)
            link_top = base / "link_top"
            link_top.symlink_to(real_top, target_is_directory=True)
            for argv in ([], ["--write"]):
                rc, out = _run_vmod(vmod, argv, CERT=str(link_top / "nested" / "certificate.json"))
                _req(rc == 1 and "symlink" in out, f"deep ancestor symlink {argv}: {rc} {out}")

    def test_04_hash_before_exec_checker_lock_nan_and_error_guards(self) -> None:
        vmod = _load_verify_module()

        # DeepSeek Finding A: src/flexure440/ package shadowing cannot hijack hash-before-exec loading
        with tempfile.TemporaryDirectory() as td:
            work = Path(td).resolve() / "repo"
            shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            shadow_pkg = work / "src" / "flexure440"
            shadow_pkg.mkdir()
            (shadow_pkg / "__init__.py").write_text("raise RuntimeError('SHADOW HIJACK')\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-I", "-O", "-B", "results/track-1-flexure/verify.py"],
                cwd=work,
                text=True,
                capture_output=True,
                check=False,
            )
            _req(proc.returncode == 0 and "RESULT: PASS" in proc.stdout, f"package shadow broke verify: {proc.stdout} {proc.stderr}")

            # Tampered src/flexure440.py MUST NOT be executed when hash mismatches lock!
            marker = work / "pwned.flag"
            (work / "src" / "flexure440.py").write_text(
                f"open({str(marker)!r}, 'w').write('ran')\n", encoding="utf-8"
            )
            proc_t = subprocess.run(
                [sys.executable, "-I", "-O", "-B", "results/track-1-flexure/verify.py"],
                cwd=work,
                text=True,
                capture_output=True,
                check=False,
            )
            _req(proc_t.returncode == 1 and "hash locked" in proc_t.stdout, f"tampered checker not rejected: {proc_t.stdout}")
            _req(not marker.exists(), "tampered src/flexure440.py was executed despite lock mismatch!")

        # Direct tests of load_locked_checker error paths (invalid UTF-8, syntax/exec error, missing run)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            for label, payload, expected_sub in (
                ("non_utf8", b"\xff\xfe", "not valid UTF-8"),
                ("bad_syntax", b"def broken(:\n", "failed to load locked checker"),
                ("no_run_fn", b"X = 1\n", "missing callable run()"),
            ):
                p = base / f"{label}.py"
                p.write_bytes(payload)
                h = hashlib.sha256(payload).hexdigest()
                with mock.patch.object(vmod, "locked_checker_hash", return_value=h):
                    try:
                        vmod.load_locked_checker(str(p))
                    except vmod.VerificationError as exc:
                        _req(expected_sub in str(exc), f"{label}: expected {expected_sub!r} in {exc!r}")
                    else:
                        raise AssertionError(f"load_locked_checker accepted {label}")

        # strict_finite_min rejects NaN/Inf/bool instead of swallowing NaN
        _req(vmod.strict_finite_min(0.004, 0.009, "cap") == 0.004, "strict_finite_min lower branch wrong")
        _req(vmod.strict_finite_min(0.009, 0.004, "cap") == 0.004, "strict_finite_min upper branch wrong")
        _req(vmod.strict_finite_min(0.004, 0.004, "cap") == 0.004, "strict_finite_min equal branch wrong")
        for pair in ((0.004, float("nan")), (float("nan"), 0.004), (0.004, float("inf")), (0.004, True)):
            try:
                vmod.strict_finite_min(pair[0], pair[1], "cap")
            except vmod.VerificationError:
                pass
            else:
                raise AssertionError(f"strict_finite_min({pair!r}) failed to reject")

        # NaN injected into checker output, checker runtime crash, non-dict output, malformed output dict
        real_mod, real_sha = vmod.load_locked_checker()
        _req(vmod.sha256(vmod.CHECKER) == real_sha, "sha256 helper drifted from load_locked_checker")

        def _make_mod(fn):
            m = types.ModuleType("fake_checker")
            m.run = fn
            return (m, real_sha)

        def _nan_efu(inp):
            res = real_mod.run(inp)
            res["design_material"]["efu"] = float("nan")
            return res

        for label, fn, expected_sub in (
            ("nan_efu", _nan_efu, "must be finite"),
            ("crash_div0", lambda _inp: 1 / 0, "checker execution failed"),
            ("non_dict", lambda _inp: [1, 2, 3], "must be a dict"),
            ("missing_keys", lambda _inp: {}, "malformed checker"),
        ):
            with mock.patch.object(vmod, "load_locked_checker", return_value=_make_mod(fn)):
                try:
                    vmod.build("2026-10-25")
                except vmod.VerificationError as exc:
                    _req(expected_sub in str(exc), f"{label}: expected {expected_sub!r} in {exc!r}")
                else:
                    raise AssertionError(f"build() did not fail on {label}")

        # resolve missing key / non-dict guard
        for bad_out in ({}, {"a": 1}):
            try:
                vmod.resolve(bad_out, "a.b")
            except vmod.VerificationError:
                pass
            else:
                raise AssertionError(f"resolve accepted {bad_out!r}")

        orig_md = (ROOT / "tracks" / "track-1-flexure-example.md").read_text(encoding="utf-8")
        orig_cert_text = (ROOT / "results" / "track-1-flexure" / "certificate.json").read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            track_md = base / "track.md"
            csums = base / "SHA256SUMS"
            croot = base / "ROOT"
            cert_path = base / "certificate.json"
            cert_path.write_text(orig_cert_text, encoding="utf-8")

            # DeepSeek Finding B: prepended fake ## Checker section (2 sections) MUST fail!
            prepended_md = "## Checker\nsha256: " + ("0" * 64) + "\n\n" + orig_md
            track_md.write_text(prepended_md, encoding="utf-8")
            rc, out = _run_vmod(vmod, [], TRACK=str(track_md))
            _req(rc == 1 and "no unique checker hash locked" in out, f"prepended ## Checker not caught: {rc} {out}")

            # Duplicate sha256 inside single ## Checker fails
            track_md.write_text(orig_md.replace("## Checker\n", "## Checker\nsha256: " + ("0" * 64) + "\n", 1), encoding="utf-8")
            rc, out = _run_vmod(vmod, [], TRACK=str(track_md))
            _req(rc == 1 and "no unique checker hash locked" in out, f"dup lock: {rc} {out}")

            # Missing ## Checker section fails (even if sha256 appears elsewhere!)
            track_md.write_text("# Track\nsha256: " + ("a" * 64) + "\n", encoding="utf-8")
            rc, out = _run_vmod(vmod, [], TRACK=str(track_md))
            _req(rc == 1 and "no unique checker hash locked" in out, f"missing section: {rc} {out}")

            # Tampered checker lock hash -> --write refuses to write
            track_md.write_text(orig_md.replace(real_sha, "0" * 64, 1), encoding="utf-8")
            rc, out = _run_vmod(vmod, ["--write"], TRACK=str(track_md), CERT=str(cert_path))
            _req(rc == 1 and "RESULT: FAIL" in out, f"--write lock bypass: {rc} {out}")

            # Invalid UTF-8 track file rejected cleanly
            track_md.write_bytes(b"\xff\xfe")
            rc, out = _run_vmod(vmod, [], TRACK=str(track_md))
            _req(rc == 1 and "not valid UTF-8" in out, f"bad utf8 track: {rc} {out}")

            # Commitment SHA256SUMS parser checks (with matching ROOT!)
            for label, content, expected_sub in (
                ("bad_hex", b"ZZZZ  results/track-1-flexure/certificate.json\n", "invalid sha256"),
                ("missing_entry", b"0000  other.txt\n", "exactly one"),
                ("bad_utf8", b"\xff\xfe", "not valid UTF-8"),
            ):
                csums.write_bytes(content)
                croot.write_text(hashlib.sha256(content).hexdigest() + "\n", encoding="utf-8")
                rc, out = _run_vmod(vmod, [], COMMITMENT_SUMS=str(csums), COMMITMENT_ROOT=str(croot))
                _req(rc == 1 and expected_sub in out, f"{label}: {rc} {out}")

            # --write refreshes date when committed cert values no longer match fresh replay
            stale_bytes = orig_cert_text.replace('"As_min_in2": 1.12', '"As_min_in2": 9.99', 1).encode("utf-8")
            cert_path.write_bytes(stale_bytes)
            stale_sums = f"{hashlib.sha256(stale_bytes).hexdigest()}  results/track-1-flexure/certificate.json\n".encode("utf-8")
            csums.write_bytes(stale_sums)
            croot.write_text(hashlib.sha256(stale_sums).hexdigest() + "\n", encoding="utf-8")
            rc, out = _run_vmod(vmod, ["--write"], CERT=str(cert_path), COMMITMENT_SUMS=str(csums), COMMITMENT_ROOT=str(croot))
            _req(rc == 0 and '"As_min_in2": 1.12' in cert_path.read_text(encoding="utf-8"), f"--write update failed: {rc} {out}")

            # --write refuses when failures(cert) is non-empty
            with mock.patch.object(vmod, "failures", return_value=["forced check failure"]):
                rc, out = _run_vmod(vmod, ["--write"], CERT=str(cert_path))
                _req(rc == 1 and "certificate not written" in out, f"--write failures gate failed: {rc} {out}")

            # Read OSError guard & exact MAX_FILE_BYTES boundary
            p = base / "f.txt"
            p.write_bytes(b"hello")
            with mock.patch.object(vmod, "MAX_FILE_BYTES", 5):
                _req(vmod.read_regular_bytes(str(p), "f.txt") == b"hello", "exact MAX_FILE_BYTES boundary rejected")
            with mock.patch("builtins.open", side_effect=OSError("io fail")):
                try:
                    vmod.read_regular_bytes(str(p), "f.txt")
                except vmod.VerificationError:
                    pass
                else:
                    raise AssertionError("read OSError did not raise VerificationError")

            # Direct duplicate-key & overflow-float JSON rejection
            try:
                vmod.parse_strict_json_bytes(b'{"a":1,"a":2}', "dup.json")
            except vmod.VerificationError as exc:
                _req("duplicate JSON key" in str(exc), f"wrong duplicate-key msg: {exc}")
            else:
                raise AssertionError("parse_strict_json_bytes accepted duplicate keys")
            try:
                vmod.parse_strict_json_bytes(b'{"x":1e999}', "inf.json")
            except vmod.VerificationError as exc:
                _req("non-finite JSON float" in str(exc), f"wrong overflow-float msg: {exc}")
            else:
                raise AssertionError("parse_strict_json_bytes accepted 1e999")

            # write_canonical_cert_bytes directly refuses non-regular path (directory)
            d = base / "dir_target"
            d.mkdir()
            try:
                vmod.write_canonical_cert_bytes(str(d), b"{}\n")
            except vmod.VerificationError:
                pass
            else:
                raise AssertionError("write_canonical_cert_bytes accepted directory")

        _req(vmod._strict_parse_int("-42") == -42, "negative int parsing broken")
        max_tok = "9" * vmod.MAX_INT_DIGITS
        _req(vmod._strict_parse_int(max_tok) == int(max_tok), "exact MAX_INT_DIGITS boundary rejected")
        try:
            vmod._strict_parse_int("-" + ("9" * (vmod.MAX_INT_DIGITS + 1)))
        except vmod.VerificationError:
            pass
        else:
            raise AssertionError("overlong negative int was not rejected")

        # failures() reports locked-missing, locked-mismatch, printed-mismatch, and failed-check
        sample_cert = vmod.build("2026-10-25")
        sample_cert["printed_match"]["efd"]["match"] = False
        sample_cert["checks_pass"]["Design strength, phiMn >= Mu"] = False
        with mock.patch.object(vmod, "locked_checker_hash", return_value=None):
            _req(len(vmod.failures(sample_cert)) == 3, "failures() missed missing lock")
        with mock.patch.object(vmod, "locked_checker_hash", return_value="0" * 64):
            _req(len(vmod.failures(sample_cert)) == 3, "failures() missed mismatched lock")

        # Missing 'source' in input.json (dict without 'source' AND non-dict containing 'source') and missing 'values'
        for bad_inp in ({}, ["source"]):
            with mock.patch.object(vmod, "parse_strict_json_bytes", side_effect=[bad_inp, {"values": {}}]):
                try:
                    vmod.build("2026-10-25")
                except vmod.VerificationError as exc:
                    _req("missing required 'source' field" in str(exc), f"wrong msg for {bad_inp!r}: {exc}")
                else:
                    raise AssertionError(f"build accepted invalid input.json {bad_inp!r}")
        for bad_exp in ({}, {"values": []}):
            with mock.patch.object(vmod, "parse_strict_json_bytes", side_effect=[{"source": "s"}, bad_exp]):
                try:
                    vmod.build("2026-10-25")
                except vmod.VerificationError as exc:
                    _req("missing 'values' mapping" in str(exc), f"wrong msg for {bad_exp!r}: {exc}")
                else:
                    raise AssertionError(f"build accepted invalid expected.json {bad_exp!r}")


if __name__ == "__main__":
    unittest.main()
