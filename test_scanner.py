import csv
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import requests

import scanner

API_KEY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
GOOD_HASH = "a" * 64


def fake_response(status=200, payload=None, headers=None, bad_json=False):
    resp = mock.MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    if bad_json:
        resp.json.side_effect = ValueError("não é json")
    else:
        resp.json.return_value = payload
    return resp


def vt_payload(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious,
        "harmless": harmless, "undetected": undetected}}}}


def make_client(*responses_or_errors):
    client = scanner.VTClient(API_KEY, interval=0)
    client.session = mock.MagicMock()
    client.session.get.side_effect = list(responses_or_errors)
    return client


class UtilityTests(unittest.TestCase):
    def test_sha256_known_vector(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "abc.bin"
            p.write_bytes(b"abc")
            self.assertEqual(
                scanner.sha256_of_file(p),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_sha256_multiple_chunks_matches_hashlib(self):
        data = os.urandom(scanner.CHUNK_SIZE * 3 + 17)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.bin"
            p.write_bytes(data)
            self.assertEqual(scanner.sha256_of_file(p), hashlib.sha256(data).hexdigest())

    def test_sanitize_removes_control_and_bidi_chars(self):
        evil = "foto\x1b[31m.jpg\u202eexe.txt\n"
        clean = scanner.sanitize_for_terminal(evil)
        self.assertNotIn("\x1b", clean)
        self.assertNotIn("\u202e", clean)
        self.assertNotIn("\n", clean)

    def test_csv_safe_neutralizes_formulas(self):
        for dangerous in ("=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"):
            self.assertTrue(scanner.csv_safe(dangerous).startswith("'"))
        self.assertEqual(scanner.csv_safe("normal.pdf"), "normal.pdf")
        self.assertEqual(scanner.csv_safe(5), 5)

    def test_as_int_rejects_bad_values(self):
        self.assertEqual(scanner._as_int(True), 0)
        self.assertEqual(scanner._as_int(-3), 0)
        self.assertEqual(scanner._as_int("9"), 0)
        self.assertEqual(scanner._as_int(7), 7)


class CollectFilesTests(unittest.TestCase):
    def test_skips_symlinks_and_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.txt"
            real.write_text("x")
            (root / "link.txt").symlink_to(real)
            files, skipped, truncated = scanner.collect_files(
                [str(root), str(root / "nao_existe")], recursive=True, max_files=10)
            self.assertEqual(files, [real])
            reasons = [r for _, r in skipped]
            self.assertIn("link simbólico ignorado", reasons)
            self.assertIn("caminho não encontrado", reasons)
            self.assertFalse(truncated)

    def test_recursive_does_not_follow_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            (Path(outside) / "secret.txt").write_text("segredo")
            root = Path(tmp)
            (root / "dentro.txt").write_text("ok")
            (root / "atalho").symlink_to(outside, target_is_directory=True)
            files, _, _ = scanner.collect_files([str(root)], recursive=True, max_files=10)
            self.assertEqual([f.name for f in files], ["dentro.txt"])

    def test_non_recursive_ignores_subfolders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("a")
            (root / "sub").mkdir()
            (root / "sub" / "b.txt").write_text("b")
            files, _, _ = scanner.collect_files([str(root)], recursive=False, max_files=10)
            self.assertEqual([f.name for f in files], ["a.txt"])

    def test_truncates_at_max_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(5):
                (Path(tmp) / f"f{i}.txt").write_text("x")
            files, _, truncated = scanner.collect_files([tmp], recursive=False, max_files=3)
            self.assertEqual(len(files), 3)
            self.assertTrue(truncated)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo indisponível")
    def test_fifo_is_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "pipe"
            os.mkfifo(fifo)
            files, skipped, _ = scanner.collect_files([str(fifo)], False, 10)
            self.assertEqual(files, [])
            self.assertEqual(skipped[0][1], "não é um arquivo comum")


@mock.patch("scanner.time.sleep")
class ClientTests(unittest.TestCase):
    def test_known_file(self, _sleep):
        client = make_client(fake_response(200, vt_payload(malicious=3)))
        stats = client.lookup(GOOD_HASH)
        self.assertEqual(stats["malicious"], 3)

    def test_unknown_file_returns_none(self, _sleep):
        client = make_client(fake_response(404))
        self.assertIsNone(client.lookup(GOOD_HASH))

    def test_rate_limit_then_success(self, sleep):
        client = make_client(
            fake_response(429, headers={"Retry-After": "5"}),
            fake_response(200, vt_payload()),
        )
        self.assertEqual(client.lookup(GOOD_HASH)["malicious"], 0)
        sleep.assert_any_call(5)

    def test_retry_after_is_capped(self, sleep):
        client = make_client(
            fake_response(429, headers={"Retry-After": "99999"}),
            fake_response(200, vt_payload()),
        )
        client.lookup(GOOD_HASH)
        sleep.assert_any_call(scanner.MAX_RETRY_WAIT)

    def test_invalid_retry_after_uses_default(self, sleep):
        client = make_client(
            fake_response(429, headers={"Retry-After": "abc"}),
            fake_response(200, vt_payload()),
        )
        client.lookup(GOOD_HASH)
        sleep.assert_any_call(60)

    def test_gives_up_after_max_retries(self, _sleep):
        client = make_client(*[fake_response(429)] * scanner.MAX_RETRIES)
        with self.assertRaises(scanner.VTError):
            client.lookup(GOOD_HASH)

    def test_auth_error_and_key_not_leaked(self, _sleep):
        client = make_client(fake_response(401))
        with self.assertRaises(scanner.VTAuthError) as ctx:
            client.lookup(GOOD_HASH)
        self.assertNotIn(API_KEY, str(ctx.exception))

    def test_unexpected_status(self, _sleep):
        client = make_client(fake_response(500))
        with self.assertRaises(scanner.VTError):
            client.lookup(GOOD_HASH)

    def test_redirect_is_not_followed(self, _sleep):
        client = make_client(fake_response(302))
        with self.assertRaises(scanner.VTError):
            client.lookup(GOOD_HASH)
        _, kwargs = client.session.get.call_args
        self.assertFalse(kwargs["allow_redirects"])

    def test_invalid_json(self, _sleep):
        client = make_client(fake_response(200, bad_json=True))
        with self.assertRaises(scanner.VTError):
            client.lookup(GOOD_HASH)

    def test_unexpected_payload_shape(self, _sleep):
        for payload in ({}, {"data": 1}, {"data": {"attributes": {"last_analysis_stats": "x"}}}, None):
            client = make_client(fake_response(200, payload))
            with self.assertRaises(scanner.VTError):
                client.lookup(GOOD_HASH)

    def test_network_errors_retry_then_fail_without_leaking(self, _sleep):
        err = requests.ConnectionError(f"falhou com chave {API_KEY}")
        client = make_client(*[err] * scanner.MAX_RETRIES)
        with self.assertRaises(scanner.VTError) as ctx:
            client.lookup(GOOD_HASH)
        self.assertNotIn(API_KEY, str(ctx.exception))

    def test_rejects_invalid_hash(self, _sleep):
        client = make_client()
        for bad in ("", "xyz", "A" * 64, "a" * 63, "a" * 64 + "/../x", "a" * 64 + "?x=1"):
            with self.assertRaises(ValueError):
                client.lookup(bad)
        client.session.get.assert_not_called()


class ScanLogicTests(unittest.TestCase):
    def test_verdicts(self):
        self.assertIn("MALICIOSO", scanner.build_verdict("known", 2, 0))
        self.assertIn("SUSPEITO", scanner.build_verdict("known", 0, 1))
        self.assertIn("NÃO garante", scanner.build_verdict("known", 0, 0))
        self.assertIn("NÃO significa", scanner.build_verdict("unknown", 0, 0))

    def test_scan_one_unreadable_file(self):
        client = mock.MagicMock()
        result = scanner.scan_one(client, Path("/caminho/que/nao/existe.bin"))
        self.assertEqual(result.status, "error")
        client.lookup.assert_not_called()

    def test_scan_one_auth_error_propagates(self):
        client = mock.MagicMock()
        client.lookup.side_effect = scanner.VTAuthError("x")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.bin"
            p.write_bytes(b"a")
            with self.assertRaises(scanner.VTAuthError):
                scanner.scan_one(client, p)


class ExportTests(unittest.TestCase):
    def sample(self):
        return [scanner.ScanResult(path="=HYPERLINK(\"http://x\")", sha256=GOOD_HASH,
                                   status="known", verdict="SEM DETECÇÕES")]

    def test_json_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            j, c = Path(tmp) / "r.json", Path(tmp) / "r.csv"
            scanner.export_json(self.sample(), str(j))
            scanner.export_csv(self.sample(), str(c))
            self.assertEqual(json.loads(j.read_text(encoding="utf-8"))[0]["sha256"], GOOD_HASH)
            rows = list(csv.DictReader(io.StringIO(c.read_text(encoding="utf-8"))))
            self.assertTrue(rows[0]["path"].startswith("'="))

    def test_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "r.json"
            dest.write_text("original")
            with self.assertRaises(FileExistsError):
                scanner.export_json(self.sample(), str(dest))
            self.assertEqual(dest.read_text(), "original")

    def test_does_not_follow_existing_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "importante.txt"
            target.write_text("não toque")
            link = Path(tmp) / "r.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                scanner.export_json(self.sample(), str(link))
            self.assertEqual(target.read_text(), "não toque")


class MainTests(unittest.TestCase):
    def run_main(self, argv, stats):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("scanner.load_api_key", return_value=API_KEY), \
                mock.patch.object(scanner.VTClient, "lookup", return_value=stats), \
                redirect_stdout(out), redirect_stderr(err):
            code = scanner.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_file_exit_zero_and_key_not_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_text("ola")
            stats = {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 5}
            code, out, err = self.run_main([str(p), "--interval", "0"], stats)
            self.assertEqual(code, 0)
            self.assertNotIn(API_KEY, out + err)

    def test_malicious_file_exit_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_text("ola")
            stats = {"malicious": 5, "suspicious": 0, "harmless": 0, "undetected": 5}
            code, out, _ = self.run_main([str(p), "--interval", "0"], stats)
            self.assertEqual(code, 1)
            self.assertIn("MALICIOSO", out)

    def test_nothing_to_scan_exit_two(self):
        code, _, err = self.run_main(["/nao/existe", "--interval", "0"], None)
        self.assertEqual(code, 2)
        self.assertIn("Nenhum arquivo", err)

    def test_invalid_args_rejected(self):
        for argv in (["x", "--max-files", "0"], ["x", "--interval", "-1"]):
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                scanner.build_parser().parse_args(argv)


class ApiKeyTests(unittest.TestCase):
    def test_missing_key_exits(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("scanner.load_dotenv"):
            with self.assertRaises(SystemExit):
                scanner.load_api_key()

    def test_malformed_key_exits(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": "chave com espaço\nX-Evil: 1"}), \
                mock.patch("scanner.load_dotenv"):
            with self.assertRaises(SystemExit):
                scanner.load_api_key()

    def test_valid_key(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": f" {API_KEY} "}), \
                mock.patch("scanner.load_dotenv"):
            self.assertEqual(scanner.load_api_key(), API_KEY)


if __name__ == "__main__":
    unittest.main()