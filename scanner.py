from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Iterator, Optional

import requests
from dotenv import load_dotenv

API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"

CHUNK_SIZE = 1024 * 1024  # lê o arquivo em blocos de 1 MB (não carrega tudo na memória)
REQUEST_TIMEOUT = 15  # segundos
DEFAULT_INTERVAL = 15.5  # segundos entre consultas (conservador; confira o limite do seu plano)
MAX_RETRIES = 3
MAX_RETRY_WAIT = 90  # espera máxima, em segundos, ao receber 429
DEFAULT_MAX_FILES = 100

ENV_PATH = Path(__file__).resolve().parent / ".env"

SHA256_RE = re.compile(r"[0-9a-f]{64}")
API_KEY_RE = re.compile(r"[A-Za-z0-9]{16,128}")
# Caracteres de controle e de inversão de texto (podem enganar ou manipular o terminal).
UNSAFE_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
# Prefixos que planilhas interpretam como fórmula ("CSV injection").
CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class VTError(Exception):
    """Erro ao consultar o VirusTotal."""


class VTAuthError(VTError):
    """Chave de API inválida ou sem permissão (não adianta continuar)."""


@dataclass
class ScanResult:
    path: str
    sha256: Optional[str]
    status: str  # "known", "unknown" ou "error"
    verdict: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    link: str = ""
    detail: str = ""


# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------

def sha256_of_file(path: Path) -> str:
    """Calcula o SHA-256 lendo o arquivo em blocos. Só lê bytes, nunca interpreta."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_for_terminal(text: str) -> str:
    """Troca caracteres de controle por '?' (nomes de arquivo podem ser maliciosos)."""
    return UNSAFE_CHARS_RE.sub("?", str(text))


def csv_safe(value: object) -> object:
    """Neutraliza texto que uma planilha trataria como fórmula."""
    if isinstance(value, str) and value.startswith(CSV_DANGEROUS_PREFIXES):
        return "'" + value
    return value


def _as_int(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


# --------------------------------------------------------------------------
# Coleta de arquivos
# --------------------------------------------------------------------------

def _classify(path: Path) -> Iterator[tuple[Path, Optional[str]]]:
    if path.is_symlink():
        yield path, "link simbólico ignorado"
    elif path.is_file():
        yield path, None
    # Diretórios e arquivos especiais (pipes, sockets) são ignorados em silêncio.


def _walk(target: Path, recursive: bool) -> Iterator[tuple[Path, Optional[str]]]:
    if target.is_symlink():
        yield target, "link simbólico ignorado"
    elif target.is_file():
        yield target, None
    elif target.is_dir():
        if recursive:
            for root, dirs, names in os.walk(target, followlinks=False):
                dirs.sort()
                for name in sorted(names):
                    yield from _classify(Path(root) / name)
        else:
            for child in sorted(target.iterdir()):
                yield from _classify(child)
    elif target.exists():
        yield target, "não é um arquivo comum"
    else:
        yield target, "caminho não encontrado"


def collect_files(
    targets: list[str], recursive: bool, max_files: int
) -> tuple[list[Path], list[tuple[str, str]], bool]:
    """Retorna (arquivos, ignorados com motivo, truncou_pelo_limite)."""
    files: list[Path] = []
    skipped: list[tuple[str, str]] = []
    truncated = False
    for raw in targets:
        try:
            for path, reason in _walk(Path(raw), recursive):
                if reason:
                    skipped.append((str(path), reason))
                    continue
                if len(files) >= max_files:
                    truncated = True
                    break
                files.append(path)
        except OSError as exc:
            skipped.append((raw, f"erro ao listar: {exc.strerror or type(exc).__name__}"))
        if truncated:
            break
    return files, skipped, truncated


# --------------------------------------------------------------------------
# Cliente do VirusTotal
# --------------------------------------------------------------------------

def extract_stats(payload: object) -> dict[str, int]:
    try:
        raw = payload["data"]["attributes"]["last_analysis_stats"]  # type: ignore[index]
    except (KeyError, TypeError):
        raise VTError("resposta da API em formato inesperado") from None
    if not isinstance(raw, dict):
        raise VTError("resposta da API em formato inesperado")
    return {
        key: _as_int(raw.get(key))
        for key in ("malicious", "suspicious", "harmless", "undetected")
    }


class VTClient:
    def __init__(self, api_key: str, interval: float = DEFAULT_INTERVAL) -> None:
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "Accept": "application/json"})
        self.interval = interval
        self._last_request: Optional[float] = None

    def _wait_turn(self) -> None:
        if self._last_request is not None:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
        self._last_request = time.monotonic()

    def lookup(self, sha256: str) -> Optional[dict[str, int]]:
        """Devolve as estatísticas da análise, ou None se o VirusTotal não conhece o hash."""
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError("hash SHA-256 inválido")
        url = API_URL.format(sha256=sha256)

        for attempt in range(1, MAX_RETRIES + 1):
            self._wait_turn()
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException as exc:
                if attempt == MAX_RETRIES:
                    raise VTError(f"falha de rede ({type(exc).__name__})") from None
                continue

            code = resp.status_code
            if code == 200:
                try:
                    payload = resp.json()
                except ValueError:
                    raise VTError("resposta da API não é um JSON válido") from None
                return extract_stats(payload)
            if code == 404:
                return None
            if code in (401, 403):
                raise VTAuthError("chave de API inválida ou sem permissão")
            if code == 429:
                try:
                    wait = int(resp.headers.get("Retry-After", "60"))
                except ValueError:
                    wait = 60
                time.sleep(max(1, min(wait, MAX_RETRY_WAIT)))
                continue
            raise VTError(f"resposta inesperada da API (HTTP {code})")

        raise VTError("limite de tentativas excedido (rede instável ou limite de consultas)")


# --------------------------------------------------------------------------
# Lógica de varredura
# --------------------------------------------------------------------------

def build_verdict(status: str, malicious: int, suspicious: int) -> str:
    if status == "unknown":
        return "DESCONHECIDO (o VirusTotal nunca viu este arquivo; isso NÃO significa que é seguro)"
    if malicious > 0:
        return f"MALICIOSO ({malicious} mecanismo(s) detectaram)"
    if suspicious > 0:
        return f"SUSPEITO ({suspicious} mecanismo(s) marcaram como suspeito)"
    return "SEM DETECÇÕES (isso NÃO garante que o arquivo seja seguro)"


def scan_one(client: VTClient, path: Path) -> ScanResult:
    try:
        digest = sha256_of_file(path)
    except OSError as exc:
        return ScanResult(
            path=str(path), sha256=None, status="error", verdict="ERRO",
            detail=f"não foi possível ler o arquivo: {exc.strerror or type(exc).__name__}",
        )

    link = GUI_URL.format(sha256=digest)
    try:
        stats = client.lookup(digest)
    except VTAuthError:
        raise
    except VTError as exc:
        return ScanResult(
            path=str(path), sha256=digest, status="error", verdict="ERRO",
            link=link, detail=str(exc),
        )

    if stats is None:
        return ScanResult(
            path=str(path), sha256=digest, status="unknown",
            verdict=build_verdict("unknown", 0, 0), link=link,
        )
    return ScanResult(
        path=str(path), sha256=digest, status="known",
        verdict=build_verdict("known", stats["malicious"], stats["suspicious"]),
        malicious=stats["malicious"], suspicious=stats["suspicious"],
        harmless=stats["harmless"], undetected=stats["undetected"], link=link,
    )


def print_result(index: int, total: int, result: ScanResult) -> None:
    print(f"[{index}/{total}] {sanitize_for_terminal(result.path)}")
    if result.sha256:
        print(f"      SHA-256:  {result.sha256}")
    print(f"      Resultado: {sanitize_for_terminal(result.verdict)}")
    if result.detail:
        print(f"      Detalhe:   {sanitize_for_terminal(result.detail)}")
    if result.status == "known":
        print(
            f"      Motores:   {result.malicious} malicioso | {result.suspicious} suspeito | "
            f"{result.harmless} inofensivo | {result.undetected} não detectou"
        )
    if result.link:
        print(f"      Relatório: {result.link}")
    print()


# --------------------------------------------------------------------------
# Exportação (nunca sobrescreve arquivos existentes)
# --------------------------------------------------------------------------

def export_json(results: list[ScanResult], dest: str) -> None:
    with open(dest, "x", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, ensure_ascii=False, indent=2)


def export_csv(results: list[ScanResult], dest: str) -> None:
    columns = [f.name for f in fields(ScanResult)]
    with open(dest, "x", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for result in results:
            writer.writerow({k: csv_safe(v) for k, v in asdict(result).items()})


def _safe_export(func, results: list[ScanResult], dest: str, label: str) -> None:
    try:
        func(results, dest)
        print(f"{label} salvo em: {sanitize_for_terminal(dest)}")
    except FileExistsError:
        print(f"Erro: {sanitize_for_terminal(dest)} já existe; não vou sobrescrever.", file=sys.stderr)
    except OSError as exc:
        print(f"Erro ao salvar {label}: {exc.strerror or type(exc).__name__}", file=sys.stderr)


# --------------------------------------------------------------------------
# Configuração e CLI
# --------------------------------------------------------------------------

def warn_if_env_is_open(env_path: Path) -> None:
    try:
        if env_path.exists() and env_path.stat().st_mode & 0o077:
            print(
                f"Aviso: {env_path.name} pode ser lido por outros usuários. "
                f"Rode: chmod 600 {env_path.name}",
                file=sys.stderr,
            )
    except OSError:
        pass


def load_api_key() -> str:
    warn_if_env_is_open(ENV_PATH)
    load_dotenv(dotenv_path=ENV_PATH)
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        raise SystemExit(
            "Erro: chave da API não encontrada. Copie .env.example para .env "
            "e preencha VT_API_KEY."
        )
    if not API_KEY_RE.fullmatch(key):
        raise SystemExit("Erro: VT_API_KEY tem formato inválido (confira se copiou a chave inteira).")
    return key


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("precisa ser um número inteiro maior que zero")
    return number


def non_negative_float(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("não pode ser negativo")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Consulta a reputação de arquivos no VirusTotal pelo hash SHA-256. "
        "O arquivo não é enviado nem aberto: só o hash é consultado."
    )
    parser.add_argument("paths", nargs="+", help="arquivos ou pastas para verificar")
    parser.add_argument("-r", "--recursive", action="store_true", help="entra nas subpastas")
    parser.add_argument("--max-files", type=positive_int, default=DEFAULT_MAX_FILES,
                        help=f"limite de arquivos por execução (padrão: {DEFAULT_MAX_FILES})")
    parser.add_argument("--interval", type=non_negative_float, default=DEFAULT_INTERVAL,
                        help="segundos entre consultas, para respeitar o limite da API "
                        f"(padrão: {DEFAULT_INTERVAL})")
    parser.add_argument("--json", metavar="ARQUIVO", help="salva o relatório em JSON (novo arquivo)")
    parser.add_argument("--csv", metavar="ARQUIVO", help="salva o relatório em CSV (novo arquivo)")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    api_key = load_api_key()

    files, skipped, truncated = collect_files(args.paths, args.recursive, args.max_files)
    for path, reason in skipped:
        print(f"Ignorado: {sanitize_for_terminal(path)} ({reason})", file=sys.stderr)
    if truncated:
        print(f"Aviso: limite de {args.max_files} arquivos atingido; o restante foi ignorado "
              "(ajuste com --max-files).", file=sys.stderr)
    if not files:
        print("Nenhum arquivo para verificar.", file=sys.stderr)
        return 2

    minutes = len(files) * args.interval / 60
    if minutes >= 1:
        print(f"{len(files)} arquivo(s); tempo estimado: cerca de {minutes:.0f} min.\n")

    client = VTClient(api_key, args.interval)
    results: list[ScanResult] = []
    try:
        for index, path in enumerate(files, 1):
            result = scan_one(client, path)
            results.append(result)
            print_result(index, len(files), result)
    except VTAuthError as exc:
        print(f"Erro: {exc}. Interrompendo.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário; salvando o que já foi verificado.", file=sys.stderr)

    if args.json:
        _safe_export(export_json, results, args.json, "JSON")
    if args.csv:
        _safe_export(export_csv, results, args.csv, "CSV")

    flagged = sum(1 for r in results if r.malicious or r.suspicious)
    unknown = sum(1 for r in results if r.status == "unknown")
    errors = sum(1 for r in results if r.status == "error")
    print(f"Resumo: {len(results)} verificado(s) | {flagged} com alerta | "
          f"{unknown} desconhecido(s) | {errors} com erro")

    if flagged:
        return 1
    if errors:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())