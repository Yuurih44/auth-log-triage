"""Triagem offline de eventos JSONL de autenticação. Apenas biblioteca padrão."""

import argparse
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def parse_event(line):
    """Normaliza campos necessários sem manter senhas, usuários ou campos extras."""
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("Evento deve ser um objeto")
    stamp = value.get("timestamp")
    source = value.get("source_ip")
    outcome = value.get("outcome")
    if not isinstance(stamp, str) or not isinstance(source, str):
        raise ValueError("Timestamp e IP são obrigatórios")
    timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Timestamp precisa de fuso horário")
    if outcome not in ("success", "failure"):
        raise ValueError("Outcome deve ser success ou failure")
    return timestamp, str(ipaddress.ip_address(source)), outcome


def analyze(lines, threshold=5, window_seconds=300):
    """Retorna uma evidência por IP: a primeira janela que atinge o limite."""
    if threshold < 2 or window_seconds < 1:
        raise ValueError("Limite mínimo 2; janela mínima 1 segundo")
    counts = Counter()
    failures = defaultdict(list)
    invalid_lines = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            timestamp, source, outcome = parse_event(line)
        except (ValueError, TypeError, OverflowError, RecursionError):
            invalid_lines.append(number)
            continue
        counts[outcome] += 1
        if outcome == "failure":
            failures[source].append(timestamp)

    findings = []
    window = timedelta(seconds=window_seconds)
    for source, timestamps in sorted(failures.items()):
        timestamps.sort()
        left = 0
        for right, end in enumerate(timestamps):
            while end - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                findings.append(
                    {
                        "rule": "repeated_auth_failures",
                        "source_ip": source,
                        "failures_in_window": count,
                        "window_start": timestamps[left].isoformat(),
                        "window_end": end.isoformat(),
                        "interpretation": "Revisar contexto; não comprova ataque ou invasão.",
                    }
                )
                break
    return {
        "valid_events": counts.total(),
        "successes": counts["success"],
        "failures": counts["failure"],
        "invalid_line_numbers": invalid_lines,
        "configuration": {"threshold": threshold, "window_seconds": window_seconds},
        "findings": findings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Arquivo JSONL local")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        with args.input.open(encoding="utf-8") as stream:
            report = analyze(stream, args.threshold, args.window_seconds)
    except (OSError, UnicodeError, ValueError, OverflowError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
