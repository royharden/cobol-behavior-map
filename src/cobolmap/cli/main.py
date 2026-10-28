"""Source analysis and supplied dev replay; no oracle/live execution backend."""
import argparse
import hashlib
from pathlib import Path
import sys
from typing import Any, Sequence

from cobolmap.reporting import build_document, render_html, render_json, to_data
from .replay import (MAX_JSON, ReplayRefusal, ReplayUnavailable, forbid_sensitive_parts,
                     load_replay, local_input, strict_json)


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cbm", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("map", "translate"):
        command = commands.add_parser(name, help="construct source output; runtime unverified")
        command.add_argument("source", type=Path)
        command.add_argument("--manifest", type=Path, help="native source-bound ProgramManifest proof metadata")
        if name == "translate":
            command.add_argument("--change", type=Path, help="raw native structured-edit JSON; code remains text")
        command.add_argument("--format", choices=("json", "html"), default="json")
        command.add_argument("--output", type=Path, help="new file only; existing evidence is never overwritten")
    for name in ("report", "demo"):
        command = commands.add_parser(name, help="render supplied dev records; no recorded code execution")
        command.add_argument("--mode", choices=("replay", "oracle", "live"), default="replay")
        command.add_argument("--bundle", type=Path, help="explicit replay manifest; no built-in evidence bundle exists")
        command.add_argument("--format", choices=("json", "html"), default="json")
        command.add_argument("--output", type=Path, help="new report file only")
    return parser.parse_args(argv)


def _read_input(path: Path, limit: int = MAX_JSON) -> bytes:
    resolved = local_input(path)
    with resolved.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ReplayRefusal("input_limit", "input exceeds declared byte budget; no truncation performed")
    return raw


def _source_action(args: argparse.Namespace) -> dict[str, Any]:
    raw = _read_input(args.source)
    try:
        source = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ReplayRefusal("source_encoding", "source must be exact UTF8 bytes") from exc
    source_sha256 = hashlib.sha256(raw).hexdigest()
    manifest = None
    if args.manifest is not None:
        manifest = strict_json(_read_input(args.manifest), "ProgramManifest")
    try:
        from cobolmap.parse import ParseRefusal, parse
    except ImportError as exc:
        raise ReplayUnavailable("parser_unavailable", "parser facade is not available in this source checkout") from exc
    try:
        program = parse(source, filename=args.source.name, manifest=manifest)
    except ParseRefusal as exc:
        raise _source_refusal(exc) from exc
    if program.source_sha256 != source_sha256 or program.filename != args.source.name:
        raise ReplayRefusal("source_identity", "parser facade changed source bytes or filename")
    payload: dict[str, Any] = {"source": {"filename": args.source.name, "sha256": source_sha256, "text": source},
                               "program_id": program.program_id}
    if args.command == "map":
        try:
            from cobolmap.mapping import MappingRefusal, build_map
        except ImportError as exc:
            raise ReplayUnavailable("mapper_unavailable", "mapping facade is unavailable") from exc
        try:
            behavior_map = build_map(program)
        except MappingRefusal as exc:
            raise _source_refusal(exc) from exc
        if behavior_map.source_sha256 != source_sha256 or behavior_map.filename != program.filename:
            raise ReplayRefusal("map_source", "mapping facade returned a foreign source identity")
        _resolve_map_pointers(behavior_map, raw, program.filename)
        payload["behavior_map"] = to_data(behavior_map)
    else:
        try:
            from cobolmap.translate import TranslationRefusal, translate
        except ImportError as exc:
            raise ReplayUnavailable("translator_unavailable", "translation facade is unavailable") from exc
        change = None
        if args.change is not None:
            change_raw = _read_input(args.change)
            change = strict_json(change_raw, "structured edit")
            if type(change) is not dict:
                raise ReplayRefusal("change_shape", "structured edit must be a native JSON mapping")
            payload["change_artifact"] = {"path": str(args.change),
                                           "raw_sha256": hashlib.sha256(change_raw).hexdigest()}
        try:
            translation = translate(program, change=change)
        except TranslationRefusal as exc:
            raise _source_refusal(exc) from exc
        if translation.original_source_sha256 != source_sha256 or type(translation.code) is not str:
            raise ReplayRefusal("translation_source", "translation facade returned a foreign source identity")
        payload["translation"] = to_data(translation)
        payload["generated_code_status"] = "text_only_not_executed"
    return build_document(title=f"COBOL {args.command} — source construction", status="source_constructed",
                          evidence_mode="static", payload=payload,
                          issues=("Source analysis/translation is runtime-unverified; no compiler/model outcome inferred.",))


def _source_refusal(error: Any) -> ReplayRefusal:
    code = getattr(error, "code", "source_refusal")
    message = getattr(error, "message", str(error))
    span = getattr(error, "span", None)
    if span is not None:
        message += " | source span: " + render_json({"span": to_data(span)}).strip()
    return ReplayRefusal(code if type(code) is str else "source_refusal", message)


def _resolve_map_pointers(model: Any, source: bytes, filename: str) -> None:
    from cobolmap.contracts import SourcePointer

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if set(value) == {"source_sha256", "filename", "line_start", "line_end", "byte_start", "byte_end"}:
                SourcePointer.model_validate(value).resolve(source, filename)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(to_data(model))


def _replay_action(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    if args.mode != "replay":
        return build_document(title="Execution mode unavailable", status="mode_blocked", evidence_mode="not_run",
                              processing_mode="not_run", issues=(
                                  "Oracle/live execution has no authorized backend in this source package.",
                                  "P2, runtime/isolation, independent appointments, licenses, model/keys and budget gates remain pending.",
                                  "Flags or supplied files cannot grant execution authority.",)), 3
    if args.bundle is None:
        return build_document(title="Replay evidence unavailable", status="unavailable", evidence_mode="not_run",
                              processing_mode="replay", issues=(
                                  "No supplied replay bundle; no authentic receipt bundle exists in this checkout.",
                                  "No fixture, compiler observation or live improvement is generated as a substitute.",)), 3
    evidence = load_replay(args.bundle)
    return build_document(title="Supplied dev replay — unauthenticated records",
                          status="replay_recorded" if evidence.available else "unavailable",
                          evidence_mode=evidence.evidence_mode, processing_mode="replay",
                          payload=evidence.payload, artifacts=evidence.artifacts,
                          pointers=evidence.pointers, issues=evidence.issues), 0 if evidence.available else 3


def _emit(document: dict[str, Any], output: Path | None, format_name: str) -> None:
    text = render_html(document) if format_name == "html" else render_json(document)
    if output is None:
        sys.stdout.write(text)
        return
    forbid_sensitive_parts(output.parts)
    if str(output).startswith(("\\\\", "//")):
        raise ReplayRefusal("remote_path", "local report output only")
    for parent in (*output.absolute().parents, output.absolute()):
        if parent.is_symlink() or parent.is_junction():
            raise ReplayRefusal("artifact_link", "linked output path refused")
    resolved = output.absolute().resolve(strict=False)
    forbid_sensitive_parts(resolved.parts)
    # Exclusive creation cannot overwrite inputs, receipts or an existing report.
    with resolved.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        if args.command in {"map", "translate"}:
            document, code = _source_action(args), 0
        else:
            document, code = _replay_action(args)
        _emit(document, args.output, args.format)
        return code
    except (ReplayRefusal, OSError, UnicodeError, ValueError, ImportError,
            TypeError, AttributeError, RecursionError) as exc:
        unavailable = isinstance(exc, (ReplayUnavailable, FileNotFoundError, ImportError))
        issue = {"code": getattr(exc, "code", "input_or_interface_error"), "message": str(exc)}
        document = build_document(title="COBOL operation refused", status="unavailable" if unavailable else "refused",
                                  evidence_mode="not_run", issues=(issue,),
                                  processing_mode="replay" if args.command in {"report", "demo"}
                                  and args.mode == "replay" else "not_run")
        # Failure is always a JSON diagnostic on stderr; no evidence/output fallback.
        sys.stderr.write(render_json(document))
        return 3 if unavailable else 2
