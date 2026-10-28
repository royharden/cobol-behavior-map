"""Conservative fixed-wrapper AST screen, not an isolation or admission gate."""
import ast
from bisect import bisect_left
import io
import re
import token
import tokenize

from cobolmap.contracts import ArtifactRef, sha256
from cobolmap.contracts.base import relative_name
from cobolmap.oracle.pins import SDK_PATHS, exact, helper_digest
from .models import ScreenContext, ScreenReason, ScreenResult

MAX_BYTES = 65536
MAX_TOKENS = 32768
MAX_AST_NODES = 32768
MAX_AST_DEPTH = 128
MAX_LITERAL_DEPTH = 64
MAX_STRING = 8192


class _Refusal(ValueError):
    def __init__(self, code, detail, node=None):
        self.reason = ScreenReason(code=code, detail=detail,
            line=getattr(node, "lineno", None), column=getattr(node, "col_offset", None))


def _need(condition, code, detail, node=None):
    if not condition:
        raise _Refusal(code, detail, node)


def _tokens(text):
    """Bound lexical expansion before ast.parse; permit no expression operators."""
    count, depth, negative = 0, 0, False
    harmless = {token.ENDMARKER, token.NEWLINE, token.INDENT, token.DEDENT,
                tokenize.NL, tokenize.COMMENT, token.NAME}
    for item in tokenize.generate_tokens(io.StringIO(text).readline):
        count += 1
        _need(count <= MAX_TOKENS, "token_limit", "token budget32768 exceeded")
        if negative:
            _need(item.type == token.NUMBER, "unsupported_token", "unary minus requires integer literal")
            negative = False
        if item.type == token.OP:
            _need(item.string in {"(", ")", "[", "]", "{", "}", ":", ",", "=", ".", "-"},
                  "unsupported_token", "operator outside fixed wrapper/literal syntax")
            if item.string in {"(", "[", "{"}:
                depth += 1
                _need(depth <= 64, "token_limit", "lexical bracket depth64 exceeded")
            elif item.string in {")", "]", "}"}:
                depth -= 1
                _need(depth >= 0, "syntax", "unbalanced bracket")
            negative = item.string == "-"
        elif item.type == token.NUMBER:
            _need(re.fullmatch(r"[0-9]{1,12}", item.string) is not None,
                  "literal_limit", "only integer literals of <=12 digits")
        elif item.type == token.STRING:
            _need(item.string.startswith(("'", '"')),
                  "unsupported_token", "only ordinary unprefixed string literals")
        else:
            _need(item.type in harmless, "unsupported_token", "unsupported lexical token")
    _need(depth == 0 and not negative, "syntax", "incomplete literal syntax")
    return count


def _tree_limits(tree):
    count, maximum = 0, 0
    stack = [(tree, 0)]
    scheduled = 1
    while stack:
        node, depth = stack.pop()
        count += 1
        maximum = max(maximum, depth)
        _need(count <= MAX_AST_NODES and depth <= MAX_AST_DEPTH,
              "ast_limit", "AST node/depth budget exceeded", node)
        for child in ast.iter_child_nodes(node):
            _need(scheduled < MAX_AST_NODES and depth < MAX_AST_DEPTH,
                  "ast_limit", "AST expansion budget exceeded", node)
            scheduled += 1
            stack.append((child, depth + 1))
    return count, maximum


def _name(node, name):
    return type(node) is ast.Name and node.id == name and type(node.ctx) is ast.Load


def _wrapper(tree):
    body = tree.body
    if body and type(body[0]) is ast.Expr and type(body[0].value) is ast.Constant and type(body[0].value.value) is str:
        _need(len(body[0].value.value) <= MAX_STRING, "literal_limit", "module docstring too long", body[0])
        body = body[1:]
    _need(len(body) == 3 and not tree.type_ignores, "entry_shape", "exact import/PLAN/run_case module required")
    imported, assignment, function = body
    _need(type(imported) is ast.ImportFrom and imported.level == 0
          and imported.module == "cobolmap.translate.runtime" and len(imported.names) == 1
          and imported.names[0].name == "run_plan" and imported.names[0].asname is None,
          "entry_shape", "only unaliased pinned run_plan import permitted", imported)
    _need(type(assignment) is ast.Assign and len(assignment.targets) == 1
          and type(assignment.targets[0]) is ast.Name and assignment.targets[0].id == "PLAN"
          and assignment.type_comment is None,
          "entry_shape", "single literal PLAN assignment required", assignment)
    _need(type(function) is ast.FunctionDef and function.name == "run_case"
          and not function.decorator_list and function.returns is None
          and function.type_comment is None and not getattr(function, "type_params", ())
          and len(function.body) == 1 and type(function.body[0]) is ast.Return,
          "entry_shape", "plain single-return run_case required", function)
    args = function.args
    _need(not args.posonlyargs and not args.kwonlyargs and not args.defaults
          and not args.kw_defaults and args.vararg is None and args.kwarg is None
          and [arg.arg for arg in args.args] == ["input_present", "records"]
          and all(arg.annotation is None and arg.type_comment is None for arg in args.args),
          "entry_shape", "exact unannotated two-argument ABI required", function)
    call = function.body[0].value
    _need(type(call) is ast.Call and _name(call.func, "run_plan") and not call.keywords
          and len(call.args) == 3 and all(_name(node, name) for node, name in
              zip(call.args, ("PLAN", "input_present", "records"))),
          "entry_shape", "only direct run_plan(PLAN,input_present,records) permitted", function)
    return assignment.value


def _literal(node, depth=0):
    _need(depth <= MAX_LITERAL_DEPTH, "literal_limit", "literal depth64 exceeded", node)
    if type(node) is ast.Constant:
        value = node.value
        _need(value is None or type(value) in {str, int, bool}, "literal_shape", "unsupported constant type", node)
        if type(value) is str:
            _need(len(value) <= MAX_STRING, "literal_limit", "string exceeds8192 characters", node)
        elif type(value) is int:
            _need(abs(value) < 10 ** 12, "literal_limit", "integer exceeds12 digits", node)
        return value
    if type(node) is ast.UnaryOp and type(node.op) is ast.USub and type(node.operand) is ast.Constant:
        value = _literal(node.operand, depth + 1)
        _need(type(value) is int, "literal_shape", "minus applies only to integer", node)
        return -value
    if type(node) in {ast.List, ast.Tuple}:
        _need(len(node.elts) <= 4096, "literal_limit", "literal sequence exceeds4096", node)
        result = [_literal(item, depth + 1) for item in node.elts]
        return tuple(result) if type(node) is ast.Tuple else result
    if type(node) is ast.Dict:
        _need(len(node.keys) <= 4096, "literal_limit", "literal mapping exceeds4096", node)
        result = {}
        for key, value in zip(node.keys, node.values):
            _need(type(key) is ast.Constant and type(key.value) is str,
                  "literal_shape", "mapping keys must be literal strings; no unpacking", node)
            name = _literal(key, depth + 1)
            _need(name not in result, "literal_shape", "duplicate literal mapping key", key)
            result[name] = _literal(value, depth + 1)
        return result
    raise _Refusal("literal_shape", "PLAN permits inert literals only", node)


def _plan_bindings(plan, context):
    required = {"version", "source_sha256", "filename", "fields", "files", "paragraphs"}
    _need(type(plan) is dict and required <= set(plan) <= required | {"candidate_loop_proofs"},
          "plan_shape", "closed translator PLAN root required")
    _need(type(plan["version"]) is int and plan["version"] == 1
          and plan["source_sha256"] == context.original_source.ref.sha256
          and plan["filename"] == context.source_filename,
          "plan_shape", "PLAN source/version/filename commitment mismatch")
    for name, low, high in (("fields", 1, 32), ("files", 2, 2), ("paragraphs", 1, 8)):
        _need(type(plan[name]) is list and low <= len(plan[name]) <= high
              and all(type(item) is dict for item in plan[name]), "plan_shape", "PLAN container bounds")
    if "candidate_loop_proofs" in plan:
        _need(type(plan["candidate_loop_proofs"]) is list and len(plan["candidate_loop_proofs"]) <= 4096,
              "plan_shape", "bounded inert candidate loop metadata required")
    raw = context.original_source.data
    newlines = [index for index, byte in enumerate(raw) if byte == 10]
    pointer_keys = {"source_sha256", "filename", "line_start", "line_end", "byte_start", "byte_end"}
    stack = [plan]
    while stack:
        item = stack.pop()
        if type(item) is dict:
            if "span" in item:
                pointer = item["span"]
                _need(type(pointer) is dict and set(pointer) == pointer_keys,
                      "source_pointer", "closed source pointer required")
                start, end = pointer["byte_start"], pointer["byte_end"]
                _need(type(start) is int and type(end) is int and 0 <= start < end <= len(raw)
                      and pointer["source_sha256"] == context.original_source.ref.sha256
                      and pointer["filename"] == context.source_filename
                      and type(pointer["line_start"]) is int and type(pointer["line_end"]) is int
                      and pointer["line_start"] == bisect_left(newlines, start) + 1
                      and pointer["line_end"] == bisect_left(newlines, end - 1) + 1,
                      "source_pointer", "pointer bytes/lines/source mismatch")
            stack.extend(item.values())
        elif type(item) in {list, tuple}:
            stack.extend(item)


def screen_candidate(candidate: bytes | str, *, context: ScreenContext | None = None) -> ScreenResult:
    """Later pure screen only; never compile/import/evaluate candidate code."""
    retained = None
    candidate_ref = None
    manifest = None
    tokens = nodes = depth = None
    try:
        _need(type(candidate) in {bytes, str}, "candidate_type", "exact bytes or text required")
        _need(len(candidate) <= MAX_BYTES, "candidate_limit", "candidate exceeds65536 source units")
        raw = candidate.encode("utf-8") if type(candidate) is str else candidate
        _need(len(raw) <= MAX_BYTES, "candidate_limit", "candidate exceeds65536 raw bytes")
        candidate_ref = ArtifactRef(path="candidate.py", sha256=sha256(raw), byte_length=len(raw))
        _need(raw and b"\0" not in raw, "candidate_encoding", "nonempty NUL-free UTF8 required")
        text = raw.decode("utf-8")
        _need(len(text.splitlines()) <= 4096, "candidate_limit", "candidate exceeds4096 lines")
        # ast.parse(str) does not apply a file's encoding cookie, while a future
        # Python loader does. Avoid screening a different decoding of the bytes.
        _need(not any(re.match(r"^[ \t\f]*#.*?coding[:=][ \t]*[-_.a-zA-Z0-9]+", line)
                      for line in text.split("\n")[:2]),
              "candidate_encoding", "file encoding cookies are unsupported")
        if context is None:
            return ScreenResult(status="pending", candidate=candidate_ref,
                reasons=(ScreenReason(code="context_missing", detail="source/helper/entry commitments required"),))
        try:
            retained = exact(context, ScreenContext)
        except Exception:
            raise _Refusal("context_invalid", "exact canonical screening context required") from None
        source = retained.original_source.data
        _need(0 < len(source) <= MAX_BYTES and source.isascii()
              and len(source.splitlines()) <= 200, "source_invalid", "bounded exact original ASCII source required")
        try:
            relative_name(retained.source_filename)
        except ValueError:
            raise _Refusal("source_invalid", "logical original filename must be relative") from None
        _need(candidate_ref.sha256 == retained.candidate_sha256,
              "candidate_pin", "raw candidate hash mismatch")
        helpers = retained.helpers
        _need(len(helpers) == 8 and len({blob.ref.path for blob in helpers}) == 8
              and {blob.ref.path for blob in helpers} == SDK_PATHS,
              "helper_pin", "exact r5 eight-file SDK/entry closure required")
        manifest = helper_digest(helpers)
        _need(manifest == retained.toolchain.helper_manifest_sha256, "helper_pin", "helper manifest mismatch")
        entry = next(blob for blob in helpers if blob.ref.path == "entry.py")
        shim = next(blob for blob in helpers if blob.ref.path == "cobolmap/shared/decimal_shim.py")
        _need(entry.data and entry.ref == retained.toolchain.launcher
              and shim.ref.sha256 == retained.toolchain.pins.shim_sha256,
              "helper_pin", "actual entry/shim bytes and pins required")
        if retained.entry_approval is None:
            return ScreenResult(status="pending", candidate=candidate_ref, context=retained,
                computed_helper_manifest_sha256=manifest,
                reasons=(ScreenReason(code="entry_missing", detail="actual external entry approval absent"),))
        tokens = _tokens(text)
        tree = ast.parse(text, filename="candidate.py", mode="exec", type_comments=True)
        nodes, depth = _tree_limits(tree)
        literal = _wrapper(tree)
        plan = _literal(literal)
        _plan_bindings(plan, retained)
        return ScreenResult(status="screened", candidate=candidate_ref, context=retained,
            computed_helper_manifest_sha256=manifest, tokens=tokens, ast_nodes=nodes, ast_depth=depth)
    except _Refusal as error:
        reason = error.reason
    except (UnicodeError, SyntaxError, tokenize.TokenError, IndentationError, RecursionError, MemoryError):
        reason = ScreenReason(code="syntax", detail="source parser/encoding refused candidate")
    return ScreenResult(status="refused", candidate=candidate_ref, context=retained,
        computed_helper_manifest_sha256=manifest, reasons=(reason,), tokens=tokens, ast_nodes=nodes, ast_depth=depth)
