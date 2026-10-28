"""Bounded data-only reader for the exact DL2 generated Python module shape."""
import ast
from dataclasses import dataclass
import re

MAX_BYTES = 2 * 1024 * 1024
FIELD_KEYS = {'name', 'pic', 'usage', 'sign', 'offset', 'width', 'scale', 'digits',
              'storage', 'record_name', 'initial', 'span'}
NODE_KEYS = {
    'literal': {'value', 'literal_type'}, 'reference': {'name'},
    'binary': {'op', 'left', 'right'}, 'compare': {'op', 'left', 'right'},
    'boolean': {'op', 'left', 'right'}, 'move': {'value', 'target'},
    **{k: {'value', 'target', 'rounded', 'has_size_error'} for k in ('add', 'subtract', 'multiply')},
    'divide': {'left', 'right', 'target', 'rounded', 'has_size_error'},
    'compute': {'expression', 'target', 'rounded', 'has_size_error'},
    'if': {'condition'}, 'perform': {'paragraph', 'until', 'max_iterations'},
    'open': {'file', 'mode'}, 'read': {'file'}, 'write': {'record'},
    'close': {'file'}, 'display': {'values'}, 'stop': set(),
}
SPAN_KEYS = {'source_sha256', 'filename', 'line_start', 'line_end', 'byte_start', 'byte_end'}


class MutationRefusal(ValueError):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise MutationRefusal(message)


@dataclass(frozen=True)
class ParsedCandidate:
    raw: bytes
    plan: dict
    values: dict
    nodes: dict

    def segment(self, path: tuple) -> tuple[int, int, bytes]:
        node = self.nodes[path]
        lines = self.raw.splitlines(keepends=True)
        start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
        end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
        return start, end, self.raw[start:end]


def parse_candidate(raw: bytes) -> ParsedCandidate:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'bounded actual candidate bytes required')
    try:
        text = raw.decode('utf-8')
        tree = ast.parse(text, mode='exec')  # Syntax tree only, never compile/eval/import.
    except (UnicodeError, SyntaxError, ValueError, RecursionError) as error:
        raise MutationRefusal('candidate is not bounded UTF8 Python data') from error
    need(len(list(ast.walk(tree))) <= 20000, 'candidate AST budget exceeded')
    need(len(tree.body) == 4, 'exact generated module shape required')
    doc, imported, assignment, function = tree.body
    need(isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant)
         and doc.value.value == 'Generated private construction candidate; runtime/compiler parity unverified.',
         'generator header mismatch')
    need(isinstance(imported, ast.ImportFrom) and imported.module == 'cobolmap.translate.runtime'
         and imported.level == 0 and len(imported.names) == 1
         and imported.names[0].name == 'run_plan' and imported.names[0].asname is None,
         'fixed runtime import required')
    need(isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
         and isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == 'PLAN',
         'single literal PLAN assignment required')
    need(isinstance(function, ast.FunctionDef) and function.name == 'run_case'
         and not function.decorator_list and function.returns is None and function.type_comment is None
         and not getattr(function, 'type_params', ()) and len(function.body) == 1,
         'fixed run_case wrapper required')
    args = function.args
    need(not args.posonlyargs and [a.arg for a in args.args] == ['input_present', 'records']
         and all(a.annotation is None and a.type_comment is None for a in args.args)
         and not args.vararg and not args.kwarg and not args.kwonlyargs and not args.defaults
         and not args.kw_defaults, 'fixed wrapper parameters required')
    returned = function.body[0]
    need(isinstance(returned, ast.Return) and isinstance(returned.value, ast.Call), 'fixed wrapper return required')
    call = returned.value
    need(isinstance(call.func, ast.Name) and call.func.id == 'run_plan' and not call.keywords
         and len(call.args) == 3 and all(isinstance(n, ast.Name) for n in call.args)
         and [n.id for n in call.args] == ['PLAN', 'input_present', 'records'], 'fixed wrapper call required')
    values, nodes = {}, {}
    def literal(node, path=(), depth=0):
        need(depth <= 64, 'PLAN depth budget exceeded')
        nodes[path] = node
        if isinstance(node, ast.Constant):
            need(node.value is None or type(node.value) in (str, int, bool), 'nonliteral PLAN atom')
            value = node.value
        elif isinstance(node, ast.Dict):
            keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and type(k.value) is str]
            need(len(keys) == len(node.keys) and len(set(keys)) == len(keys), 'closed unique literal string keys required')
            value = {k: literal(v, path + (k,), depth + 1) for k, v in zip(keys, node.values)}
        elif isinstance(node, ast.List):
            value = [literal(v, path + (i,), depth + 1) for i, v in enumerate(node.elts)]
        else:
            raise MutationRefusal('PLAN contains executable or unsupported syntax')
        values[path] = value
        return value
    plan = literal(assignment.value)
    need(type(plan) is dict and set(plan) == {'version', 'source_sha256', 'filename', 'fields', 'files', 'paragraphs'}
         and type(plan['version']) is int and plan['version'] == 1, 'closed version1 PLAN required')
    need(type(plan['source_sha256']) is str and re.fullmatch('[0-9a-f]{64}', plan['source_sha256'])
         and type(plan['filename']) is str and plan['filename'], 'source/header identity required')
    def span(value):
        need(type(value) is dict and set(value) == SPAN_KEYS
             and value['source_sha256'] == plan['source_sha256'] and value['filename'] == plan['filename'],
             'source pointer identity drift')
        need(all(type(value[k]) is int for k in ('line_start', 'line_end', 'byte_start', 'byte_end'))
             and 1 <= value['line_start'] <= value['line_end'] and 0 <= value['byte_start'] < value['byte_end'],
             'source span shape')
    need(type(plan['fields']) is list and 1 <= len(plan['fields']) <= 32, 'field count')
    names = set()
    for field in plan['fields']:
        need(type(field) is dict and set(field) == FIELD_KEYS and type(field['name']) is str
             and field['name'] not in names, 'closed unique field required')
        names.add(field['name'])
        need(all(type(field[k]) is str for k in ('pic', 'usage', 'sign', 'storage'))
             and field['storage'] in ('working', 'input', 'output')
             and (field['record_name'] is None or type(field['record_name']) is str)
             and (field['initial'] is None or type(field['initial']) is str), 'field scalar types')
        need(all(type(field[k]) is int and field[k] >= 0 for k in ('offset', 'width', 'scale', 'digits')),
             'field numeric shape')
        span(field['span'])
    need(type(plan['files']) is list and len(plan['files']) == 2, 'two file bindings required')
    for file in plan['files']:
        need(type(file) is dict and set(file) == {'name', 'record', 'status', 'direction', 'fields'}
             and all(type(file[k]) is str for k in ('name', 'record', 'status', 'direction'))
             and file['direction'] in ('input', 'output') and file['status'] in names
             and type(file['fields']) is list and all(type(n) is str and n in names for n in file['fields']),
             'closed file binding required')
    def node(value, depth=0):
        need(depth <= 64 and type(value) is dict and type(value.get('kind')) is str
             and value['kind'] in NODE_KEYS, 'closed node kind')
        kind = value['kind']
        need(set(value) == NODE_KEYS[kind] | {'kind', 'span', 'body', 'otherwise'}, 'closed node keys')
        span(value['span'])
        need(type(value['body']) is list and type(value['otherwise']) is list, 'node body lists')
        for key in NODE_KEYS[kind]:
            item = value[key]
            if key in ('left', 'right', 'value', 'expression', 'condition') and type(item) is dict:
                node(item, depth + 1)
            elif key == 'values':
                need(type(item) is list and item, 'DISPLAY values')
                for child in item:
                    node(child, depth + 1)
            elif key == 'until' and item is not None:
                node(item, depth + 1)
            else:
                need(item is None or type(item) in (str, int, bool), 'closed scalar argument')
        for child in value['body'] + value['otherwise']:
            node(child, depth + 1)
    need(type(plan['paragraphs']) is list and 1 <= len(plan['paragraphs']) <= 8, 'paragraph count')
    for paragraph in plan['paragraphs']:
        need(type(paragraph) is dict and set(paragraph) == {'name', 'span', 'body'}
             and type(paragraph['name']) is str and type(paragraph['body']) is list, 'closed paragraph')
        span(paragraph['span'])
        for child in paragraph['body']:
            node(child)
    return ParsedCandidate(raw, plan, values, nodes)
