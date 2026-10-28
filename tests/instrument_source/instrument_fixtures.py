"""Builder-only inert SOURCE vectors, never candidates to import or execute.

The metadata is synthetic; these are not COBOL programs, study cases, expected
ordinary outputs, independently planted mutants, validity proofs or receipts.
"""
from copy import deepcopy
from hashlib import sha256

from evaluation.mutants import MutationBinding

ORIGINAL = b'BUILDER source identity data; not a COBOL program.\n'
SOURCE_SHA = sha256(ORIGINAL).hexdigest()
HEADER = 'Generated private construction candidate; runtime/compiler parity unverified.'


def digest(label):
    return sha256(('builder-only:' + label).encode()).hexdigest()


def span():
    return dict(source_sha256=SOURCE_SHA, filename='builder-source.txt', line_start=1,
                line_end=1, byte_start=0, byte_end=1)


def node(kind, **args):
    return dict(kind=kind, span=span(), body=[], otherwise=[], **args)


def literal(text, kind='numeric'):
    return node('literal', value=text, literal_type=kind)


def reference(name):
    return node('reference', name=name)


def field(name, *, alpha=False, storage='working', record=None, initial=None, signed=False):
    return dict(name=name, pic='X(2)' if alpha else 'S9(3)' if signed else '9(3)',
                usage='DISPLAY', sign='leading_separate' if signed else 'none', offset=0,
                width=2 if alpha else 4 if signed else 3, scale=0, digits=0 if alpha else 3,
                storage=storage, record_name=record, initial=initial, span=span())


def plan(body=(), *, number=None):
    return dict(version=1, source_sha256=SOURCE_SHA, filename='builder-source.txt',
                fields=[field('N', **(number or {})), field('SIN', alpha=True),
                        field('SOUT', alpha=True), field('IN', alpha=True, storage='input', record='IR'),
                        field('OUT', alpha=True, storage='output', record='OR')],
                files=[dict(name='IF', record='IR', status='SIN', direction='input', fields=['IN']),
                       dict(name='OF', record='OR', status='SOUT', direction='output', fields=['OUT'])],
                paragraphs=[dict(name='MAIN', span=span(), body=list(body) + [node('stop')])])


def source(value):
    # This is a bytes string in memory. It is never a Python module/file to load.
    return (repr(HEADER) + '\nfrom cobolmap.translate.runtime import run_plan\nPLAN = '
            + repr(value) + '\ndef run_case(input_present, records):\n'
            '    return run_plan(PLAN, input_present, records)\n').encode('utf-8')


def binding(raw):
    return MutationBinding(task_id='builder_task', program_id='builder_program', family_id='builder_family',
                           split='dev', original_source_sha256=SOURCE_SHA,
                           parent_candidate_sha256=sha256(raw).hexdigest(),
                           generator_sha256=digest('translator'), runtime_sha256=digest('runtime'),
                           operator_source_sha256=digest('operators'), plan_reader_sha256=digest('reader'))


def vector(operator):
    """Independent literal edit expectation, not an expected execution answer."""
    root = ('paragraphs', 0, 'body', 0)
    if operator in {'M01', 'M02', 'M03', 'M05', 'M07', 'M11', 'M12', 'M17'}:
        before, after, kind = {
            'M01': ('AB', 'AB ', 'alpha'), 'M02': ('AB ', 'AB', 'alpha'),
            'M03': ('2', '-2', 'numeric'), 'M05': ('2.5', '25', 'numeric'),
            'M07': ('2.34', '2.3', 'numeric'), 'M11': ('2', '3', 'numeric'),
            'M12': ('QX', 'AX', 'alpha'), 'M17': ('1900', '2000', 'numeric'),
        }[operator]
        value = plan([node('move', value=literal(before, kind), target='OUT' if kind == 'alpha' else 'N')])
        path, expected = root + ('value', 'value'), after
    elif operator in {'M04', 'M06'}:
        value = plan(number={'initial': '-2', 'signed': True} if operator == 'M04' else {'initial': '2.5'})
        path, expected = ('fields', 0, 'initial'), '2' if operator == 'M04' else '0.25'
    elif operator == 'M16':
        value = plan()
        value['fields'][1]['initial'] = '00'
        path, expected = ('fields', 1, 'initial'), '10'
    elif operator in {'M08', 'M09', 'M10'}:
        value = plan([node('add', value=literal('0'), target='N', rounded=operator == 'M08',
                           has_size_error=operator == 'M10')])
        path = root + ('has_size_error' if operator == 'M10' else 'rounded',)
        expected = operator == 'M09'
    elif operator in {'M13', 'M14'}:
        value = plan([node('write', record='OR')])
        body = deepcopy(value['paragraphs'][0]['body'])
        path = ('paragraphs', 0, 'body')
        expected = body[1:] if operator == 'M13' else [deepcopy(body[0])] + body
    elif operator in {'M15', 'M18', 'M19'}:
        if operator == 'M15':
            comparison = node('compare', op='=', left=reference('SIN'), right=literal('10', 'alpha'))
            path, expected = root + ('condition', 'right', 'value'), '00'
        elif operator == 'M18':
            comparison = node('compare', op='<', left=reference('YEAR'), right=literal('50'))
            path, expected = root + ('condition', 'right', 'value'), '51'
        else:
            comparison = node('compare', op='<', left=reference('N'), right=literal('0'))
            path, expected = root + ('condition', 'op'), '<='
        value = plan([node('if', condition=comparison)])
        if operator == 'M18':
            value['fields'].append(field('YEAR'))
    elif operator == 'M20':
        value = plan([node('compute', expression=node('binary', op='+', left=literal('0'), right=reference('N')),
                           target='N', rounded=False, has_size_error=False)])
        path, expected = root + ('expression', 'op'), '-'
    else:
        raise ValueError('unknown builder vector')
    return source(value), path, expected, value
