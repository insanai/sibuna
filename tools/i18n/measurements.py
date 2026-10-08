"""Localize generated table prose while sharing drawings and measured numeric data."""
import json
import re

TABLES = {
    'benchmark_rows', 'benchmark_results_table', 'benchmark_chart_block', 'workload_label',
    'tools_mode_table', 'tools_footprint_table', 'tools_not_measured_table', 'tools_meta_line',
    'distributed_results_table', 'admission_comparison_table', 'cluster_cell',
    'cluster_throughput_table', 'cluster_parity_table', 'cluster_meta_line',
}


def prose(value):
    # Values come from committed benchmark provenance, never from a document macro.
    return '[' + re.sub(r'([\\\[\]#*_`$<>])', r'\\\1', value) + ']'


def source(root):
    from .book import split_blocks
    figures = (root / 'docs/book/figures.typ').read_text()
    parts = []
    for block in split_blocks(figures):
        name = re.match(r'#let (\w+)', block)
        if name and name[1] in TABLES:
            parts.append(block)
    assert len(parts) == len(TABLES), 'measurement helper set changed'
    # Publish explanations from the same measurement file as the English edition.
    # Numbers and run identifiers still come directly from that immutable result file.
    data = json.loads((root / 'benchmarks/results/tools-comparison-latest.json').read_text())
    notes = '#let published_notes() = (\n'
    for item in data['not_measured']:
        notes += (f'  (version: {prose(item["version_checked"])},\n'
                  f'   reason: {prose(item["reason"])}, facts: (\n')
        for key, value in item['published'].items():
            notes += f'    ({prose(key.replace("_", " "))}, {prose(value)}),\n'
        notes += '  )),\n'
    notes += ')\n'
    text = '\n'.join(parts)
    old = ('for item in data.not_measured {\n'
           '    let facts = item.published.pairs().map(((k, v)) => '
           '[*#k.replace("_", " ")*: #v]).join(linebreak())')
    new = ('for (index, item) in data.not_measured.enumerate() {\n'
           '    let note = published_notes().at(index)\n'
           '    let facts = note.facts.map(((k, v)) => [*#k*: #v]).join(linebreak())')
    assert old in text
    text = text.replace(old, new).replace('#item.version_checked', '#note.version')
    text = text.replace('#item.reason', '#note.reason')
    # A run's machine-readable status stays intact; its table label is local prose.
    text = text.replace('#run.status]', '#check_label(run.status)]')
    text = re.sub(r'#calc\.round\([^\n)]*\) ms',
                  lambda m: '#text(dir: ltr, lang: "en")[' + m[0] + ']', text)
    status = ('#let check_label(value) = (passed: [passed], failed: [failed])'
              '.at(value, default: value)\n')
    return notes + '\n' + status + '\n' + text
