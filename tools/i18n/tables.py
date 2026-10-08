"""Compare table coverage and numeric cells across complete language editions."""
from collections import Counter
from html.parser import HTMLParser
import re

NUMERIC = re.compile(r'[0-9.,–−—%/ ×µsmnBGiKkbps():+≤≥\s]+')


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables = []
        self.current = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            assert self.current is None, 'unexpected nested table'
            self.current = []
        if self.current is not None and tag in ('td', 'th'):
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None:
            self.current.append(''.join(self.cell))
            self.cell = None
        if tag == 'table':
            self.tables.append(self.current)
            self.current = None

    def contract(self):
        return [(len(cells), Counter(cell for cell in cells if NUMERIC.fullmatch(cell)
                                    and re.search(r'[0-9]', cell))) for cells in self.tables]


def contract(source):
    parser = Tables()
    parser.feed(source)
    parser.close()
    assert parser.current is None, 'unterminated table'
    return parser.contract()


def check_bundle(original, translated):
    for path in original.glob('*.html'):
        native = translated / path.name
        assert contract(path.read_text()) == contract(native.read_text()), (
            f'{translated.parent.name}/{path.name}: table coverage or measured values differ')


def isolate_numbers(source):
    """Keep measured cells and ISO timestamps in their published reading order in RTL."""
    def cell(match):
        parser = Tables()
        parser.feed('<table>' + match[0] + '</table>')
        value = parser.tables[0][0]
        if NUMERIC.fullmatch(value) and re.search(r'[0-9]', value):
            return '<td dir="ltr"' + match[1] + '>' + match[2] + '</td>'
        return match[0]
    source = re.sub(r'<td([^>]*)>(.*?)</td>', cell, source, flags=re.S)
    stamp = re.compile(r'\b[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+\-Z]+')
    def text(match):
        return stamp.sub(lambda date: '<bdi dir="ltr">' + date[0] + '</bdi>', match[0])
    return re.sub(r'(?<=>)[^<>]+(?=<)', text, source)
