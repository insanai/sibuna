"""Inspect rendered form state in native/Wasm tests; Chrome verifies actual DOM behavior."""
from html.parser import HTMLParser


class FormValues(HTMLParser):
    def __init__(self, form_id, attribute="id"):
        super().__init__()
        self.form_id, self.active, self.select, self.values = form_id, False, None, {}
        self.attribute = attribute

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "form":
            self.active = attrs.get(self.attribute) == self.form_id
        if not self.active:
            return
        if tag == "input" and "name" in attrs:
            self.values[attrs["name"]] = attrs.get("value", "")
        elif tag == "select":
            self.select = attrs.get("name")
        elif tag == "option" and self.select and "selected" in attrs:
            self.values[self.select] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = False
        elif tag == "select":
            self.select = None
