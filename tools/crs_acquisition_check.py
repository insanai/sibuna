#!/usr/bin/env python3
"""Check native acquisition against independent JSON, form, MIME and XML decoders.

JSON syntax uses Python's standard parser. Field naming follows the explicitly
reviewed ModSecurity 3.0.14 profile; this is not whole-engine FTW qualification.
Fixtures cover duplicate members, binary bytes, numeric spelling and path collisions.
"""
import argparse
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import random
import subprocess
from urllib.parse import quote_from_bytes, unquote_to_bytes
from xml.etree import ElementTree


class Object(list):
    """An ordered object distinct from arrays, retaining repeated members."""


class Number(str):
    """Keep the exact spelling rather than rounding through a numeric value."""


def fields(node, prefix="json"):
    if isinstance(node, Object):
        result = []
        for key, child in node:
            result.extend(fields(child, prefix + "." + (key or "empty-key")))
        return result
    if isinstance(node, list):
        result = []
        for index, child in enumerate(node):
            result.extend(fields(child, prefix + ".array_" + str(index)))
        return result
    if node is None:
        value = ""
    elif node is True:
        value = "true"
    elif node is False:
        value = "false"
    else:
        value = str(node)
    return [(prefix.encode("utf-8"), value.encode("utf-8"))]


def forbid_constant(value):
    raise ValueError(f"non-JSON constant {value}")


def oracle(input_bytes):
    value = json.loads(input_bytes.decode("utf-8"), object_pairs_hook=Object,
                       parse_float=Number, parse_int=Number, parse_constant=forbid_constant)
    return fields(value)


def probe(binary, kind, input_bytes, expected):
    result = subprocess.run([str(binary), kind, input_bytes.hex()], check=False,
                            capture_output=True, timeout=15)
    output = result.stdout.decode("ascii")
    if expected is None:
        if result.returncode == 0 or not output.startswith("rejected "):
            raise ValueError(f"invalid input accepted: {kind} {input_bytes!r} {output!r}")
        return
    if result.returncode:
        raise ValueError(f"valid input refused: {kind} {input_bytes!r} {output!r}")
    actual = []
    for line in output.splitlines():
        tag, key, value = line.split("\t")
        decoded = (bytes.fromhex(key), bytes.fromhex(value))
        if kind in ["multipart", "xml"]:
            actual.append((tag, *decoded))
        else:
            if tag != "arg":
                raise ValueError(f"invalid probe output: {line!r}")
            actual.append(decoded)
    if actual != expected:
        raise ValueError(f"acquisition mismatch: {kind} {input_bytes!r}\n"
                         f"expected {expected!r}\nactual {actual!r}")


def json_vectors():
    yield from [
        b'{"a":1,"a":2,"":null}', b'{"a.b":"x","a":{"b":"y"}}',
        b'[[1,{},2],[true,null,false]]', b'{"x":[{},[],{"y":1}]}',
        b'{"a\\u0000":"b\\u0000c","emoji":"\\ud83d\\ude00"}',
        b'"scalar"', b'false', b'null', b'-0.25e+002',
    ]
    randomizer = random.Random(0x435253)
    atoms = ['""', '"x\\u0000y"', '"\\ud83d\\ude00"', 'null', 'false',
             'true', '-1.250e+2', '123456789012345678901234567890']
    keys = ["x", "", "a.b", "array_0", "é", "x"]

    def generate(depth):
        if depth == 0 or randomizer.randrange(3) == 0:
            return randomizer.choice(atoms)
        if randomizer.randrange(2):
            return "[" + ",".join(generate(depth - 1)
                                   for _ in range(randomizer.randrange(4))) + "]"
        return "{" + ",".join(json.dumps(randomizer.choice(keys)) + ":" + generate(depth - 1)
                               for _ in range(randomizer.randrange(4))) + "}"

    for _ in range(500):
        yield generate(5).encode("utf-8")


def form_oracle(data):
    if not data:
        return []
    parts = data.split(b"&")
    if not parts[-1]:
        parts.pop()  # std::getline does not emit a token after the final separator.
    result = []
    for part in parts:
        key, separator, value = part.partition(b"=")
        del separator
        result.append((unquote_to_bytes(key.replace(b"+", b" ")),
                       unquote_to_bytes(value.replace(b"+", b" "))))
    return result


def multipart_oracle(body):
    header = b'Content-Type: multipart/form-data; boundary="B"\r\nMIME-Version: 1.0\r\n\r\n'
    message = BytesParser(policy=policy.default).parsebytes(header + body)
    if not message.is_multipart():
        raise ValueError("independent parser did not recognize fixture")
    result = []
    file_bytes = 0
    for part in message.iter_parts():
        name = part.get_param("name", header="Content-Disposition")
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if filename:
            result.append(("file", name.encode("utf-8"), filename.encode("utf-8")))
            file_bytes += len(payload)
        else:
            result.append(("arg", name.encode("utf-8"), payload))
    result.append(("size", b"", str(file_bytes).encode("ascii")))
    return result


def multipart_vectors():
    randomizer = random.Random(0x4d494d45)
    for iteration in range(150):
        parts = []
        for index in range(randomizer.randrange(1, 10)):
            name = "q" if index % 2 else "upload"
            filename = f"file-{index}.bin" if randomizer.randrange(2) else None
            metadata = f'Content-Disposition: form-data; name="{name}"'
            if filename:
                metadata += f'; filename="{filename}"'
            metadata += "\r\nContent-Type: application/octet-stream\r\n\r\n"
            payload = randomizer.randbytes(randomizer.randrange(100))
            payload += b"\r\n--Bx\r\n--B--garbage"  # Prefixes inside file/field data.
            parts.append(b"--B\r\n" + metadata.encode("ascii") + payload + b"\r\n")
        body = b"".join(parts) + b"--B--\r\n"
        if iteration % 2:
            body = b"preamble\r\n" + body + b"epilogue"
        yield body


def xml_oracle(data):
    root = ElementTree.fromstring(data)
    result = []
    for element in root.iter():
        for value in element.attrib.values():
            result.append(("xml-attribute", b"//@*", value.encode("utf-8")))
    text = "".join(root.itertext()).encode("utf-8")
    result.append(("xml-element", b"/*", text))
    return result


def xml_vectors():
    yield from [
        b"<root/>", b"<root a='a&#9;b\r\nc'>x\r\ny&#13;z</root>",
        b"<?xml version='1.0' encoding='UTF-8'?><root><![CDATA[a&b<c]]></root>",
        b"<root xmlns='urn:a' xmlns:p='urn:p' a='1' p:a='2'><p:x/></root>",
        b"<root>before<!--ignored--><?instruction ignored?>after<child>child</child>end</root>",
        b"<root xmlns:p='urn:a'><p:x xmlns:p='urn:b' p:a='one'/><p:y p:a='two'/></root>",
    ]
    randomizer = random.Random(0x584d4c)
    atoms = ["ordinary", "&amp;&lt;&gt;&quot;&apos;", "&#x1F600;", "&#233;", "x\r\ny", ""]

    def element(depth, index):
        name = "node" + str(index)
        attribute = randomizer.choice(atoms)
        text = randomizer.choice(atoms)
        children = "" if depth == 0 else "".join(element(depth - 1, child)
                                                for child in range(randomizer.randrange(4)))
        return f'<{name} a="{attribute}">{text}{children}{text}</{name}>'

    for _ in range(150):
        yield element(4, 0).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--download", action="store_true", help="No external inputs required")
    args = parser.parse_args()
    binary = args.binary.resolve()
    count = 0
    for data in json_vectors():
        probe(binary, "json", data, oracle(data))
        count += 1
    for data in [b"", b"{}{}", b"[1,]", b"01", b"NaN", b'"\\uD800"',
                 b'"\\uDC00"', b'"\xff"', b'{"a":1,"b":}', b'"raw\nline"']:
        try:
            oracle(data)
        except (ValueError, UnicodeError):
            pass
        else:
            raise ValueError(f"invalid fixture unexpectedly valid: {data!r}")
        probe(binary, "json", data, None)
        count += 1
    randomizer = random.Random(0x464f524d)
    cases = [b"", b"&&", b"=value&empty&q=a+b&q=%00%26%3d&", b"key=a=b;c"]
    for _ in range(250):
        parts = []
        for _ in range(randomizer.randrange(20)):
            key = randomizer.randbytes(randomizer.randrange(12))
            value = randomizer.randbytes(randomizer.randrange(30))
            parts.append((quote_from_bytes(key) + "=" + quote_from_bytes(value)).encode("ascii"))
        cases.append(b"&".join(parts))
    for data in cases:
        for kind in ["query", "form"]:
            probe(binary, kind, data, form_oracle(data))
            count += 1
    for data in [b"q=%", b"q=%a", b"q=%zz", b"ok=v&bad=%0g"]:
        probe(binary, "form", data, None)
        count += 1
    for body in multipart_vectors():
        probe(binary, "multipart", body, multipart_oracle(body))
        count += 1
    for document in xml_vectors():
        probe(binary, "xml", document, xml_oracle(document))
        count += 1
    for document in [b"<a>", b"<a/><b/>", b"<a>&#0;</a>", b"<p:a/>",
                     b"<a xmlns:p='urn:x' xmlns:q='urn:x' p:a='1' q:a='2'/>"]:
        try:
            xml_oracle(document)
        except ElementTree.ParseError:
            pass
        else:
            raise ValueError(f"invalid XML fixture accepted by independent parser: {document!r}")
        probe(binary, "xml", document, None)
        count += 1
    probe(binary, "xml", b"<!DOCTYPE a [<!ENTITY e 'unsafe'>]><a>&e;</a>", None)
    count += 1
    print(f"Native acquisition agrees with {count} independent cases; "
          "whole-engine FTW qualification remains separate.")


if __name__ == "__main__":
    main()
