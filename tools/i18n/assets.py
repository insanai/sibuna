"""Asset versions cover the full animation graph, including lazy-loaded modules."""
from hashlib import sha256
from .locale import ROOT

DEPENDENCIES = {
    'admission-animation.js': ('admission-model.js', 'admission-scene.bundle.js'),
}


def version(directory, name):
    digest = sha256()
    for file in (name, *DEPENDENCIES.get(name, ())):
        data = (directory / file).read_bytes()
        digest.update(file.encode() + b'\0' + len(data).to_bytes(8, 'big') + data)
    return digest.hexdigest()[:16]


def url(name):
    return '/sibuna/assets/' + name + '?v=' + version(ROOT / 'docs/site', name)
