// Copyright 2026 Vikrant Rathore and Ronak Rathore. LGPL-3.0; see LICENSE.
// Build-time tools are optional. Pages serves the checked-in renderer without npm.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

const root = resolve(import.meta.dirname, '..');
const site = join(root, 'docs/site');
const dependencies = process.argv[2];
if (!dependencies) throw new Error('Pass the absolute path to the pinned node_modules directory.');
const pins = {
    three: { version: '0.186.1', integrity:
        'sha512-' +
        'blFeqb49wRCSGUGj7gtpfnSGHy2lwDk94RhUmS1c/hTby70kvChbWpkJ4Pm1390LqzzvTmzgXKHPEafJwCb8jA==' },
    esbuild: { version: '0.28.2', integrity:
        'sha512-' +
        'HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==' },
};
for (const [name, pin] of Object.entries(pins)) {
    const installed = JSON.parse(await readFile(join(dependencies, name, 'package.json')));
    if (installed.version !== pin.version) throw new Error(`Expected ${name} ${pin.version}`);
    const lock = JSON.parse(await readFile(join(dependencies, '..', 'package-lock.json')));
    const entry = Object.entries(lock.packages).find(([key]) =>
        key.endsWith(`node_modules/${name}`))?.[1];
    if (entry?.integrity !== pin.integrity) throw new Error(`Unverified ${name} package`);
}
const { build } = await import(pathToFileURL(join(dependencies, 'esbuild/lib/main.js')));
await build({
    entryPoints: [join(site, 'admission-scene.js')], outfile: join(site, 'admission-scene.bundle.js'),
    bundle: true, format: 'esm', target: 'es2022', minify: true,
    nodePaths: [resolve(dependencies)], external: ['./admission-model.js'], legalComments: 'inline',
    banner: { js: '// Sibuna scene: LGPL-3.0. Bundled three.js: MIT; see three-LICENSE.txt.' },
});
await writeFile(join(site, 'three-LICENSE.txt'), await readFile(join(dependencies, 'three/LICENSE')));
const files = {};
for (const name of ['admission-scene.js', 'admission-model.js', 'admission-scene.bundle.js',
    'three-LICENSE.txt']) {
    const bytes = await readFile(join(site, name));
    files[name] = { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
}
await writeFile(join(site, 'admission-assets.json'), JSON.stringify({
    dependencies: pins,
    rebuild: 'node tools/site_animation_build.mjs /absolute/path/to/pinned/node_modules',
    files,
}, null, 2) + '\n');
console.log(`Bundled scene: ${files['admission-scene.bundle.js'].bytes} bytes`);
