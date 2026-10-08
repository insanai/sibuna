// Copyright 2026 Vikrant Rathore and Ronak Rathore. LGPL-3.0; see LICENSE.
// The build bundles the pinned MIT-licensed three.js; no runtime CDN or remote textures.
import * as T from 'three';
import { fraction, firstTimes as F, returnTimes as R } from './admission-model.js';

const positions = {
    client: [-6.5, 0, 0], ingress: [-3, 0, 0], sibuna: [0.7, 0, 0], app: [6, 0, 0],
};
const colors = { green: '#a1e8ba', gold: '#f1ce8e', red: '#ffa997', white: '#e1efeb' };

function roundedCube() {
    const s = new T.Shape();
    s.moveTo(-0.4, -0.47); s.lineTo(0.4, -0.47);
    s.quadraticCurveTo(0.47, -0.47, 0.47, -0.4); s.lineTo(0.47, 0.4);
    s.quadraticCurveTo(0.47, 0.47, 0.4, 0.47); s.lineTo(-0.4, 0.47);
    s.quadraticCurveTo(-0.47, 0.47, -0.47, 0.4); s.lineTo(-0.47, -0.4);
    s.quadraticCurveTo(-0.47, -0.47, -0.4, -0.47);
    const g = new T.ExtrudeGeometry(s, { depth: 0.86, bevelEnabled: true,
        curveSegments: 2, bevelSegments: 2, steps: 1, bevelSize: 0.03, bevelThickness: 0.07 });
    g.center();
    return g;
}

function canvasTexture(width, height, paint) {
    const canvas = document.createElement('canvas');
    canvas.width = width; canvas.height = height;
    paint(canvas.getContext('2d'), width, height);
    const texture = new T.CanvasTexture(canvas);
    texture.colorSpace = T.SRGBColorSpace;
    return texture;
}

function studioTexture() {
    return canvasTexture(512, 256, (c, w, h) => {
        c.fillStyle = '#213329'; c.fillRect(0, 0, w, h);
        const gradient = c.createLinearGradient(0, 0, 0, h);
        gradient.addColorStop(0, '#aabcae'); gradient.addColorStop(0.48, '#314e3d');
        gradient.addColorStop(1, '#07100b'); c.fillStyle = gradient; c.fillRect(0, 0, w, h);
        c.fillStyle = '#e3e9de'; c.fillRect(60, 35, 100, 45);
        c.fillStyle = '#7fba9e'; c.fillRect(350, 55, 25, 90);
    });
}

function glowTexture() {
    return canvasTexture(64, 64, (c) => {
        const g = c.createRadialGradient(32, 32, 0, 32, 32, 32);
        g.addColorStop(0, '#ffffffd0'); g.addColorStop(0.22, '#ffffff55');
        g.addColorStop(1, '#ffffff00'); c.fillStyle = g; c.fillRect(0, 0, 64, 64);
    });
}

function screenTexture(title, rtl) {
    return canvasTexture(512, 384, (c, w, h) => {
        c.fillStyle = '#0e241a'; c.fillRect(0, 0, w, h);
        c.fillStyle = '#41554a'; c.fillRect(0, 0, w, 38);
        ['#deb77a', '#8bbba0', '#6b8b77'].forEach((color, i) => {
            c.fillStyle = color; c.beginPath(); c.arc(24 + 21 * i, 19, 5, 0, Math.PI * 2); c.fill();
        });
        c.fillStyle = '#bed4c2'; c.font = '500 28px system-ui';
        c.direction = rtl ? 'rtl' : 'ltr'; c.textAlign = rtl ? 'right' : 'left';
        c.fillText(title, rtl ? w - 40 : 40, 102, 432);
        c.fillStyle = '#345e46'; c.fillRect(40, 126, 432, 82);
        c.fillStyle = '#789982'; c.fillRect(58, 143, 245, 7); c.fillRect(58, 162, 329, 7);
        c.fillStyle = '#4d7257'; c.fillRect(40, 238, 202, 91); c.fillRect(270, 238, 202, 91);
        c.fillStyle = '#91b099'; c.fillRect(56, 255, 120, 6); c.fillRect(286, 255, 133, 6);
    });
}

export class AdmissionScene {
    constructor(canvas, labels, { screenTitle = 'Your website', rtl = false } = {}) {
        this.canvas = canvas; this.screenTitle = screenTitle; this.rtl = rtl;
        this.labels = labels;
        this.resources = new Set();
        this.projected = new T.Vector3();
        this.point = new T.Vector3();
        this.scene = new T.Scene();
        this.scene.background = new T.Color('#0c1c13');
        this.scene.fog = new T.Fog('#0c1c13', 25, 65);
        this.renderer = new T.WebGLRenderer({ canvas, antialias: true, alpha: false,
            powerPreference: 'low-power' });
        try {
            this.initialize();
        } catch (error) {
            this.dispose();
            throw error;
        }
    }

    initialize() {
        this.renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.5));
        this.renderer.shadowMap.enabled = true;
        this.renderer.shadowMap.type = T.PCFShadowMap;
        this.renderer.toneMapping = T.ACESFilmicToneMapping;
        this.renderer.toneMappingExposure = 1.25;
        this.camera = new T.OrthographicCamera(-10, 10, 7, -7, 0.1, 100);
        this.geometries = { cube: this.keep(roundedCube()),
            sphere: this.keep(new T.SphereGeometry(0.05, 12, 8)),
            cylinder: this.keep(new T.CylinderGeometry(1, 1, 1, 48)),
            ring: this.keep(new T.TorusGeometry(1.45, 0.018, 6, 80)) };
        this.materials = this.createMaterials();
        this.light();
        this.build();
        this.resize();
    }

    keep(resource) { this.resources.add(resource); return resource; }

    createMaterials() {
        const result = {};
        for (const [name, color] of Object.entries({ metal: '#314a39', dark: '#12251a',
            pale: '#b9c9b6', glass: '#55705b', brass: '#b4996a' })) {
            result[name] = this.keep(new T.MeshStandardMaterial({ color, metalness: 0.65,
                roughness: name === 'brass' ? 0.28 : 0.36 }));
        }
        for (const [name, color] of Object.entries(colors)) {
            result[name] = this.keep(new T.MeshStandardMaterial({ color, metalness: 0.25,
                roughness: 0.28, emissive: color, emissiveIntensity: 0.5 }));
        }
        result.floor = this.keep(new T.MeshStandardMaterial({ color: '#172b1c',
            roughness: 0.62, metalness: 0.25 }));
        return result;
    }

    light() {
        this.scene.add(new T.HemisphereLight('#ebf6e2', '#172b20', 2));
        const key = new T.DirectionalLight('#fff3d7', 4);
        key.position.set(-5, 12, 8); key.castShadow = true;
        key.shadow.mapSize.set(1024, 1024);
        Object.assign(key.shadow.camera, { left: -13, right: 13, top: 9, bottom: -9,
            near: 0.1, far: 40 });
        key.shadow.bias = -0.0002; key.shadow.normalBias = 0.03;
        this.keep(key.shadow);
        this.scene.add(key, new T.AmbientLight('#537961', 0.45));
        const fill = new T.DirectionalLight('#97d7b5', 2);
        fill.position.set(9, 5, -7); this.scene.add(fill);
        const studio = this.keep(studioTexture());
        studio.mapping = T.EquirectangularReflectionMapping;
        const generator = new T.PMREMGenerator(this.renderer);
        try {
            this.environment = generator.fromEquirectangular(studio);
            this.scene.environment = this.environment.texture;
        } finally { generator.dispose(); }
    }

    box(parent, x, y, z, w, h, d, material) {
        const object = new T.Mesh(this.geometries.cube, material);
        object.position.set(x, y, z); object.scale.set(w, h, d);
        object.castShadow = true; object.receiveShadow = true;
        parent.add(object);
        return object;
    }

    pedestal(parent, width = 2) {
        this.box(parent, 0, 0.12, 0, width, 0.22, 1.7, this.materials.metal);
        this.box(parent, 0, 0.02, 0, width + 0.12, 0.08, 1.82, this.materials.dark);
    }

    led(parent, x, y, z, material) {
        const light = new T.Mesh(this.geometries.sphere, material);
        light.position.set(x, y, z); parent.add(light);
        return light;
    }

    node(name) {
        const node = new T.Group();
        node.position.set(...positions[name]); this.scene.add(node);
        this.pedestal(node, name === 'app' ? 2.6 : 2);
        return node;
    }

    browser() {
        const node = this.node('client');
        this.box(node, 0, 0.62, 0, 0.36, 0.95, 0.36, this.materials.metal);
        this.box(node, 0, 1.62, 0, 2.16, 1.62, 0.16, this.materials.dark);
        const material = this.keep(new T.MeshBasicMaterial({ map: this.keep(screenTexture(this.screenTitle, this.rtl)) }));
        const screen = new T.Mesh(this.keep(new T.PlaneGeometry(1.97, 1.43)), material);
        screen.position.set(0, 1.62, 0.092); node.add(screen);
        this.box(node, 0, 0.38, 0.78, 1.9, 0.08, 0.6, this.materials.metal);
        for (let i = 0; i < 8; i++) {
            this.box(node, -0.7 + i * 0.2, 0.43, 0.78, 0.13, 0.025, 0.37, this.materials.dark);
        }
        this.clientToken = this.box(node, 0.85, 2.47, 0.1, 0.23, 0.23, 0.23, this.materials.green);
    }

    ingress() {
        const node = this.node('ingress');
        this.box(node, -0.64, 1.22, 0, 0.22, 1.98, 0.53, this.materials.pale);
        this.box(node, 0.64, 1.22, 0, 0.22, 1.98, 0.53, this.materials.pale);
        this.box(node, 0, 2.17, 0, 1.47, 0.22, 0.53, this.materials.pale);
        this.box(node, 0, 1.24, -0.18, 1.13, 1.7, 0.07, this.materials.glass);
        const ring = new T.Mesh(this.keep(new T.TorusGeometry(0.16, 0.04, 8, 24)),
            this.materials.brass);
        ring.position.set(0, 1.55, 0.35); node.add(ring);
        this.box(node, 0, 1.3, 0.35, 0.37, 0.3, 0.09, this.materials.brass);
        this.led(node, 0, 0.39, 0.68, this.materials.green);
    }

    protector() {
        const node = this.node('sibuna');
        const base = new T.Mesh(this.geometries.cylinder, this.materials.dark);
        base.scale.set(1.37, 0.16, 1.37); base.position.y = 0.32; node.add(base);
        this.box(node, 0, 1.11, 0, 1.6, 1.38, 1.14, this.materials.metal);
        this.box(node, 0, 1.82, 0, 1.72, 0.16, 1.26, this.materials.pale);
        this.box(node, 0, 0.43, 0, 1.72, 0.12, 1.26, this.materials.dark);
        const logo = this.keep(canvasTexture(256, 256, (c) => {
            c.fillStyle = '#11281a'; c.fillRect(0, 0, 256, 256);
            c.fillStyle = '#d2e5cb'; c.font = '600 135px system-ui'; c.fillText('s.', 57, 175);
        }));
        const face = new T.Mesh(this.keep(new T.PlaneGeometry(0.92, 0.92)),
            this.keep(new T.MeshBasicMaterial({ map: logo })));
        face.position.set(0, 1.12, 0.58); node.add(face);
        for (let i = 0; i < 5; i++) {
            this.box(node, 0.82, 0.68 + i * 0.16, 0, 0.04, 0.045, 0.64, this.materials.dark);
        }
        this.aura = new T.Mesh(this.geometries.ring, this.materials.green);
        this.aura.rotation.x = -Math.PI / 2; this.aura.position.y = 0.46; node.add(this.aura);
        this.checkToken = this.box(node, 0, 2.4, 0, 0.26, 0.26, 0.26, this.materials.green);
    }

    application() {
        const node = this.node('app');
        this.appLights = [];
        for (let rack = 0; rack < 2; rack++) {
            for (let row = 0; row < 4; row++) {
                const x = -0.61 + rack * 1.22, y = 0.53 + row * 0.42;
                this.box(node, x, y, 0, 1.03, 0.34, 1.14, this.materials.metal);
                this.box(node, x, y, 0.59, 0.87, 0.23, 0.045, this.materials.dark);
                for (let i = 0; i < 3; i++) {
                    this.box(node, x - 0.26 + i * 0.12, y, 0.622,
                        0.04, 0.13, 0.012, this.materials.glass);
                }
                this.appLights.push(this.led(node, x + 0.29, y, 0.65, this.materials.green));
            }
        }
    }

    curve(points, color = '#416a4a', radius = 0.023) {
        const path = new T.CatmullRomCurve3(points.map(p => new T.Vector3(...p)));
        const mesh = new T.Mesh(this.keep(new T.TubeGeometry(path, 64, radius, 5, false)),
            this.keep(new T.MeshStandardMaterial({ color, roughness: 0.55, metalness: 0.3 })));
        this.scene.add(mesh);
        return path;
    }

    tracks() {
        this.inbound = this.curve([[-6.5, 0.45, 1.18], [-3, 0.45, 1.18], [0.7, 0.45, 1.18]]);
        this.outbound = this.curve([[0.7, 0.45, 1.18], [3.3, 0.45, 1.18], [6, 0.45, 1.18]]);
        this.challenge = this.curve([[0.7, 0.5, 1.18], [0.2, 0.57, 3.1],
            [-3.2, 0.57, 3.7], [-6.5, 0.6, 3], [-6.5, 0.45, 1.18]], '#746543', 0.015);
        this.proof = this.curve([[-5.5, 0.52, 2.7], [-4, 0.8, 3.2],
            [-1, 0.95, 3.2], [0.7, 1.4, 1.18]], '#746543', 0.015);
        this.work = [];
        for (let i = 0; i < 5; i++) {
            this.work.push(this.box(this.scene, -5.5 + i * 0.68, 0.33, 2.65,
                0.38, 0.26, 0.38, this.materials.dark));
        }
    }

    packet() {
        const packet = new T.Group();
        this.packetBody = this.box(packet, 0, 0, 0, 0.19, 0.19, 0.19, this.materials.white);
        const material = this.keep(new T.SpriteMaterial({ map: this.keep(glowTexture()),
            color: '#a1e8ba', transparent: true, depthWrite: false,
            blending: T.AdditiveBlending, opacity: 0.45 }));
        this.packetGlow = new T.Sprite(material); this.packetGlow.scale.setScalar(0.95);
        packet.add(this.packetGlow); this.scene.add(packet);
        return packet;
    }

    build() {
        const floor = new T.Mesh(this.keep(new T.PlaneGeometry(200, 200)), this.materials.floor);
        floor.rotation.x = -Math.PI / 2; floor.position.y = -0.05;
        floor.receiveShadow = true; this.scene.add(floor);
        const grid = new T.GridHelper(36, 45, '#355a3b', '#26422d');
        grid.material.transparent = true; grid.material.opacity = 0.2;
        grid.position.y = -0.04; this.keep(grid.geometry); this.keep(grid.material); this.scene.add(grid);
        this.browser(); this.ingress(); this.protector(); this.application(); this.tracks();
        this.traveller = this.packet();
        this.batchStaticBoxes();
    }

    batchStaticBoxes() {
        // Keep animated objects independent. Static housings share one draw per material.
        const dynamic = new Set([...this.work, this.packetBody, this.clientToken, this.checkToken]);
        const groups = new Map();
        this.scene.updateMatrixWorld(true);
        this.scene.traverse(object => {
            if (object.geometry !== this.geometries.cube || dynamic.has(object)) return;
            const group = groups.get(object.material) ?? [];
            group.push(object); groups.set(object.material, group);
        });
        for (const [material, objects] of groups) {
            const batch = this.keep(new T.InstancedMesh(this.geometries.cube, material, objects.length));
            batch.castShadow = true; batch.receiveShadow = true;
            objects.forEach((object, index) => {
                batch.setMatrixAt(index, object.matrixWorld);
                object.removeFromParent();
            });
            this.scene.add(batch);
        }
    }

    resize() {
        this.width = this.canvas.parentElement.clientWidth;
        this.height = this.canvas.parentElement.clientHeight;
        this.renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.5));
        this.renderer.setSize(this.width, this.height, false);
        const halfWidth = 10.1, halfHeight = halfWidth * this.height / this.width;
        Object.assign(this.camera, { left: -halfWidth, right: halfWidth,
            top: halfHeight, bottom: -halfHeight });
        this.camera.position.set(3.5, 12.5, 19);
        this.camera.lookAt(0, 0.4, 0.7); this.camera.updateProjectionMatrix();
        this.projectLabels();
    }

    projectLabels() {
        this.camera.updateMatrixWorld();
        for (const label of this.labels) {
            const p = positions[label.dataset.node];
            this.projected.set(p[0], 2.95, p[2]).project(this.camera);
            label.style.left = `${(this.projected.x + 1) * this.width / 2}px`;
            label.style.top = `${(1 - this.projected.y) * this.height / 2 - 20}px`;
        }
    }

    move(path, progress, color) {
        path.getPointAt(progress, this.point);
        this.traveller.position.copy(this.point); this.traveller.position.y += 0.1;
        this.packetBody.material = this.materials[color];
        this.packetGlow.material.color.set(colors[color]);
        this.traveller.visible = true;
    }

    first(time) {
        // Retain the completed chain while its proof travels back to Sibuna.
        // The first cell is visible when manually stepping into the work stage.
        const completed = time < F.work ? 0 :
            Math.max(1, fraction(time, F.work, F.proof) * this.work.length);
        this.work.forEach((cell, i) => {
            cell.material = i < completed ? this.materials.gold : this.materials.dark;
            cell.position.y = 0.33 + (i < completed && i + 1 > completed ? 0.07 : 0);
        });
        if (time < F.challenge) this.move(this.inbound, fraction(time, 0, F.challenge), 'white');
        else if (time < F.work) {
            this.move(this.challenge, fraction(time, F.challenge, F.work), 'gold');
        } else if (time < F.proof) this.traveller.visible = false;
        else if (time < F.verification) {
            this.move(this.proof, fraction(time, F.proof, F.verification), 'gold');
        } else if (time < F.retry) this.traveller.visible = false;
        else if (time < F.checks) {
            this.move(this.inbound, fraction(time, F.retry, F.checks), 'white');
        } else if (time < F.forward) this.move(this.inbound, 1, 'white');
        else this.move(this.outbound, fraction(time, F.forward, F.end), 'green');
        this.checkToken.visible = time >= F.verification && time < F.retry;
        this.clientToken.visible = time >= F.retry;
    }

    render(frame) {
        const t = frame.elapsed;
        this.work.forEach(cell => { cell.material = this.materials.dark; cell.position.y = 0.33; });
        this.checkToken.visible = false; this.clientToken.visible = frame.name !== 'first';
        this.aura.material = frame.name === 'blocked' && t >= R.checks ?
            this.materials.red : this.materials.green;
        if (frame.name === 'first') this.first(t);
        else if (t < R.checks) this.move(this.inbound, fraction(t, 0, R.checks), 'white');
        else if (t < R.forward) {
            this.move(this.inbound, 1, frame.name === 'blocked' ? 'red' : 'white');
        } else if (frame.name === 'session') {
            this.move(this.outbound, fraction(t, R.forward, R.end), 'green');
        } else {
            this.move(this.inbound, 1, 'red');
            this.traveller.scale.setScalar(1 - fraction(t, R.forward, R.end));
        }
        if (frame.name !== 'blocked' || t < R.forward) this.traveller.scale.setScalar(1);
        this.packetBody.rotation.set(t * 0.3, t * 0.5, Math.PI / 4);
        this.checkToken.rotation.set(0, t * 0.5, Math.PI / 4);
        const admitted = (frame.name === 'first' && t >= F.forward) ||
            (frame.name === 'session' && t >= R.forward);
        this.appLights.forEach((led, i) => {
            led.scale.setScalar(admitted ? 1 + 0.2 * Math.sin(t * 3 + i) : 0.6);
        });
        this.renderer.render(this.scene, this.camera);
    }

    dispose() {
        this.resources.forEach(resource => resource.dispose());
        this.environment?.dispose(); this.renderer?.dispose();
        this.resources.clear();
    }
}
