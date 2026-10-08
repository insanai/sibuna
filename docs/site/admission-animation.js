// Copyright 2026 Vikrant Rathore and Ronak Rathore. LGPL-3.0; see LICENSE.
import { journeys, order, frameAt, nextStep } from './admission-model.js';

class AdmissionAnimation {
    constructor(root) {
        this.root = root;
        this.messages = JSON.parse(root.querySelector('[data-demo-language]')?.textContent || '{}');
        this.name = 'first'; this.time = 0; this.playing = false; this.visible = false;
        this.frame = 0; this.last = 0; this.drawn = 0; this.caption = '';
        this.scene = null; this.loading = false; this.lost = false; this.disposed = false;
        this.reduced = matchMedia('(prefers-reduced-motion: reduce)');
        this.ui = {};
        for (const name of ['play', 'heading', 'description', 'number', 'status']) {
            this.ui[name] = root.querySelector(`[data-demo="${name}"]`);
        }
        this.progress = root.querySelector('.demo-progress div');
        this.tick = this.tick.bind(this);
        this.schedule = this.schedule.bind(this);
        this.motion = this.motion.bind(this);
        this.bindControls(); this.observe();
        root.dataset.interactive = 'true';
        this.motion(); this.draw();
    }

    draw(manual = false) {
        const frame = frameAt(this.name, this.time);
        if (this.caption !== `${frame.name}:${frame.index}`) {
            this.caption = `${frame.name}:${frame.index}`;
            this.ui.heading.textContent = this.text(frame.title);
            this.ui.description.textContent = this.text(frame.text);
            this.ui.number.textContent = `${frame.index + 1} / ${frame.steps}`;
        }
        this.progress.style.width = `${frame.progress * 100}%`;
        this.scene?.render(frame);
        if (manual) this.root.querySelector('.demo-announcement').textContent =
            `${this.text(frame.title)} ${this.text(frame.text)}`;
        this.root.dataset.journey = frame.name;
        this.root.dataset.step = String(frame.index);
    }

    text(value) { return this.messages[value] ?? value; }

    controls() {
        this.ui.play.textContent = this.text(this.playing ? 'Pause' : 'Play');
        this.ui.play.setAttribute('aria-pressed', String(this.playing));
        this.ui.status.textContent = this.text(this.lost ? 'Static view · 3D is unavailable' :
            this.playing ? 'Playing illustration' : this.reduced.matches ?
                'Reduced motion · step through' : 'Paused illustration');
        for (const button of this.root.querySelectorAll('[data-journey]')) {
            button.setAttribute('aria-pressed', String(button.dataset.journey === this.name));
        }
    }

    schedule() {
        const active = this.playing && this.visible && !document.hidden && !this.disposed;
        if (!active) {
            cancelAnimationFrame(this.frame); this.frame = 0; this.last = 0;
        } else if (!this.frame) this.frame = requestAnimationFrame(this.tick);
    }

    tick(now) {
        this.frame = 0;
        if (this.last) this.time += Math.min((now - this.last) / 1000, 0.1);
        this.last = now;
        if (this.time >= journeys[this.name].duration) {
            this.name = order[(order.indexOf(this.name) + 1) % order.length];
            this.time = 0; this.controls();
        }
        // Bound GPU work to 30 fps. Hidden, offscreen and paused views have no frame loop.
        if (now - this.drawn >= 1000 / 30) { this.draw(); this.drawn = now; }
        this.schedule();
    }

    async load() {
        if (this.scene || this.loading || this.lost || this.disposed) return;
        this.loading = true;
        try {
            const { AdmissionScene } = await import('./admission-scene.bundle.js');
            if (this.disposed || this.lost) return;
            this.scene = new AdmissionScene(this.root.querySelector('canvas'),
                this.root.querySelectorAll('.demo-node'), { screenTitle: this.text('Your website'),
                    rtl: document.documentElement.dir === 'rtl' });
            this.draw(); this.root.dataset.renderer = 'ready';
        } catch {
            // Keep an informative SVG and the complete text journey if WebGL cannot start.
            this.fallback();
        } finally { this.loading = false; }
    }

    fallback() {
        this.lost = true; this.playing = false;
        this.scene?.dispose(); this.scene = null;
        this.root.dataset.renderer = 'fallback'; this.controls(); this.schedule();
    }

    motion() { this.playing = !this.reduced.matches && !this.lost; this.controls(); this.schedule(); }

    bindControls() {
        this.ui.play.addEventListener('click', () => {
            this.playing = !this.playing; this.controls(); this.schedule();
        });
        this.root.querySelector('[data-demo="step"]').addEventListener('click', () => {
            this.playing = false; this.time = nextStep(this.name, this.time);
            this.controls(); this.schedule(); this.draw(true);
        });
        for (const button of this.root.querySelectorAll('[data-journey]')) {
            button.addEventListener('click', () => {
                this.name = button.dataset.journey; this.time = 0;
                this.controls(); this.draw(true);
            });
        }
        this.root.querySelector('canvas').addEventListener('webglcontextlost', event => {
            event.preventDefault(); this.fallback();
        });
    }

    observe() {
        this.observer = new IntersectionObserver(entries => {
            this.visible = entries[0].isIntersecting;
            if (this.visible) this.load();
            this.schedule();
        }, { threshold: 0.08 });
        this.observer.observe(this.root);
        this.resize = new ResizeObserver(() => { this.scene?.resize(); this.draw(); });
        this.resize.observe(this.root.querySelector('.demo-stage'));
        document.addEventListener('visibilitychange', this.schedule);
        this.reduced.addEventListener('change', this.motion);
        addEventListener('pagehide', event => {
            this.visible = false; this.schedule();
            if (event.persisted) return;
            this.disposed = true; this.observer.disconnect(); this.resize.disconnect();
            this.reduced.removeEventListener('change', this.motion);
            document.removeEventListener('visibilitychange', this.schedule);
            this.scene?.dispose(); this.scene = null;
        });
        addEventListener('pageshow', event => {
            if (!event.persisted) return;
            const bounds = this.root.getBoundingClientRect();
            this.visible = bounds.top < innerHeight && bounds.bottom > 0;
            if (this.visible) this.load();
            this.schedule();
        });
    }
}

const root = document.querySelector('.admission-demo');
if (root) new AdmissionAnimation(root);
