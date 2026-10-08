// Copyright 2026 Vikrant Rathore and Ronak Rathore. LGPL-3.0; see LICENSE.
const supported = ['en', 'zh-Hans', 'ko', 'ja', 'es', 'de', 'hi', 'ar'];
const storageKey = 'sibuna-language';

export function languageCode(value) {
    const language = String(value ?? '').toLowerCase();
    if (language === 'zh' || language.startsWith('zh-')) {
        const parts = language.split('-');
        if (parts.includes('hant')) return null;
        if (language === 'zh' || parts.includes('hans') ||
            parts.includes('cn') || parts.includes('sg')) return 'zh-Hans';
        return null;
    }
    // Do not present Simplified Chinese as a Traditional Chinese edition.
    return supported.find(code => code !== 'zh-Hans' &&
        (language === code || language.startsWith(`${code}-`))) ?? null;
}

export function preferredLanguage(stored, languages) {
    if (supported.includes(stored)) return stored;
    return languages.map(languageCode).find(Boolean) ?? 'en';
}

function updateAnchor(link) {
    if (link.dataset.samePage !== 'true') return;
    const target = new URL(link.href);
    target.hash = location.hash;
    link.href = target.href;
}

function initialize() {
    const root = document.documentElement;
    const explicit = new URL(location.href).searchParams.get('lang');
    // A bookmarked manual choice must remain effective on the next navigation too.
    if (supported.includes(explicit) &&
        (explicit === root.lang || root.dataset.detectLanguage === 'true')) {
        try { localStorage.setItem(storageKey, explicit); }
        catch { /* The explicit URL still selects the edition without browser storage. */ }
    }
    const links = [...document.querySelectorAll('[data-language-choice]')];
    for (const link of links) {
        const target = new URL(link.href);
        // A manual selection survives denied storage and keeps the current book anchor.
        target.search = location.search;
        target.searchParams.set('lang', link.dataset.languageChoice);
        if (link.dataset.samePage === 'true') target.hash = location.hash;
        link.href = target.href;
        link.addEventListener('click', () => {
            try { localStorage.setItem(storageKey, link.dataset.languageChoice); }
            catch { /* Explicit URL selection remains usable without browser storage. */ }
        });
    }
    addEventListener('hashchange', () => links.forEach(updateAnchor));
    if (root.dataset.detectLanguage !== 'true' || root.lang !== 'en') return;
    let stored;
    try { stored = localStorage.getItem(storageKey); }
    catch { /* Browser language still works when storage is unavailable. */ }
    const desired = supported.includes(explicit) ? explicit :
        preferredLanguage(stored, navigator.languages?.length ? navigator.languages :
            [navigator.language]);
    const link = links.find(item => item.dataset.languageChoice === desired);
    if (desired !== 'en' && link) location.replace(link.href);
}

if (typeof document !== 'undefined') initialize();
