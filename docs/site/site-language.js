// Copyright 2026 Vikrant Rathore and Sibuna contributors. LGPL-3.0-or-later; see LICENSE.
// The language menu remembers a choice, and the English landing page opens the edition
// in the visitor's language. A choice is a link with ?lang=<code>: it works without
// storage, and the page it opens stores it. Only the English landing page redirects, and
// only when no choice is stored and the browser prefers another edition's language.
const supported = ['en', 'zh-Hans', 'ko', 'ja', 'es', 'de', 'hi', 'ar'];
const storageKey = 'sibuna-language';

// The edition for a browser language tag, or null. Simplified Chinese is not offered
// for Traditional Chinese.
export function languageCode(value) {
    const language = String(value ?? '').toLowerCase();
    if (language === 'zh' || language.startsWith('zh-')) {
        const parts = language.split('-');
        if (parts.includes('hant')) return null;
        if (language === 'zh' || parts.includes('hans') ||
            parts.includes('cn') || parts.includes('sg')) return 'zh-Hans';
        return null;
    }
    return supported.find(code => code !== 'zh-Hans' &&
        (language === code || language.startsWith(`${code}-`))) ?? null;
}

export function preferredLanguage(stored, languages) {
    if (supported.includes(stored)) return stored;
    return languages.map(languageCode).find(Boolean) ?? 'en';
}

function remember(code) {
    try { localStorage.setItem(storageKey, code); }
    catch { /* Without storage the ?lang= link still selects the edition. */ }
}

function stored() {
    try { return localStorage.getItem(storageKey); }
    catch { return null; }
}

function initialize() {
    const explicit = new URL(location.href).searchParams.get('lang');
    if (supported.includes(explicit)) remember(explicit);
    const links = [...document.querySelectorAll('[data-language-choice]')];
    // A choice of the same page in another language keeps the section being read.
    const follow = () => {
        for (const link of links) {
            if (link.dataset.samePage !== 'true') continue;
            const target = new URL(link.href);
            target.hash = location.hash;
            link.href = target.href;
        }
    };
    follow();
    addEventListener('hashchange', follow);
    for (const link of links) {
        link.addEventListener('click', () => remember(link.dataset.languageChoice));
    }
    if (document.documentElement.dataset.detectLanguage !== 'true' ||
        supported.includes(explicit)) return;
    const desired = preferredLanguage(stored(), navigator.languages?.length ?
        navigator.languages : [navigator.language]);
    const link = links.find(item => item.dataset.languageChoice === desired);
    if (desired !== 'en' && link) location.replace(link.href);
}

if (typeof document !== 'undefined') initialize();
