#import "theme.typ": configure-document, document-frontmatter

#let shd-placeholder-number = "XXXXX"

#let shd-state-fill(state) = {
  if state == "published" {
    rgb("dbeafe")
  } else if state == "discussion" {
    rgb("dcfce7")
  } else if state == "committed" {
    rgb("ede9fe")
  } else if state == "abandoned" {
    rgb("e5e7eb")
  } else {
    rgb("fef3c7")
  }
}

#let shd-chip(label, fill) = box(
  inset: (x: 0.45em, y: 0.25em),
  radius: 999pt,
  fill: fill,
  stroke: none,
)[
  #text(9pt, weight: "semibold")[#label]
]

#let shd-title(number, title) = {
  if number == shd-placeholder-number {
    [SHD #shd-placeholder-number: #title]
  } else {
    [SHD #number: #title]
  }
}

#let authors-block(authors) = {
  if authors.len() == 0 {
    [Sibuna Contributors]
  } else {
    authors.join("\n")
  }
}

#let shd-label(label) = text(8.7pt, weight: "bold", tracking: 0.04em, fill: rgb("475569"))[#label]

#let shd-value(body) = text(10.2pt, fill: rgb("111827"))[#body]

#let html-style = "
:root {
  --font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Menlo', 'Courier New', monospace;
  
  --bg-primary: #ffffff;
  --bg-secondary: #f8fafc;
  --bg-accent: #f1f5f9;
  
  --text-primary: #0f172a;
  --text-secondary: #334155;
  --text-muted: #64748b;
  
  --border-color: #e2e8f0;
  
  --color-primary: #0284c7;
  --color-primary-hover: #0369a1;
  
  --state-published-bg: #dcfce7;
  --state-published-text: #166534;
  --state-discussion-bg: #dbeafe;
  --state-discussion-text: #1e40af;
  --state-accepted-bg: #fef9c3;
  --state-accepted-text: #854d0e;
  --state-committed-bg: #f3e8ff;
  --state-committed-text: #6b21a8;
  --state-abandoned-bg: #f1f5f9;
  --state-abandoned-text: #475569;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-accent: #334155;
    
    --text-primary: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    
    --border-color: #334155;
    
    --color-primary: #38bdf8;
    --color-primary-hover: #7dd3fc;
    
    --state-published-bg: rgba(22, 101, 52, 0.3);
    --state-published-text: #86efac;
    --state-discussion-bg: rgba(30, 64, 175, 0.3);
    --state-discussion-text: #93c5fd;
    --state-accepted-bg: rgba(133, 77, 14, 0.3);
    --state-accepted-text: #fde047;
    --state-committed-bg: rgba(107, 33, 168, 0.3);
    --state-committed-text: #e9d5ff;
    --state-abandoned-bg: rgba(71, 85, 105, 0.3);
    --state-abandoned-text: #cbd5e1;
  }
}

body {
  font-family: var(--font-sans);
  background-color: var(--bg-primary);
  color: var(--text-primary);
  line-height: 1.75;
  margin: 0;
  padding: 0;
  -webkit-font-smoothing: antialiased;
}

.shd-container {
  max-width: 880px;
  margin: 4rem auto;
  padding: 0 2rem;
}

.shd-back-link {
  margin-bottom: 2rem;
  font-size: 0.95rem;
  font-weight: 600;
}

.shd-back-link a {
  color: var(--text-muted) !important;
  border-bottom: none !important;
  text-decoration: none;
  transition: color 0.15s ease;
}

.shd-back-link a:hover {
  color: var(--color-primary) !important;
}

.shd-header {
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 2.5rem;
  margin-bottom: 3rem;
}

.shd-badge {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0.35rem 0.85rem;
  border-radius: 9999px;
  margin-bottom: 1.25rem;
}

.shd-badge.published { background: var(--state-published-bg); color: var(--state-published-text); }
.shd-badge.discussion { background: var(--state-discussion-bg); color: var(--state-discussion-text); }
.shd-badge.accepted { background: var(--state-accepted-bg); color: var(--state-accepted-text); }
.shd-badge.committed { background: var(--state-committed-bg); color: var(--state-committed-text); }
.shd-badge.abandoned { background: var(--state-abandoned-bg); color: var(--state-abandoned-text); }

.shd-title {
  font-size: 2.5rem;
  font-weight: 800;
  line-height: 1.2;
  letter-spacing: -0.03em;
  margin: 0 0 2rem 0;
}

.shd-meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.25rem;
  background-color: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.5rem;
}

.shd-meta-item {
  display: flex;
  flex-direction: column;
}

.shd-meta-label {
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted);
  letter-spacing: 0.05em;
  margin-bottom: 0.35rem;
}

.shd-meta-val {
  font-size: 0.95rem;
  color: var(--text-secondary);
  font-weight: 600;
}

h1, h2, h3, h4 {
  color: var(--text-primary);
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.3;
}

h2 {
  font-size: 1.8rem;
  margin-top: 3.5rem;
  margin-bottom: 1.25rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--border-color);
}

h3 {
  font-size: 1.4rem;
  margin-top: 2.5rem;
  margin-bottom: 1rem;
}

p {
  margin-top: 0;
  margin-bottom: 1.6rem;
  font-size: 1.075rem;
  color: var(--text-secondary);
}

ul, ol {
  margin-top: 0;
  margin-bottom: 1.6rem;
  padding-left: 1.75rem;
}

li {
  margin-bottom: 0.5rem;
  font-size: 1.05rem;
  color: var(--text-secondary);
}

code {
  font-family: var(--font-mono);
  font-size: 0.9rem;
  background-color: var(--bg-secondary);
  padding: 0.2rem 0.45rem;
  border-radius: 6px;
  border: 1px solid var(--border-color);
}

pre {
  background-color: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.5rem;
  overflow-x: auto;
  margin-bottom: 1.8rem;
}

pre code {
  background-color: transparent;
  padding: 0;
  border: none;
  font-size: 0.9rem;
}

a {
  color: var(--color-primary);
  text-decoration: none;
  border-bottom: 1px dashed var(--color-primary);
  transition: all 0.2s ease;
}

a:hover {
  color: var(--color-primary-hover);
  border-bottom-style: solid;
}

.shd-index-header {
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 2rem;
  margin-bottom: 3rem;
}

.shd-index-header h1 {
  font-size: 3rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  margin: 0 0 1rem 0;
}

.shd-index-header p {
  font-size: 1.2rem;
  color: var(--text-secondary);
  margin: 0;
}

.shd-index-card {
  background-color: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.75rem;
  margin-bottom: 1.5rem;
  transition: transform 0.15s ease, border-color 0.15s ease;
}

.shd-index-card:hover {
  border-color: var(--color-primary);
  transform: translateY(-2px);
}

.shd-card-title {
  font-size: 1.5rem;
  margin: 0 0 0.75rem 0;
}

.shd-card-desc {
  font-size: 1rem;
  color: var(--text-secondary);
  margin: 0 0 1.25rem 0;
  line-height: 1.6;
}

.shd-card-links {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.25rem;
}

.shd-card-links a {
  font-size: 0.875rem;
  font-weight: 600;
  padding: 0.4rem 0.8rem;
  background-color: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  border-bottom: 1px solid var(--border-color);
}

.shd-card-links a:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.shd-card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1.25rem;
  font-size: 0.825rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border-color);
  padding-top: 1rem;
}
"

#let shd-document(
  number,
  title,
  body,
  authors: (),
  state: "prediscussion",
  created: "YYYY-MM-DD",
  discussion: "",
  labels: (),
  category: "Engineering Discussion",
  status: "Draft",
  last-updated: "None",
) = context {
  if target() == "html" {
    [
      #html.elem("style")[#html-style]
      #html.elem("div", attrs: (class: "shd-container"))[
        #html.elem("div", attrs: (class: "shd-back-link"))[
          #html.elem("a", attrs: (href: "../index.html"))[← Back to Shibuna Discussions]
        ]
        #html.elem("header", attrs: (class: "shd-header"))[
          #html.elem("span", attrs: (class: "shd-badge " + state))[#state]
          #html.elem("h1", attrs: (class: "shd-title"))[#shd-title(number, title)]
          #html.elem("div", attrs: (class: "shd-meta-grid"))[
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Document]
              #html.elem("span", attrs: (class: "shd-meta-val"))[SHD #number]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Category]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#category]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Status]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#status]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Created]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#created]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Last Updated]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#last-updated]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Authors]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#authors-block(authors)]
            ]
            #html.elem("div", attrs: (class: "shd-meta-item"))[
              #html.elem("span", attrs: (class: "shd-meta-label"))[Discussion]
              #html.elem("span", attrs: (class: "shd-meta-val"))[#discussion]
            ]
          ]
        ]

        #body
      ]
    ]
  } else {
    [
      #set document(
        title: [SHD #number: #title],
        author: authors,
        description: [#discussion],
        date: none,
      )
      #configure-document()
      #set page(margin: (x: 1.15in, y: 1in), numbering: "1")
      #set par(justify: true)
      #set heading(numbering: "1.")

      #block(inset: (x: 1.05em, y: 0.95em), stroke: 0.65pt + rgb("d7dee8"), fill: luma(99%))[
        #set par(justify: false)
        #grid(
          columns: (1fr, auto),
          column-gutter: 1.4em,
          align: (left, top),
          [
            #text(12.4pt, weight: "bold")[Sibuna Working Group]
            #linebreak()
            #text(9.3pt, fill: rgb("64748b"))[Request for Discussion and Implementation Record]
          ],
          [
            #align(right)[
              #text(13.5pt, weight: "bold")[SHD #if number == shd-placeholder-number { [#shd-placeholder-number] } else { [#number] }]
              #linebreak()
              #text(9.3pt, weight: "semibold", fill: rgb("64748b"))[#category]
            ]
          ],
        )

        #v(0.95em)
        #text(21pt, weight: "bold")[#title]

        #v(0.55em)
        #line(length: 100%, stroke: 0.7pt + rgb("e2e8f0"))

        #v(0.8em)
        #grid(
          columns: (1fr, 1fr),
          column-gutter: 1.9em,
          row-gutter: 0.5em,
          align: (left, top),
          [#shd-label[STATE]],
          [#shd-label[INTENDED STATUS]],
          [#shd-chip(state, shd-state-fill(state))],
          [#shd-value[#status]],
          [#shd-label[CREATED]],
          [#shd-label[AUTHORS]],
          [#shd-value[#created]],
          [#block(width: 100%)[#shd-value[#authors-block(authors)]]],
          [#shd-label[LAST UPDATED]],
          [],
          [#shd-value[#last-updated]],
          [],
        )

        #v(0.65em)
        #shd-label[DISCUSSION]
        #linebreak()
        #block(width: 100%)[#shd-value[#discussion]]

        #if labels.len() > 0 [
          #v(0.65em)
          #shd-label[LABELS]
          #linebreak()
          #text(10pt, fill: rgb("334155"))[#labels.join(", ")]
        ]
      ]

      #v(1em)

      #block(inset: 0.9em, stroke: 0.7pt + rgb("9ca3af"), fill: luma(98%))[
        *Status of This Memo*

        This document is an internal Sibuna discussion record authored in Typst and tracked in git. It intentionally follows RFC-style structure so the design scope, rationale, trade-offs, and operational constraints remain explicit. Documents that still use the placeholder number #text(font: "Libertinus Mono", size: 10pt)[#shd-placeholder-number] are provisional drafts. Numbered SHD documents are part of the permanent project record.
      ]

      #v(1em)
      #outline(indent: 1.4em)
      #v(1em)

      #body
    ]
  }
}

#let shd-index-entry(doc) = [
  #block(inset: 0.8em, stroke: 0.65pt + rgb("d7dee8"), fill: luma(99%), radius: 4pt)[
    #grid(
      columns: (1fr, auto),
      column-gutter: 1.2em,
      align: (left, top),
      [
        #text(12.5pt, weight: "bold")[SHD #doc.number: #doc.title]
        #linebreak()
        #text(9.3pt, fill: rgb("64748b"))[#doc.summary]
      ],
      [
        #align(right)[
          #shd-chip(doc.state, shd-state-fill(doc.state))
          #linebreak()
          #text(8.7pt, fill: rgb("64748b"))[#doc.area]
        ]
      ],
    )

    #v(0.55em)
    #grid(
      columns: (auto, 1fr, auto, 1fr),
      column-gutter: 0.8em,
      row-gutter: 0.25em,
      [#shd-label[STATUS]], [#shd-value[#doc.status]],
      [#shd-label[CREATED]], [#shd-value[#doc.created]],
      [#shd-label[CATEGORY]], [#shd-value[#doc.category]],
      [#shd-label[UPDATED]], [#shd-value[#doc.updated]],
    )

    #v(0.55em)
    #text(9.2pt, fill: rgb("334155"))[
      Source: #raw(doc.source)
    ]
  ]
]

#let shd-index-page(documents) = [
  = Index

  Shibuna Discussions (SHD) are RFC/RFD-style design records for the sibuna monorepo: the high-performance Web AI Firewall and anti-crawler daemon. Each SHD is a standalone Typst source file with metadata, lifecycle state, area, and summary data surfaced in this index.

  Placeholder drafts use the number #raw(shd-placeholder-number) until maintainers assign the next permanent four-digit SHD number.

  #for doc in documents [
    #shd-index-entry(doc)
    #v(0.65em)
  ]
]

#let shd-site-index(documents) = [
  #html.elem("style")[#html-style]
  
  #html.elem("div", attrs: (class: "shd-container"))[
    #html.elem("div", attrs: (class: "shd-index-header"))[
      #html.elem("h1")[Shibuna Discussions]
      #html.elem("p")[Index of Shibuna Discussion (SHD) records.]
    ]

    #for doc in documents [
      #html.elem("div", attrs: (class: "shd-index-card"))[
        #html.elem("span", attrs: (class: "shd-badge " + doc.state))[#doc.state]
        #html.elem("h2", attrs: (class: "shd-card-title"))[SHD #doc.number: #doc.title]
        #html.elem("p", attrs: (class: "shd-card-desc"))[#doc.summary]
        
        #html.elem("div", attrs: (class: "shd-card-links"))[
          #html.elem("a", attrs: (href: doc.html))[HTML View]
          #html.elem("a", attrs: (href: doc.pdf))[PDF View]
        ]
        
        #html.elem("div", attrs: (class: "shd-card-meta"))[
          #html.elem("span")[*Area:* #doc.area]
          #html.elem("span")[*Category:* #doc.category]
          #html.elem("span")[*Status:* #doc.status]
          #html.elem("span")[*Created:* #doc.created]
          #html.elem("span")[*Updated:* #doc.updated]
          #html.elem("span")[*Source:* `#doc.source`]
        ]
      ]
    ]
  ]
]
