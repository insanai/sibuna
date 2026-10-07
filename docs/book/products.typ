#import "theme.typ": blue_light, gray, rule
#import "figures.typ": fmt_int, fmt_ms, fmt_mib, fmt_dec

#let proxy_data(loopback: false) = json(if loopback {
  "../../benchmarks/results/bunkerweb-comparison-latest.json"
} else {
  "../../benchmarks/results/products-proxy-two-host-latest.json"
})

#let profile_names = (
  "origin": [Origin directly],
  "sibuna-gate": [Sibuna Gate],
  "anubis-proxy": [Anubis, proxy],
  "anubis": [Anubis],
  "bunkerweb-js": [BunkerWeb, JS],
  "bunkerweb-js-crs": [BunkerWeb, JS + CRS],
  "bunkerweb-proxy": [BunkerWeb, CRS off],
  "sibuna-shield": [Sibuna Shield],
  "bunkerweb-crs": [BunkerWeb, CRS on],
  "bunkerweb-crs-small-error": [BunkerWeb, CRS on, small error page],
)

#let proxy_meta_line(loopback: false) = {
  let data = proxy_data(loopback: loopback)
  let m = data.meta
  text(size: 8pt, fill: gray)[
    Recorded #m.date · server #m.host · #m.cpu ·
    #if not loopback { [generator #data.generator.host · #data.generator.cpu ·] }
    Sibuna revision #raw(m.git.slice(0, 12)) ·
    Zig #m.zig · BunkerWeb #data.bunkerweb.version ·
    #if data.at("anubis", default: none) != none { [#data.anubis.version ·] }
    #data.load.threads load threads, #data.load.connections connections ·
    #data.load.seconds s × #data.load.repetitions rounds, with #data.load.warmup s warmup
  ]
}

#let proxy_table(denied: false, loopback: false) = {
  let data = proxy_data(loopback: loopback)
  assert(data.functional_pass, message: "Proxy comparison failed functional validation")
  let labels = if loopback {
    (("benign_get", [Benign GET]),)
  } else if denied {
    (("sqli_query", [SQL injection (query)]), ("sqli_json", [SQL injection (JSON)]))
  } else {
    (("benign_get", [Benign GET]), ("benign_json_8k", [Benign JSON POST]))
  }
  let rows = ()
  for run in data.runs {
    if denied and run.profile not in (
      "sibuna-shield", "bunkerweb-crs", "bunkerweb-crs-small-error",
    ) { continue }
    for (label, name) in labels {
      let s = run.workloads.at(label)
      rows.push((
        profile_names.at(run.profile), name,
        [#fmt_int(s.requests_per_second_median) #linebreak()
          #text(size: 7pt, fill: gray)[#fmt_int(s.requests_per_second_min)–#fmt_int(s.requests_per_second_max)]],
        fmt_ms(s.p99_us_median), fmt_dec(s.cpu_us_per_request_median),
        fmt_mib(s.peak_process_tree_rss_kib_max),
      ))
    }
  }
  set text(size: 8pt)
  set par(justify: false)
  block(breakable: false, table(
    columns: (1.35fr, 1fr, 1.25fr, 0.65fr, 0.65fr, 0.75fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Profile*], [*Workload*], [*req/s* #linebreak() median; min–max],
      [*p99*], [*CPU* #linebreak() µs/req], [*Peak resident memory*]),
    ..rows.flatten(),
  ))
}
