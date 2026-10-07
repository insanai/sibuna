#import "theme.typ": blue_light, gray, rule
#import "figures.typ": fmt_int, fmt_ms, fmt_mib, fmt_dec

#let crs_data = json("../../benchmarks/results/crs-request-path-two-host-latest.json")

#let crs_profiles = (
  "disabled": [CRS disabled],
  "audit-pl1": [Audit, PL1],
  "enforce-pl1": [Enforce, PL1],
  "audit-pl2": [Audit, PL2],
  "enforce-pl2": [Enforce, PL2],
)

#let crs_workloads = (
  ("small_get", [Small GET]),
  ("json_8k", [8 KiB JSON]),
  ("multipart_16k", [16 KiB multipart]),
  ("sqli_query", [SQL injection (query)]),
)

#let crs_meta_line() = {
  let m = crs_data.meta
  text(size: 8pt, fill: gray)[
    Recorded #m.date · server #m.host · #m.cpu · generator #crs_data.generator.host ·
    #crs_data.generator.cpu · Sibuna revision #raw(m.git.slice(0, 12)) · Zig #m.zig ·
    CRS #crs_data.crs_release · #crs_data.load.workers workers ·
    #crs_data.load.threads load threads, #crs_data.load.connections connections ·
    #crs_data.load.seconds s × #crs_data.load.repetitions rounds, with
    #crs_data.load.warmup s warmup
  ]
}

#let crs_table(profiles) = {
  assert(crs_data.functional_pass, message: "CRS request path failed functional validation")
  let rows = ()
  for run in crs_data.runs {
    if run.profile not in profiles { continue }
    for (label, name) in crs_workloads {
      let s = run.workloads.at(label)
      rows.push((
        crs_profiles.at(run.profile), name,
        [#fmt_int(s.requests_per_second_median) #linebreak()
          #text(size: 7pt, fill: gray)[#fmt_int(s.requests_per_second_min)–#fmt_int(s.requests_per_second_max)]],
        fmt_ms(s.p50_us_median), fmt_ms(s.p99_us_median),
        fmt_dec(s.cpu_us_per_request_median), fmt_mib(s.peak_process_tree_rss_kib_max),
      ))
    }
  }
  set text(size: 8pt)
  set par(justify: false)
  block(breakable: false, table(
    columns: (1.1fr, 1.1fr, 1.25fr, 0.6fr, 0.6fr, 0.7fr, 0.75fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Profile*], [*Workload*], [*req/s* #linebreak() median; min–max],
      [*p50*], [*p99*], [*CPU* #linebreak() µs/req], [*Peak resident memory*]),
    ..rows.flatten(),
  ))
}
