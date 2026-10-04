#import "theme.typ": blue_light, gray, rule
#import "figures.typ": fmt_int, fmt_ms, fmt_mib, fmt_dec
#import "products.typ": profile_names

#let admission_data(operations: false) = json(if operations {
  "../../benchmarks/results/products-admission-operations-two-host-latest.json"
} else {
  "../../benchmarks/results/products-admission-http-two-host-latest.json"
})

#let admission_meta_line(operations: false) = {
  let d = admission_data(operations: operations)
  assert(d.functional_pass, message: "Admission comparison failed validation")
  text(size: 8pt, fill: gray)[
    Recorded #d.meta.date · server #d.meta.host · generator #d.generator.host ·
    revision #raw(d.meta.git.slice(0, 12)) · Zig #d.meta.zig ·
    #d.anubis.version · BunkerWeb #d.bunkerweb.version ·
    #d.scope.at("proof_bits", default: d.scope.at("verified_proof_bits", default: 16)) proof bits
  ]
}

#let workload_names = (
  "admitted": [Admitted session], "challenged": [No session],
  "allowed_static": [Allowed static path], "attack": [SQLi with session],
  "valid_session": [Session check], "unauthenticated_check": [No session],
  "proof_verification": [Fresh proof], "challenge_bootstrap": [Challenge bootstrap],
)

#let admission_http_table(mode, labels) = {
  let rows = ()
  for run in admission_data().runs {
    if run.mode != mode { continue }
    for label in labels {
      let s = run.workloads.at(label)
      rows.push((profile_names.at(run.profile), workload_names.at(label),
        [#fmt_int(s.requests_per_second_median) #linebreak()
          #text(size: 7pt, fill: gray)[#fmt_int(s.requests_per_second_min)–#fmt_int(s.requests_per_second_max)]],
        fmt_ms(s.p99_us_median), fmt_dec(s.cpu_us_per_request_median),
        fmt_mib(s.peak_process_tree_rss_kib_max)))
    }
  }
  set text(size: 8pt)
  set par(justify: false)
  block(breakable: false, table(columns: (1.15fr, 1.2fr, 1.2fr, 0.6fr, 0.7fr, 0.8fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Profile*], [*Workload*], [*req/s* #linebreak() median; min–max],
      [*p99*], [*CPU* #linebreak() µs/req], [*Peak summed RSS*]), ..rows.flatten()))
}

#let admission_operations_table(labels) = {
  let rows = ()
  for run in admission_data(operations: true).runs {
    let name = profile_names.at(run.profile)
    if run.profile == "anubis" {
      name = [Anubis, #if run.scheme == "hs512" { [HS512] } else { [Ed25519] }]
    }
    for label in labels {
      let s = run.operations.at(label)
      rows.push((name, if run.mode == "forward_auth" { [Forward-auth] } else { [Proxy] },
        workload_names.at(label),
        [#fmt_int(s.operations_per_second_median) #linebreak()
          #text(size: 7pt, fill: gray)[#fmt_int(s.operations_per_second_min)–#fmt_int(s.operations_per_second_max)]],
        if s.cpu_us_per_operation == none { [Unresolved] } else { fmt_dec(s.cpu_us_per_operation) },
        fmt_mib(s.peak_process_tree_rss_kib)))
    }
  }
  set text(size: 8pt)
  set par(justify: false)
  block(breakable: false, table(columns: (1.2fr, 0.85fr, 1.2fr, 1.15fr, 0.7fr, 0.75fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Profile*], [*Mode*], [*Operation*], [*ops/s* #linebreak() median; min–max],
      [*CPU* #linebreak() µs/op], [*Peak summed RSS*]), ..rows.flatten()))
}

#let bootstrap_work_line() = {
  let ranges = ()
  for run in admission_data(operations: true).runs {
    if not run.profile.starts-with("sibuna") { continue }
    let samples = run.operations.challenge_bootstrap.samples
    let low = calc.min(..samples.map(s => s.issued_bits_min))
    let high = calc.max(..samples.map(s => s.issued_bits_max))
    ranges.push([#profile_names.at(run.profile): #low#if low != high { [–#high] } bits])
  }
  text(size: 8pt, fill: gray)[Observed bootstrap issuance: #ranges.join([; ]).]
}
