// Reusable post-login wireframe; all traffic values and geography are illustrative.
#import "@preview/cetz:0.5.2" as cetz

#let earth(center, R) = {
  import cetz.draw: *
  let blue = rgb("0284c7")
  let red = rgb("bc3d45")
  let cx=center.at(0)
  let cy=center.at(1)
  circle((cx,cy),radius:R,fill:rgb("edf7fc"),stroke:0.6pt+rgb("7cb5d0"))
  // Orthographic projection centered on Africa/Europe. Coastlines simplified for wireframe.
  let project(lon,lat) = {
    let d=(lon - 10)*1deg
    let p=lat*1deg
    let p0=12deg
    (cx+R*calc.cos(p)*calc.sin(d),cy+R*(calc.cos(p0)*calc.sin(p)-calc.sin(p0)*calc.cos(p)*calc.cos(d)),calc.sin(p0)*calc.sin(p)+calc.cos(p0)*calc.cos(p)*calc.cos(d))
  }
  for lon in range(-60,91,step:30) {
    let pts=()
    for lat in range(-85,86,step:3) {
      let p=project(lon,lat)
      if p.at(2)>=0 {pts.push((p.at(0),p.at(1)))}
    }
    if pts.len()>1 {line(..pts,stroke:0.25pt+rgb("c7dfea"))}
  }
  for lat in (-60,-30,0,30,60) {
    let pts=()
    for lon in range(-79,100,step:3) {
      let p=project(lon,lat)
      if p.at(2)>=0 {pts.push((p.at(0),p.at(1)))}
    }
    if pts.len()>1 {line(..pts,stroke:0.25pt+rgb("c7dfea"))}
  }
  let land=(
    ((-17,15),(-17,28),(-6,36),(10,37),(25,32),(33,31),(35,22),(43,12),(51,11),(44,2),(40,-11),(34,-20),(29,-34),(18,-35),(12,-18),(9,-1),(1,5),(-9,5)),
    ((-10,36),(-9,43),(-1,46),(-5,50),(8,55),(6,62),(20,71),(31,70),(28,60),(42,57),(55,60),(69,71),(85,68),(89,53),(82,38),(68,25),(52,15),(43,12),(35,30),(26,36),(20,40),(15,38),(12,44),(3,43)),
    ((-9,50),(-6,58),(-3,59),(1,52)),
    ((-72,12),(-60,9),(-51,4),(-35,-6),(-40,-20),(-52,-33),(-67,-54),(-73,-42),(-75,-20),(-80,-4)),
    ((46,-13),(50,-16),(48,-25),(44,-25)),
  )
  for coast in land {
    let pts=()
    for ll in coast {let p=project(ll.at(0),ll.at(1)); if p.at(2)>=0 {pts.push((p.at(0),p.at(1)))}}
    if pts.len()>2 {line(..pts,close:true,fill:rgb("bbdccc"),stroke:0.35pt+rgb("83b49c"))}
  }
  for item in ((2,47,1.4), (10,51,1.9), (-3,55,1.2), (8,9,1.0), (25,-29,0.9), (-51,-10,1.5), (77,22,1.7)) {
    let p=project(item.at(0),item.at(1))
    if p.at(2)>=0 {circle((p.at(0),p.at(1)),radius:item.at(2),fill:if item.at(0)==10 or item.at(0)==77 {red} else {blue},stroke:0.6pt+white)}
  }
}

#let landing-page() = cetz.canvas(length: 1mm, {
  import cetz.draw: *
  let H = 178
  let navy = rgb("102b46")
  let muted = rgb("607589")
  let line-color = rgb("dce6ee")
  let blue = rgb("0284c7")
  let green = rgb("16845b")
  let amber = rgb("b87511")
  let red = rgb("bc3d45")
  let label(x, y, body, size: 7pt, color: navy, weight: "regular", anchor: "west") = content((x, H - y), anchor: anchor, text(font: "Arial", size: size, fill: color, weight: weight)[#body])
  let box(x,y,w,h,fill:white,stroke:line-color,radius:2) = rect((x,H - y - h),(x+w,H - y),fill:fill,stroke:0.4pt+stroke,radius:radius)
  let button(x,y,w,body,active:false) = {
    box(x,y,w,6,fill:if active {rgb("e5f3fc")} else {white})
    label(x+w/2,y+3,body,size:6pt,color:if active {blue} else {muted},anchor:"center")
  }
  rect((0,0),(268,H),fill:rgb("f4f7fa"),stroke:0.5pt+line-color)
  rect((0,0),(36,H),fill:navy,stroke:none)
  label(5,9,[SIBUNA],size:13pt,weight:"bold",color:white)
  label(5,16,[CONSOLE],size:6pt,color:rgb("a8c5dd"))
  for (i,name) in ("Statistics", "Attack events", "Challenges", "Policy", "Nodes", "GeoIP", "Settings", "Audit").enumerate() {
    let y=29+i*10
    if i==0 {box(3,y - 4,30,8,fill:rgb("254c6b"),stroke:rgb("254c6b"))}
    label(7,y,name,size:7.5pt,color:if i==0 {white} else {rgb("bdd0df")},weight:if i==0 {"bold"} else {"regular"})
  }
  label(5,154,[node 1 · Edge],size:6pt,color:rgb("bdd0df"))
  label(5,161,[v0.1.0 · proposed UI],size:5.5pt,color:rgb("bdd0df"))
  label(5,169,[Operator guide ↗],size:6pt,color:rgb("bdd0df"))
  rect((36,H - 17),(268,H),fill:white,stroke:0.4pt+line-color)
  label(42,8,[edge-eu / All nodes / Statistics / Traffic],size:7pt)
  label(42,13,[3 of 3 nodes reporting · last update 1 s ago],size:5.8pt,color:muted)
  button(201,5,22,[Light / Dark])
  button(227,5,35,[admin ▾ · Sign out])
  label(42,26,[Traffic overview],size:14pt,weight:"bold")
  label(42,33,[External requests · UTC · illustrative data after successful login],size:6pt,color:muted)
  button(186,23,24,[All nodes ▾])
  button(213,23,23,[Last 24 h ▾])
  button(239,23,23,[● Live],active:true)
  button(42,37,24,[Traffic],active:true)
  button(68,37,24,[Security])
  button(239,37,23,[Kiosk ↗])
  let cards=(("1.28 M","Requests · 24 h","↑ 8.2% vs prior day",blue),("1.19 M","Admitted","↑ 7.1% vs prior day",green),("64 k","Challenged","↑ 3.4% vs prior day",amber),("21 k","Denied","↓ 2.1% vs prior day",red),("5 k","Banned / rate-limited","Separate outcomes",red),("3 / 3","Reporting nodes","Coverage complete",blue))
  for (i,c) in cards.enumerate() {
    let x=42+i*37
    box(x,47,35,24)
    label(x+3,53,c.at(1),size:6pt,color:muted)
    label(x+3,61,c.at(0),size:12pt,weight:"bold",color:c.at(3))
    label(x+3,67,c.at(2),size:5pt,color:muted)
  }
  // Dominant earth panel with quiet, explicitly sampled geographic signals.
  box(42,75,140,67)
  label(46,81,[Live earth globe],size:9pt,weight:"bold")
  button(126,78,24,[Traffic],active:true)
  button(152,78,25,[Attacks])
  label(46,87,[Last 60 s · GeoIP by DB-IP · countries, not precise locations],size:5.8pt,color:muted)
  earth((77,H - 112),21)
  label(107,95,[Country],size:6pt,color:muted)
  label(176,95,[Est. requests],size:6pt,color:muted,anchor:"east")
  for (i,c) in (("United States","38.4 k",26),("Germany","25.6 k",18),("India","19.2 k",13),("Brazil","12.8 k",9),("Japan","6.4 k",5)).enumerate() {
    let y=101+i*6
    label(107,y,c.at(0),size:6pt)
    label(176,y,c.at(1),size:6pt,anchor:"east")
    rect((107,H - y - 2.2),(107+c.at(2),H - y - 1.5),fill:blue,stroke:none)
  }
  button(47,135,18,[← Rotate])
  button(67,135,18,[Rotate →])
  button(87,135,15,[Reset])
  button(106,135,20,[Flat map])
  button(128,135,18,[Pause])
  label(178,137.5,[Unknown 4%],size:5.5pt,color:muted,anchor:"east")
  box(186,75,76,67)
  label(190,81,[Traffic timeline],size:9pt,weight:"bold")
  label(190,88,[2,140 req/s now · external outcomes],size:6pt,color:muted)
  for (i,t) in ("2 k", "1 k", "0").enumerate() {
    let y=96+i*13
    label(190,y,t,size:5pt,color:muted)
    line((199,H - y),(257,H - y),stroke:0.3pt+line-color)
  }
  for (j,col) in (green,amber,red).enumerate() {
    let pts=()
    for k in range(31) {
      let v=if j==0 {12+6*calc.sin(k*15deg)+3*calc.sin(k*53deg)} else {2+j+1.6*calc.sin(k*18deg+j*40deg)}
      pts.push((199+k*1.93,H - 122+v))
    }
    line(..pts,stroke:0.85pt+col)
  }
  label(199,126,[00:00],size:5pt,color:muted)
  label(257,126,[24:00 UTC],size:5pt,color:muted,anchor:"east")
  label(190,132,[Admitted  ·  Challenged  ·  Denied],size:5.8pt)
  label(190,138,[Banned / rate-limited / other in detail ↗],size:5.3pt,color:muted)
  for (i,c) in (("Origin status (sampled)","2xx  92%     4xx  5%     5xx  3%"),("Popular paths (sampled)","/  42%     /api  31%     /login  12%"),("Client families (sampled)","Chrome  58%     Safari  22%" )).enumerate() {
    let x=42+i*74
    box(x,146,72,19)
    label(x+4,152,c.at(0),size:7pt,weight:"bold")
    label(x+4,160,c.at(1),size:6pt,color:muted)
  }
  label(42,171,[Geo sample p = 1/64 · loss 0 · known country 96% · blue: traffic / red: attacks · table includes hidden hemisphere],size:5.6pt,color:muted)
  label(42,176,[Wireframe only · illustrative traffic and simplified geography · no live console is implemented yet],size:5pt,color:muted)
})
