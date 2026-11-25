#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 100, H => {
  import cetz.draw: *
  shell(H,170,"Challenges")
  content((29,H - 13),anchor:"west",text(size:8pt,weight:"bold")[Challenges · all nodes · last hour])
  panel(H,28,19,65,63,[*Challenge flow · window totals*],size:7pt)
  for (i,r) in (("Issued · 8,200",57,blue-light),("Submitted · 7,900",54,amber-light),("Accepted · 7,750",52,green-light),("Rejected 120 · malformed 30",48,rgb("fef2f2"))).enumerate() {
    let x=32+(57-r.at(1))/2
    panel(H,x,29+i*12,r.at(1),9,[#r.at(0)],bg:r.at(2),size:7pt)
  }
  panel(H,97,19,71,63,[*Accepted solve time · client reported* #linebreak() Hashcash ▾ · difficulty 16 ▾],size:7pt)
  for (i,n) in (1,2,3,6,10,15,22,29,34,25,18,11,7,4,2,1).enumerate() {
    rect((101+i*3.8,H - 70),(103.5+i*3.8,H - 70+n*0.8),stroke:none,fill:blue)
  }
  content((101,H - 75),anchor:"west",text(size:5pt,fill:gray)[0–1 ms · logarithmic powers of two · ≥16,384 ms])
  panel(H,28,86,140,11,[Timing missing 4% · invalid 0.1% · client-reported values are untrusted. Issued and submitted can refer to different time-window cohorts.],bg:blue-light,size:6pt)
})
