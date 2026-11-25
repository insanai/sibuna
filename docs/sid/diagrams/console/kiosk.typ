#import "wireframe.typ": *
#import "traffic-layout.typ": earth
#set text(font: "Noto Sans")

#wire(170, 95, H => {
  import cetz.draw: *
  panel(H,3,3,164,9,[SIBUNA · edge-eu · Traffic / Attacks · 3/3 reporting · live · last update 1 s],bg:blue-light,size:7pt)
  panel(H,3,15,103,62,[*Live earth globe · Traffic / Attacks*],size:8pt)
  earth((35,H - 49),23)
  panel(H,64,26,40,40,[*Countries* #linebreak() Germany · 2,560 #linebreak() India · 1,920 #linebreak() Brazil · 1,280 #linebreak() Unknown · 4% #linebreak() #linebreak() Samples · p=1/64 #linebreak() Loss: 0 (example)],size:6.5pt)
  panel(H,64,68,40,7,[Rotate / Pause / Reset],size:6pt)
  panel(H,110,15,57,29,[*Last 60 seconds* #linebreak() Requests: 128 k (example) #linebreak() Recorded incidents: 128 #linebreak() Unknown country: 4%],size:7pt)
  panel(H,110,48,57,29,[*Module trends* #linebreak() Inspection / reputation / limits #linebreak() Challenges / bans / honeypot #linebreak() Read-only · no payload detail],size:7pt)
  panel(H,3,81,164,10,[Exit kiosk · session expiry visible · no URL bearer token · stale stream freezes with age; GeoIP unavailable shows outline only],bg:amber-light,size:6pt)
})
