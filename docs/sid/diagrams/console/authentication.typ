#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 98, H => {
  import cetz.draw: *
  content((85,H - 8),text(size:10pt,weight:"bold",fill:blue)[SIBUNA · Sign in])
  panel(H,8,17,48,66,[*1 · Credentials* #linebreak() #linebreak() Username #linebreak() [────────] #linebreak() Password #linebreak() [••••••••••••••••] #linebreak() #linebreak() [Sign in] #linebreak() #linebreak() Invalid credentials: retry #linebreak() Rate limited: retry after Ns],size:7pt)
  panel(H,61,17,48,66,[*2 · Required verification* #linebreak() #linebreak() Authenticator code #linebreak() [────────] #linebreak() [Verify] #linebreak() #linebreak() Use recovery code #linebreak() #linebreak() First login: change temporary password; enroll TOTP when required.],size:7pt)
  panel(H,114,17,48,66,[*3 · Success / expiry* #linebreak() #linebreak() Success → Traffic overview #linebreak() Load globe + open streams #linebreak() #linebreak() Expired → Sign in again #linebreak() Preserve safe return route #linebreak() #linebreak() No users? Run init-admin locally; no public account creation.],size:7pt)
  panel(H,8,87,154,8,[Authentication only: no globe assets, telemetry connection, country data, cluster health or traffic on the sign-in page.],bg:blue-light,size:6pt)
})
