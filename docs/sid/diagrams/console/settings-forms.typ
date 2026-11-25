#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("Settings", [Settings · Users / Tokens / Pages / Retention / Notifications / About], [Users and API tokens], [
  User: alice · role: operator ▾\
  TOTP: enrolled · last login: 12:00 UTC\
  Disable user / reset password / revoke sessions

  Token label: deploy-ci · role: operator ▾\
  Expiry: date/time · scope: policy only\
  Create → show secret once → copy → close\
  Existing tokens: id / scope / expiry / revoke

  Viewer role: inspect, cannot change settings.\
  Administrator changes require recent auth.

  About: node/version/build/listener/storage\
  Never expose secrets or arbitrary environment.
], [Operational settings], [
  *Templates* · denied ▾ · bounded placeholders\
  Edit / sandboxed preview / reset / save\
  No executable scripts or arbitrary imports

  *Retention* · traffic 90 d · incidents 30 d\
  Rankings 7 d / 512 MiB · audit 365 d\
  Estimate footprint → review → save

  *Notifications* · destination type: webhook ▾\
  URL / masked secret / events / cooldown\
  Test destination → show result → save\
  Node unhealthy / leader change / denial spike\
  Bounded retries; one cluster notifier lease
], [Validation is inline; save has pending/success/error states. Slow notifications never run in data-plane threads.])
