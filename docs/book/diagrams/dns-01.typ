#import "style.typ": *
#show: sheet.with(lang: "en")

#sequence(
  ("Sibuna", "DNS provider", "Authoritative DNS", "Certificate authority"),
  (
    (0, 3, "Order · *.example.org"),
    (3, 0, "TOKEN"),
    (0, 1, "Publish TXT"),
    (0, 2, "Check every server"),
    (2, 0, "All return VALUE"),
    (0, 3, "Ready"),
    (3, 2, "TXT?"),
    (2, 3, "VALUE"),
    (3, 0, "Certificate"),
    (0, 1, "Remove TXT"),
  ),
)
