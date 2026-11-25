#import "style.typ": *
#show: sheet.with(lang: "en")

#sequence(
  ("Client", "Sibuna", "Certificate authority"),
  (
    (0, 1, "ClientHello"),
    (1, 2, "Guard permits order"),
    (2, 1, "Validate name"),
    (2, 1, "Certificate"),
    (1, 0, "Resume TLS"),
  ),
)
