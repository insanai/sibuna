#import "style.typ": *
#show: sheet.with(lang: "en")

#sequence(
  ("Sibuna", "Certificate authority"),
  (
    (0, 1, "Order · example.org"),
    (1, 0, "GET /.well-known/acme-challenge/TOKEN"),
    (0, 1, "TOKEN.THUMBPRINT"),
    (1, 0, "Certificate"),
  ),
)
