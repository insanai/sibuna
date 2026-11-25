#import "style.typ": *
#show: sheet.with(lang: "en")

#sequence(
  ("Replacement", "Old process"),
  (
    (0, 1, "HELLO"),
    (1, 0, "LISTENERS · SCM_RIGHTS"),
    (0, 1, "READY · pause UDP"),
    (1, 0, "FLOWS · COMMIT"),
    (0, 1, "DONE"),
  ),
  notes: ((4, 0, "adopt mappings · accept TCP"), (5, 0, "read UDP"), (5, 1, "drain TCP")),
)
