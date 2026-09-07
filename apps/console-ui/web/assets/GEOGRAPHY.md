# World boundaries

Source: Natural Earth **5.1.2**, `ne_110m_admin_0_countries.geojson`, from
[the pinned upstream release](https://raw.githubusercontent.com/nvkelso/natural-earth-vector/v5.1.2/geojson/ne_110m_admin_0_countries.geojson).
Source SHA-256: `6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f`.
Natural Earth data is [public domain](https://www.naturalearthdata.com/about/terms-of-use/).
Made with Natural Earth. Boundaries represent the source dataset, not precise client locations.

Reproduce with `python3 tools/console_geometry.py <downloaded-geojson>`.
The converter checks the source digest and bounds every ring and coordinate. The 1:110m
source is already generalized; coordinates are quantized to hundredths of a degree and
consecutive duplicates removed. Rings retain closure and holes. `ISO_A2_EH` supplies country
codes; unavailable codes use `ZZ` and are never assigned traffic counts.

Binary version 2: ASCII `SBG2`, little-endian `u16` center count and ring count, then
the center records (two ASCII country bytes plus signed little-endian `i16` longitude/latitude).
Centers use the publisher’s `LABEL_X`/`LABEL_Y` representative country positions.
Each ring then contains two ASCII
country bytes, little-endian `u16` point count, and signed little-endian `i16` longitude,
latitude pairs in hundredths of a degree. Bounds: 1,024 rings, 16,384 vertices, 128 KiB file.
Geometry is a separate authenticated asset, never part of the authentication Wasm module.
