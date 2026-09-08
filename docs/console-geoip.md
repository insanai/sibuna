# Loading country data from the command line

Start Sibuna with storage and its opt-in console, then finish administrator bootstrap and
password setup. The CLI prompts for the password without putting it in shell history:

```sh
python3 tools/console_geoip.py --origin http://127.0.0.1:19446 \
    --username admin --month 2026-09
```

The port must match your `--console` listener. Omit `--month` to use the current month.
Add `--totp` to prompt for an authenticator or recovery code. Use `--status` to inspect
the active generation without importing. Remote consoles require HTTPS with a valid
certificate; HTTP is restricted to literal loopback addresses.

The command authenticates to the running console, requests its fixed DB-IP HTTPS download,
and waits for durable storage and local activation. It never opens the database directly.
Downloads and imports remain bounded by the daemon's existing limits. An invalid download
retains the previous generation. Interrupting the CLI or reaching `--timeout` stops polling;
it does not cancel a submitted import. The CLI signs out its own session when it exits.
Repeating the command for the active month succeeds without importing it again. A supplied
checksum must match that active generation.

Use `--checksum` with an independently obtained SHA-256 of the published **compressed
`.csv.gz` file** to require a particular download. No checksum is required for the normal
certificate-validated HTTPS download. The resulting digest is printed with the active
revision, source month and range count.

The free [DB-IP IP to Country Lite](https://db-ip.com/db/lite.php) dataset requires
CC BY 4.0 attribution, which the console displays. Country mapping is approximate.
Local/private addresses remain Unknown when absent from the dataset. The globe uses sampled
requests from a rolling 60-second window, so loading the database does not invent traffic
or retroactively locate old samples. Send requests through the firewall to see live countries.

The September 2026 dataset was loaded into the development review instance with 717,152
known-country ranges and compressed SHA-256
`a32bb3c384bd3de60ad9024596aa5b395a6dd5beaa27a7223407cc2edc681d0b`.
Dataset files and the populated development database are not committed to Git.
