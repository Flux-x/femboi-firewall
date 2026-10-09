# GeoIP data (`geoip.dat`)

The runtime loads a compact binary range table (`GEO1` magic, then a
`uint32 count` and `count` packed `{start_ip, end_ip, cc[2]}` records).
The repository bundles a prebuilt `geoip.dat`.

## Provenance / license — ACTION REQUIRED

`geoip.dat` is a **redistributed third-party dataset**. Before any public
release, the maintainer MUST:

1. Record the upstream source (e.g. MaxMind GeoLite2 or DB-IP Lite) and the
   exact snapshot date used to generate the file.
2. Confirm the license permits redistribution. MaxMind GeoLite2 requires
   attribution and, for many uses, a license key; DB-IP Lite is CC-BY.
3. Add the required attribution to `LICENSE`/`README` and to the Debian
   `debian/copyright` `Files: geoip.dat` stanza (already stubbed).

Until that is done, treat `geoip.dat` as unreviewed for redistribution.

## Regeneration

Provide the source CSV (range,start,end,cc) and run the generator (add a
script here when the pipeline is formalised) to emit `geoip.dat`. The header
comment inside the file should carry the generator version, source and date.

## Updates

The `update.sh` script refreshes the dataset with mandatory integrity checks:

```sh
sudo GEOIP_URL=https://example.org/femboi \
     GEOIP_PUBKEY=/etc/femboi/geoip-signing.pub \
     ./tools/geoip/update.sh
```

- downloads `geoip.dat` over HTTPS
- verifies the `.sha256` sidecar (required; nothing installs on mismatch)
- optionally verifies a detached `.asc` signature with `gpg` when
  `GEOIP_PUBKEY` is set
- atomically replaces the dataset and writes the matching `.sha256`
- reloads the daemon

On startup the daemon itself enforces the same guard: if a
`<geoip>.sha256` sidecar exists next to the dataset, `geodb` refuses to load a
file that does not match it, so a tampered or partially written dataset cannot
silently change which countries are blocked.

### systemd timer

```ini
# /etc/systemd/system/femboi-geoip.service
[Service]
Type=oneshot
Environment=GEOIP_URL=https://example.org/femboi
Environment=GEOIP_PUBKEY=/etc/femboi/geoip-signing.pub
ExecStart=/usr/share/femboi/update.sh

# /etc/systemd/system/femboi-geoip.timer
[Timer]
OnCalendar=weekly
Persistent=true
```

