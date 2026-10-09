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

A systemd timer can refresh the dataset out-of-band:

- download to a temp file
- verify a checksum/signature
- atomically `rename()` over `/usr/share/femboi/geoip.dat`
- `systemctl reload femboi-firewall`

See the audit report for the full plan (item 32/39). Until the timer exists,
refresh manually and reload.
