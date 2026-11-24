# World map (Natural Earth)

`worldmap.bin` is the world map of SnitchBox’s trace route window. It is generated from
**Natural Earth 1:50m Admin 0 – Countries** (`ne_50m_admin_0_countries.geojson` from
[github.com/nvkelso/natural-earth-vector](https://github.com/nvkelso/natural-earth-vector), folder `geojson/`) by
[`scripts/make_worldmap.py`](../../scripts/make_worldmap.py):

```
python -I scripts/make_worldmap.py ne_50m_admin_0_countries.geojson
```

The script simplifies the outlines (Douglas-Peucker, 0.02°), rounds them to 0.01°, leaves out Antarctica, merges parts with the
same ISO code, keeps the country names in the 12 languages of SnitchBox and adds 13 small territories that the country table of
DB-IP knows but Natural Earth does not draw separately (Gibraltar, Réunion, …) as points. Result: 252 countries and territories,
about 49,000 points, 114 KB compressed (raw Deflate).

**License:** Natural Earth data is in the public domain (“Made with Natural Earth. Free vector and raster map data
@ naturalearthdata.com”, see [naturalearthdata.com/about/terms-of-use](https://www.naturalearthdata.com/about/terms-of-use/)).
Country borders and names are those of Natural Earth and do not express an opinion of SnitchBox on disputed territories.

The country table for IP addresses is **not** part of the program: SnitchBox downloads DB-IP’s
“IP to Country Lite” (CC BY 4.0, [db-ip.com](https://db-ip.com)) only when the user turns on the map and agrees.
