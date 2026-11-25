# YueLink first-use DNS data

YueLink uses these five groups only for an app-generated DNS policy that names the standard Yue.to GEO mirror. Its normal country and domain matchers consume the original protobuf entries, including full domains, suffixes, patterns and attributes. Other categories, custom sources and ordinary routing rules use the existing loader. Each group has a separate filename. None is installed as a complete GeoIP.dat or GeoSite.dat.

The source release is [MetaCubeX/meta-rules-dat at b2a83b825e81e3cd24f5e3099134f003734dacab](https://github.com/MetaCubeX/meta-rules-dat/tree/b2a83b825e81e3cd24f5e3099134f003734dacab). The download filenames are geosite.dat and geoip.dat. The generator checks both full SHA-256 values before writing any output. Run from the fork root with the Go toolchain used for release.

```sh
go run ./scripts/dnsseed /path/to/geosite.dat /path/to/geoip.dat component/geodata/dnsseed
```

The GeoSite groups are CN, PRIVATE, GEOLOCATION-!CN and GFW. The GeoIP group is CN. The extractor serializes each group's original protobuf fields deterministically, then gzip-compresses it without a timestamp. Check the generated files into the same reviewed revision as the input digests. Updating this snapshot also requires advancing the client's seed publication date for its normal seven-day background freshness check.

[The upstream recipe](https://github.com/MetaCubeX/meta-rules-dat/blob/4178770badecb1b349fbcd62c737e0d7a2079729/.github/workflows/run.yml) records the sources of the country, overseas and private lists. The source repositories, distribution notices and license texts accompany the seed in NOTICE.txt. The files are data extracts, and the attribution and redistribution terms of their original contributors continue to apply.
