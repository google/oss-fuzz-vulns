# OSS-Fuzz vulnerabilities

This is a repo for recording [OSS-Fuzz](https://github.com/google/oss-fuzz)
vulnerabilities, and acts as the source of truth for OSS-Fuzz vulnerabilities in
[OSV].

Users may submit PRs to update any information here.

## Automation

Vulnerabilities undergo automated bisection and repository analysis as part of 
[OSV] to determine the affected commit ranges and versions. They are then
automatically imported in this repository.

Any user changes to vulnerability files in this repository will trigger a
re-analysis by OSV.

[OSV]: https://github.com/google/osv
