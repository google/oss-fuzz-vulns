# OSS-Fuzz vulnerabilities

This is a repo for OSS-Fuzz vulnerabilities, and acts as the source of truth
for OSS-Fuzz vulnerabilities in https://osv.dev.

Users may submit PRs to update any information here.

## Automation

Vulnerabilities undergo automated bisection and repository analysis as part of 
[OSV](https://github.com/google/osv) to determine the affected commit ranges
and versions. They are then automatically imported in this repository.

Any changes to vulnerability files in this repository will trigger a
re-analysis by OSV.
