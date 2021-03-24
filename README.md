# OSS-Fuzz vulnerabilities

This is a repo for recording [OSS-Fuzz](https://github.com/google/oss-fuzz)
vulnerabilities, and acts as the source of truth for OSS-Fuzz vulnerabilities in
[OSV].

Each OSS-Fuzz vulnerability has precise impacted version and commit version
information added.

Users may submit PRs to update any information here.

## Automation

Vulnerabilities undergo automated bisection and repository analysis as part of 
[OSV] to determine the affected commit ranges and versions. They are then
automatically imported in this repository.

Any user changes to vulnerability files in this repository will trigger a
[re-analysis by OSV](https://github.com/google/osv/blob/master/docker/importer/importer.py).

[OSV]: https://github.com/google/osv

## Missing entries

Entries may be missing for a few reasons:

### The automated bisection failed

Sometimes the bisection is unable to resolve the introduced and fixed
ranges to an acceptably small range. In these cases, we opt to keep the database
higher quality and avoid showing such results by default. 

TODO: how to add results back manually.

### The bug was not marked as security by OSS-Fuzz

We only include bugs that are marked as security by OSS-Fuzz. If you are a
project maintainer, you may edit the security flag on the corresponding testcase
details page. Marking a bug as security will automatically cause it to be fed into OSV.
Likewise, marking a bug as non-security will cause the entry to be marked as invalid in
OSV.



