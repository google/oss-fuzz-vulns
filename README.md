# OSS-Fuzz vulnerabilities

This is a repo for recording disclosed [OSS-Fuzz](https://github.com/google/oss-fuzz)
vulnerabilities, and acts as the source of truth for OSS-Fuzz vulnerabilities in
[OSV].

Each OSS-Fuzz vulnerability has precise impacted version and commit version
information added by OSV.

Users may submit PRs to update any information here.

## Format spec

The format is described [here](https://osv.dev/docs/index.html#tag/vulnerability_schema).

## Automation

Vulnerabilities undergo automated bisection and repository analysis as part of 
[OSV] to determine the affected commit ranges and versions. They are then
automatically imported in this repository.

Any user changes to vulnerability files in this repository will trigger a
[re-analysis by OSV](https://github.com/google/osv/blob/master/docker/importer/importer.py)
within a few minutes.

OSV will also regularly recompute affected versions and detect cherry picks
across different branches for each vulnerability
([example](https://github.com/google/oss-fuzz-vulns/commit/76395230e992d4de9bae19b39d27dbad16ec389d)).

[OSV]: https://github.com/google/osv

## Missing entries

Entries may be missing for a few reasons.

### The automated bisection failed

Sometimes the bisection is unable to resolve the introduced and fixed
ranges to an acceptably small range. In these cases, we opt to keep the database
higher quality and avoid showing such results by default. 

TODO: how to add results back manually.

### The bug was not marked as security by OSS-Fuzz

We only include bugs that are marked as security by OSS-Fuzz. If you are a
project maintainer, you may edit the security flag on the corresponding testcase
details page. Marking a bug as security will automatically cause it to be fed into OSV.

## Removing an entry

If a vulnerability in this repository is not considered a security vulnerability,
it may be removed by submitting a PR.


