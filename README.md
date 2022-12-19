# OSS-Fuzz vulnerabilities

This is a repo for recording disclosed [OSS-Fuzz](https://github.com/google/oss-fuzz)
vulnerabilities, and acts as the source of truth for OSS-Fuzz vulnerabilities in
[OSV].

Each OSS-Fuzz vulnerability has precise impacted version and commit version
information added by OSV.

Users may submit PRs to update any information here.

## Format spec

The format is described [here](https://ossf.github.io/osv-schema/).

## Automation

Vulnerabilities undergo **automated bisection** and **repository analysis** as part of 
[OSV] to determine the affected commit ranges and versions. They are then
automatically imported in this repository.

Any user changes to vulnerability files in this repository will trigger a
re-analysis by OSV within a few minutes (
[example change](https://github.com/google/oss-fuzz-vulns/commit/8546454f8ad92bee001ca3be5b4c236bcc2df3d5),
[re-analysis](https://github.com/google/oss-fuzz-vulns/commit/5a1e660f6e8ddd3d3db513f976f4987287fc258e)).

OSV will also regularly recompute affected versions and detect cherry picks
across different branches for each vulnerability
([example](https://github.com/google/oss-fuzz-vulns/commit/76395230e992d4de9bae19b39d27dbad16ec389d)).

OSV also provides an [API](https://osv.dev/docs/) to let users easily query this information.

[OSV]: https://github.com/google/osv

## Missing entries

An OSS-Fuzz vulnerability may be missing here for a few reasons.

### The automated bisection failed

Sometimes the bisection is unable to resolve the introduced and fixed
ranges to an acceptably small range. In these cases, we opt to keep the database
higher quality and avoid showing such results by default. 

Failure cases are recorded at the public GCS bucket `gs://oss-fuzz-osv-vulns`.
You may use the script `scripts/import.py` to import any existing details about
these failed vulnerabilities.

```bash
$ python scripts/import.py <oss-fuzz issue ID>
```

Any missing details may be filled in manually and submitted as part of a PR to this repo.
See [this example](https://github.com/google/oss-fuzz-vulns/commit/8546454f8ad92bee001ca3be5b4c236bcc2df3d5).

### The bug was not marked as security by OSS-Fuzz

We only include bugs that are marked as security by OSS-Fuzz. If you are a
project maintainer, you may edit the security flag on the corresponding testcase
details page. Marking a bug as security will automatically cause it to be fed into OSV,
if the bug is reliably reproducible.

## Removing an entry

If a vulnerability in this repository is not considered a security vulnerability,
it may be removed by submitting a PR to add a [`withdrawn`](https://ossf.github.io/osv-schema/#withdrawn-field)
field to the relevant entry. 
