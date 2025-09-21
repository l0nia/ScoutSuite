<p align="center">
  <img src="https://user-images.githubusercontent.com/4206926/49877604-10457580-fe26-11e8-92d7-cd876c4f6454.png" width=350/>
</p>

#

[![Workflow](https://github.com/nccgroup/ScoutSuite/workflows/CI%20Workflow/badge.svg)](https://github.com/nccgroup/ScoutSuite/actions)
[![CodeCov](https://codecov.io/gh/nccgroup/ScoutSuite/branch/master/graph/badge.svg)](https://codecov.io/gh/nccgroup/ScoutSuite)

[![PyPI version](https://badge.fury.io/py/ScoutSuite.svg)](https://badge.fury.io/py/ScoutSuite)
[![PyPI downloads](https://img.shields.io/pypi/dm/scoutsuite)](https://img.shields.io/pypi/dm/scoutsuite)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-rossja%2Fncc--scoutsuite-blue)](https://hub.docker.com/r/rossja/ncc-scoutsuite/)
[![Docker Pulls](https://img.shields.io/docker/pulls/rossja/ncc-scoutsuite.svg?style=flat-square)](https://hub.docker.com/r/rossja/ncc-scoutsuite/)

## Description

Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments. Using the APIs exposed by cloud providers, Scout Suite gathers configuration data for manual inspection and highlights risk areas. Rather than going through dozens of pages on the web consoles, Scout Suite presents a clear view of the attack surface automatically.

Scout Suite was designed by security consultants/auditors. It is meant to provide a point-in-time security-oriented view of the cloud account it was run in. Once the data has been gathered, all usage may be performed offline.

The project team can be contacted at <scoutsuite@nccgroup.com>.

### Cloud Provider Support

The following cloud providers are currently supported:

- Amazon Web Services
- Microsoft Azure
- Google Cloud Platform
- Alibaba Cloud (alpha)
- Oracle Cloud Infrastructure (alpha)
- Kubernetes clusters on a cloud provider (alpha)
- DigitalOcean Cloud (alpha)


## Modules

This version of ScoutSuite contains a module to run checks on GCP service perimeters and access levels.

```
python scout.py gcp --services accesscontextmanager
```


## Installation

Refer to the [wiki](https://github.com/nccgroup/ScoutSuite/wiki/Setup).


