# Twingate Kubernetes Access Gateway

[![CI](https://github.com/Twingate/kubernetes-access-gateway/actions/workflows/ci.yaml/badge.svg?branch=master)](https://github.com/Twingate/kubernetes-access-gateway/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/Twingate/kubernetes-access-gateway/badge.svg?branch=master&t=iFagz6)](https://coveralls.io/github/Twingate/kubernetes-access-gateway?branch=master)
[![Dockerhub](https://img.shields.io/badge/dockerhub-images-info.svg?logo=Docker)](https://hub.docker.com/r/twingate/kubernetes-access-gateway)

> [!IMPORTANT]
> **Twingate Kubernetes Access is currently in beta.** Sign up for early access at https://www.twingate.com/product/kubernetes-access.

Twingate Kubernetes Access enables secure, zero-trust access to your Kubernetes cluster. It provides a seamless integration between Twingate's secure access platform and your Kubernetes infrastructure, allowing you to manage and control access to your cluster through Twingate's security policies.

[Wiki][1]  |  [Quick Started][2]  |  [Installation][3]

[1]: https://github.com/Twingate/kubernetes-access-gateway/wiki
[2]: https://github.com/Twingate/kubernetes-access-gateway/wiki/Quick-Start-Guide
[3]: https://github.com/Twingate/kubernetes-access-gateway/wiki/Installation

## Prerequisites

- Kubernetes cluster (1.31+)
- Twingate account setup with a `Remote Network` for the Kubernetes cluster and
 connectors deployed (see the [Twingate Kubernetes Operator](https://github.com/Twingate/kubernetes-operator) or [the Helm chart](https://github.com/Twingate/helm-charts)
 if required)

## Installation

- See [Quick Started](https://github.com/Twingate/kubernetes-access-gateway/wiki/Quick-Start-Guide) to set up the Gateway from scratch using the Twingate Operator.
- See [Installation](https://github.com/Twingate/kubernetes-access-gateway/wiki/Installation) for different installation options.

## Support

- For general issues using this gateway please open a GitHub issue.
- For account specific issues, please visit the [Twingate forum](https://forum.twingate.com/)
 or open a [support ticket](https://help.twingate.com/)

## Developers

- See [Developer](https://github.com/Twingate/kubernetes-access-gateway/wiki/Developer) for how to set up a development environment and release process.
