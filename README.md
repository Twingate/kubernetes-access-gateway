# Twingate Kubernetes Access Gateway

## Prerequisites

- Kubernetes cluster (1.16+)
- Twingate account setup with a `Remote Network` for the Kubernetes cluster and
 connectors deployed (see the [Twingate Kubernetes Operator](https://github.com/Twingate/kubernetes-operator) or [the Helm chart](https://github.com/Twingate/helm-charts)
 if required)

## Installation

- Install [helm-unittest](https://github.com/helm-unittest/helm-unittest) plugin for unit-testing Helm chart
  ```
  helm plugin install https://github.com/helm-unittest/helm-unittest.git
  ```

## Testing

### Helm testing

- Run `make test-helm` to test changes in Helm chart
- If the test snapshot changes are expected, run `test-helm-and-update-snapshots` to update the snapshots.

### Debugging

You can debug the Gateway locally using Minikube or other Kubernetes environments. The following guide assumes you already have a connector and a gateway deployed in your cluster.

#### Debugging with Minikube

1. **Point Docker to Minikube's Docker Daemon**

   This allows you to build images directly in the Minikube environment:

   ```sh
   eval $(minikube docker-env)
   ```

2. **Build the Debug Image**

   Build a debug-enabled image using the provided Makefile target:

   ```sh
   make build-local IMAGE_NAME=k8s-access-gateway
   ```

3. **Update the Gateway Deployment**

   Upgrade (or install) the gateway deployment to use your local debug image and enable diagnostic mode (Delve debugger):

   ```sh
   helm upgrade <release-name> ./deploy/gateway/ --install -f <values.yaml> \
     --set image.repository="k8s-access-gateway" \
     --set diagnosticMode.enabled=true
   ```

   > **Note:** Replace `<release-name>` and `<values.yaml>` with your actual release name and values file.

4. **Port Forward to the Debugger**

   Forward port 2345 from the gateway pod to your local machine:

   ```sh
   kubectl port-forward pod/<gateway-pod> 2345:2345
   ```

5. **Connect Your Debugger**

   Use your Go debugger (e.g., GoLand, VS Code, or Delve CLI) to connect to `127.0.0.1:2345`.

---

**What Happens When Diagnostic Mode Is Enabled?**

- The gateway container will start with the Delve debugger in headless mode, listening on port 2345.
- You can set breakpoints and debug the Go process remotely.

---

**Troubleshooting**

- If you have trouble connecting, ensure the pod is running and port 2345 is not already in use locally.
- If you see connection errors, double-check that diagnostic mode is enabled and the correct image is deployed.

## Releasing

We use tags to release. `Makefile` has shortcut commands to release development or production releases.
Semantic Release is used to determine the version (see `go tool svu next`).

- `make cut-release`        - release a dev release (ex: `v0.2.1-dev+7a5384c`)
- `make cut-release-prod`   - release a production release (ex: `v0.2.2`)

## Support

- For general issues using this gateway please open a GitHub issue.
- For account specific issues, please visit the [Twingate forum](https://forum.twingate.com/)
 or open a [support ticket](https://help.twingate.com/)
