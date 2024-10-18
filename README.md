
# Kubernetes Sanity Check Pod

This repository contains a Kubernetes pod configuration designed for performing basic sanity checks within a Kubernetes cluster. It is useful for troubleshooting, testing connectivity, and verifying that a Kubernetes environment is functioning as expected.

## Features

- **Sanity Check Pod**: Simple pod for performing basic network connectivity and service availability checks.
- **Custom Commands**: Can run custom diagnostic commands within the pod.
- **Minimalistic and Lightweight**: Uses a lightweight container image for fast startup.

## Prerequisites

- **Kubernetes Cluster**: A running Kubernetes cluster.
- **kubectl**: Installed and configured to interact with your Kubernetes cluster.

## Project Structure

```bash
/
├── /sanity-check-pod.yaml                  # Kubernetes Pod YAML configuration
├── /scripts/                               # Optional scripts for testing
├── /Dockerfile                             # Dockerfile to build a custom image (optional)
└── /README.md                              # Project README (this file)
```

## Usage

### 1. Clone the Repository

```bash
git clone https://github.com/vishnuswmech/sanity-check-pod.git
cd sanity-check-pod
```

### 2. Deploy the Sanity Check Pod

Apply the provided Kubernetes pod configuration:

```bash
kubectl apply -f sanity-check-pod.yaml
```

This will deploy a simple pod that you can use to test your Kubernetes environment.

### 3. Verify Pod Status

Ensure the pod is running by checking its status:

```bash
kubectl get pods
```

Once the pod is in a `Running` state, you can execute commands inside the pod.

### 4. Running Commands in the Pod

You can execute commands inside the sanity check pod for diagnostics. For example, to test connectivity to another service:

```bash
kubectl exec -it <pod-name> -- ping google.com
```

You can replace `<pod-name>` with the actual pod name retrieved from the `kubectl get pods` command.

### 5. Deleting the Pod

To clean up and delete the sanity check pod:

```bash
kubectl delete -f sanity-check-pod.yaml
```

## Custom Docker Image (Optional)

The repository includes a `Dockerfile` for creating a custom image for the sanity check pod. You can build and use your own image if needed:

```bash
docker build -t sanity-check:latest .
```

Then, you can modify the `sanity-check-pod.yaml` to use your custom image.
