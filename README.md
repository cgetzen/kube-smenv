### Kube-smenv

Based on [secretsmanagerenv](https://github.com/cgetzen/secretsmanagerenv).

### What it does
kube-smenv allows you to run pods with env vars sourced from AWS secrets manager.

### How it works
kube-smenv is a <1 MB binary that can be written to a configmap and mounted to a pod. The pod can then exec kube-smenv to run the process with the correct env vars.
