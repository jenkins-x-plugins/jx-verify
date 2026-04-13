

# jx verify

This chart verifies pods start and deletes any that fail to pull images.

## Installing

- Add jx3 helm charts repo

```bash
helm repo add jx3 https://storage.googleapis.com/jenkinsxio/charts

helm repo update
```

- Install (or upgrade)

```bash
# This will install jx-verify in the jx namespace (with a jx-verify release name)

# Helm v3
helm upgrade --install jx-verify --namespace jx jx3/jx-verify
```

Look [below](#values) for the list of all available options and their corresponding description.

## Uninstalling

To uninstall the chart, simply delete the release.

```bash
# This will uninstall jx-verify in the jx-verify namespace (assuming a jx-verify release name)

# Helm v3
helm uninstall jx-verify --namespace jx
```

## Version

