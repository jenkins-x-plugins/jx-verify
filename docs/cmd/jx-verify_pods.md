## jx-verify pods

Verifies that all pods start OK in the current namespace; killing any Pods which have ErrImagePull

***Aliases**: pod*

### Usage

```
jx-verify pods
```

### Synopsis

Verifies that all pods start OK in the current namespace; killing any Pods which have ErrImagePul

### Examples

  # populate the pods don't have missing images
  jx verify pods%!(EXTRA string=jx-verify)

### Options

```
  -c, --count int          The minimum Ready pod count required matching the selector before terminating (default 2)
  -h, --help               help for pods
  -n, --namespace string   The namespace to look for events
  -s, --selector string    The selector to query for all pods being running
```

### SEE ALSO

* [jx-verify](jx-verify.md)	 - commands for verifying Jenkins X environments

###### Auto generated by spf13/cobra on 3-Apr-2022
