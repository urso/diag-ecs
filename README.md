# diag-ecs

[Elastic common schema (ECS)](https://github.com/elastic/ecs) field definitions for use with the go diagnatic context library github.com/urso/diag.

The definitions are automatically generated via `mage`.

Print list of environment variables the mage script supports:

```
$ mage info:vars
BUILD_DIR=build  : set build directory to load temporary files into
REPOSITORY=https://github.com/elastic/ecs.git  : URL used to clone the ECS repository
USE_REF=v1.4.0  : set tag or branch name to checkout
VERSION=1.4.0  : set ecs version tag to check out
```

Generate ecs/ecs.go:

```
$ mage clean
$ mage build
```

Update constants in magefile.go to permanently update the ECS version.
