# trivy-db-to

[![build](https://github.com/k1LoW/trivy-db-to/workflows/build/badge.svg)](https://github.com/k1LoW/trivy-db-to/actions)

`trivy-db-to` is a tool for migrating/converting vulnerability information from [Trivy DB](https://github.com/aquasecurity/trivy-db) to other datasource.

## Usage

``` console
$ trivy-db-to mysql://root:mypass@127.0.0.1:3306/mydb
Fetching and updating Trivy DB ...
19.35 MiB / 19.35 MiB [--------------------------------------------------] 100.00% 2.58 MiB p/s 8s
done
Initializing vulnerability information tables ... done
Updating vulnerability information tables ...
>> Updating table 'vulnerabilities' ...
>> Update table 'vulnerability_advisories' ...
>>> GitHub Security Advisory Composer
>>> GitHub Security Advisory Maven
>>> GitHub Security Advisory Npm
>>> GitHub Security Advisory Nuget
>>> GitHub Security Advisory Pip
>>> GitHub Security Advisory Rubygems
>>> Oracle Linux 5
>>> Oracle Linux 6
>>> Oracle Linux 7
>>> Oracle Linux 8
>>> Photon OS 1.0
>>> Photon OS 2.0
>>> Photon OS 3.0
>>> Red Hat Enterprise Linux 5
>>> Red Hat Enterprise Linux 6
>>> Red Hat Enterprise Linux 7
[...]
>>> ubuntu 17.10
>>> ubuntu 18.04
>>> ubuntu 18.10
>>> ubuntu 19.04
>>> ubuntu 19.10
>>> ubuntu 20.04
done
```

## Support datasource

- MySQL ( [schema](docs/schema/mysql/README.md) )
- PostgreSQL ( [schema](docs/schema/postgres/README.md) )

## Install

**deb:**

Use [dpkg-i-from-url](https://github.com/k1LoW/dpkg-i-from-url)

``` console
$ export TRIVY_DB_TO_VERSION=X.X.X
$ curl -L https://git.io/dpkg-i-from-url | bash -s -- https://github.com/k1LoW/trivy-db-to/releases/download/v$TRIVY_DB_TO_VERSION/trivy-db-to_$TRIVY_DB_TO_VERSION-1_amd64.deb
```

**RPM:**

``` console
$ export TRIVY_DB_TO_VERSION=X.X.X
$ yum install https://github.com/k1LoW/trivy-db-to/releases/download/v$TRIVY_DB_TO_VERSION/trivy-db-to_$TRIVY_DB_TO_VERSION-1_amd64.rpm
```

**homebrew tap:**

```console
$ brew install k1LoW/tap/trivy-db-to
```

**manually:**

Download binary from [releases page](https://github.com/k1LoW/trivy-db-to/releases)

**go get:**

```console
$ go get github.com/k1LoW/trivy-db-to
```
