PKG = github.com/k1LoW/trivy-db-to
COMMIT = $$(git describe --tags --always)
OSNAME=${shell uname -s}
ifeq ($(OSNAME),Darwin)
	DATE = $$(gdate --utc '+%Y-%m-%d_%H:%M:%S')
else
	DATE = $$(date --utc '+%Y-%m-%d_%H:%M:%S')
endif

export GO111MODULE=on

BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)

TEST_MYSQL_DSN = mysql://root:mypass@127.0.0.1:33357/trivydb

default: test

ci: depsdev test integration sec

test:
	go test ./... -coverprofile=coverage.txt -covermode=count

sec:
	gosec ./...

integration: build
	./trivy-db-to $(TEST_MYSQL_DSN)
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;" | grep '\d\d\d\d\d'
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;" | grep '\d\d\d\d\d\d'

build:
	go build -ldflags="$(BUILD_LDFLAGS)"

depsdev:
	go get github.com/Songmu/ghch/cmd/ghch
	go get github.com/Songmu/gocredits/cmd/gocredits
	go get github.com/securego/gosec/cmd/gosec
	go get github.com/xo/usql

prerelease:
	git pull origin --tag
	ghch -w -N ${VER}
	gocredits . > CREDITS
	git add CHANGELOG.md CREDITS
	git commit -m'Bump up version number'
	git tag ${VER}

release:
	goreleaser --rm-dist

.PHONY: default test
