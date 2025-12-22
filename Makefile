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

export TEST_MYSQL_DSN = mysql://root:mypass@127.0.0.1:33357/trivydb
export TEST_POSTGRES_DSN = pg://postgres:pgpass@127.0.0.1:35432/trivydb?sslmode=disable
export TEST_SQLITE_DSN = sqlite://./trivydb.sqlite3

default: test

ci: depsdev test

test:
	go test ./... -coverprofile=coverage.out -covermode=count

lint:
	golangci-lint run ./...

doc:
	tbls doc -f -c docs/tbls-mysql.yml
	tbls doc -f -c docs/tbls-postgres.yml
	tbls doc -f -c docs/tbls-sqlite.yml

integration_mysql: build
	./trivy-db-to $(TEST_MYSQL_DSN)
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;"
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;" | grep '[0-9]\{5\}'
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;"
	usql $(TEST_MYSQL_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;" | grep '[0-9]\{6\}'

integration_postgres: build
	./trivy-db-to $(TEST_POSTGRES_DSN)
	usql $(TEST_POSTGRES_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;"
	usql $(TEST_POSTGRES_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;" | grep '[0-9]\{5\}'
	usql $(TEST_POSTGRES_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;"
	usql $(TEST_POSTGRES_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;" | grep '[0-9]\{6\}'

integration_sqlite: build
	./trivy-db-to $(TEST_SQLITE_DSN)
	usql $(TEST_SQLITE_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;"
	usql $(TEST_SQLITE_DSN) -c "SELECT COUNT(*) FROM vulnerabilities;" | grep '[0-9]\{5\}'
	usql $(TEST_SQLITE_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;"
	usql $(TEST_SQLITE_DSN) -c "SELECT COUNT(*) FROM vulnerability_advisories;" | grep '[0-9]\{6\}'

integration: integration_mysql integration_postgres integration_sqlite

build:
	go build -ldflags="$(BUILD_LDFLAGS)"

depsdev:
	go install github.com/Songmu/gocredits/cmd/gocredits@latest
	go install github.com/xo/usql@latest
	go install github.com/k1LoW/tbls@latest

prerelease:
	git pull origin --tag
	ghch -w -N ${VER}
	gocredits -w .
	git add CHANGELOG.md CREDITS
	git commit -m'Bump up version number'
	git tag ${VER}

prerelease_for_tagpr:
	gocredits -w .
	git add CHANGELOG.md CREDITS go.mod go.sum

release:
	git push origin main --tag
	goreleaser --clean

.PHONY: default test
