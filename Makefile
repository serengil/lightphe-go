GO ?= go
PKGS ?= ./...

lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; \
		echo "$$unformatted" | sed 's/^/  /'; \
		echo "run 'make fmt' to fix"; \
		exit 1; \
	fi
	$(GO) vet $(PKGS)

fmt:
	gofmt -l -w .

vet:
	$(GO) vet $(PKGS)

test:
	$(GO) test $(PKGS) -v

test-short:
	$(GO) test $(PKGS) -short

cover:
	$(GO) test -coverprofile=coverage.txt -covermode=atomic $(PKGS)
	$(GO) tool cover -func=coverage.txt

clean:
	$(GO) clean -testcache
	rm -f coverage.txt coverage.html
