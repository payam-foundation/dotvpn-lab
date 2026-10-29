GO ?= go

.PHONY: test lab lab-docker matrix report lab-clean

# Userspace suites, any OS.
test:
	$(GO) vet ./...
	$(GO) test -race -count=1 -timeout 10m ./...

# Packet-level suites (Linux, root). On a Mac: make lab-docker.
lab:
	$(GO) test -tags lab -race -count=1 -timeout 20m ./suites/...

# Profile x carrier matrix; writes out/matrix.json and out/matrix.md.
matrix:
	$(GO) run ./cmd/lab matrix -out out

# Diff out/matrix.json against profiles/baseline.json.
report:
	$(GO) run ./cmd/lab report -matrix out/matrix.json -baseline profiles/baseline.json

# Same, inside the lab container (Docker Desktop on a Mac).
lab-docker:
	docker/lab.sh $(PKGS)

# Remove leftover lab namespaces and veth links from aborted runs (Linux, root).
lab-clean:
	-@for ns in $$(ip netns list 2>/dev/null | awk '/^dvl[0-9a-f]+-/{print $$1}'); do ip netns del $$ns; done
