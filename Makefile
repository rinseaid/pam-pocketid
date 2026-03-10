.PHONY: build test clean docker

build:
	CGO_ENABLED=0 go build -o bin/pam-pocketid .

build-all:
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -o bin/pam-pocketid-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -o bin/pam-pocketid-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/pam-pocketid-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/pam-pocketid-darwin-arm64 .

test:
	go test ./... -v

clean:
	rm -rf bin/

docker:
	docker build -t pam-pocketid:latest .
