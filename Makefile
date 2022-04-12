
all:	compile vet test

compile:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

clean:
	$(RM) -r build

.PHONY:	compile vet test clean
