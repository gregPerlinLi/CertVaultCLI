.PHONY: build install clean

BINARY=cv
MODULE=github.com/gregPerlinLi/CertVaultCLI

build:
	go build -o $(BINARY) .

install:
	go install .

clean:
	rm -f $(BINARY)
