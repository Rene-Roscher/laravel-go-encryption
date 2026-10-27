.PHONY: test race fuzz lint interop tidy

test:
	go test ./...

race:
	go test -race -count=1 ./...

fuzz:
	go test -run '^$$' -fuzz FuzzDecryptString -fuzztime 30s .
	go test -run '^$$' -fuzz FuzzPHPUnmarshal -fuzztime 30s .

lint:
	golangci-lint run

tidy:
	go mod tidy

# Cross-language interop (needs PHP + composer): proves both directions against the real
# Laravel encrypter.
interop:
	composer install --no-interaction --no-progress
	php scripts/generate_vectors.php
	go test -run 'TestDecryptLaravel|TestLaravel' -v ./...
	go run ./cmd/genvectors | php scripts/verify_go_vectors.php
	go run ./cmd/mutations | php scripts/verify_mutations.php
