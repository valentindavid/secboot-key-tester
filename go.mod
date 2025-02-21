module github.com/valentindavid/analyze-key

go 1.22.2

require (
	github.com/canonical/go-tpm2 v0.0.0-20210827151749-f80ff5afff61
	github.com/snapcore/secboot v0.0.0-20240411101434-f3ad7c92552a
)

require (
	github.com/canonical/go-sp800.108-kdf v0.0.0-20210314145419-a3359f2d21b9 // indirect
	github.com/canonical/go-sp800.90a-drbg v0.0.0-20210314144037-6eeb1040d6c3 // indirect
	github.com/snapcore/go-gettext v0.0.0-20191107141714-82bbea49e785 // indirect
	github.com/snapcore/snapd v0.0.0-20250130080022-644664967920 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	gopkg.in/retry.v1 v1.0.3 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	maze.io/x/crypto v0.0.0-20190131090603-9b94c9afe066 // indirect
)

replace github.com/snapcore/secboot => github.com/valentindavid/secboot v0.0.0-20250221120754-cffef31415c8
