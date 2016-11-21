package identityHasher

import "testing"

var benchmarkGenerateAndValidateHashResult bool

func BenchmarkGenerateAndValidateHash(benchmark *testing.B) {
	for benchmarkIteration := 0; benchmarkIteration < benchmark.N; benchmarkIteration++ {
		password := getRandomString()

		hashed, err := Hash(password)
		if err != nil {
			panic(err)
		}

		BenchmarkGenerateAndValidateHashResult, err = ValidateHash(password, hashed)
		if err != nil {
			panic(err)
		}
	}
}

func getRandomString() string {
	bytes, err := getRandomBytes(32)
	if err != nil {
		panic(err)
	}

	return string(bytes[:])
}
