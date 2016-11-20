package identityHasher

import "testing"

func BenchmarkGenerateAndValidateHash(benchmark *testing.B) {
	for benchmarkIteration := 0; benchmarkIteration < benchmark.N; benchmarkIteration++ {
		password := getRandomString()

		hashed, err := Hash(password)
		if err != nil {
			panic(err)
		}

		_, err = ValidateHash(password, hashed)
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
