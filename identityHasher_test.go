package identityHasher

import "testing"

const hash = "AFYJggv7CVVexgMBBNE2SepPqi/SEv1MwqyvWQPs1HXyU1rSltyYcxzbEhLCijWW5w=="
const password = "ololopassword"

func TestValidateHash(test *testing.T) {
	result, err := ValidateHash(password, hash)

	test.Log(result)

	if err != nil {
		test.Error(err)
	}

	if !result {
		test.Fail()
	}
}

func TestGenerateAndValidateHash(test *testing.T) {
	hashed, err := Hash(password)
	test.Log(hashed)

	if err != nil {
		test.Error(err)
	}

	result, err := ValidateHash(password, hashed)

	if err != nil {
		test.Error(err)
	}

	if !result {
		test.Fail()
	}
}
