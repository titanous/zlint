// lint_subject_locality_name_max_length_test.go
package lints

import (
	"testing"
)

func TestSubjectLocalityNameLengthGood(t *testing.T) {
	inputPath := "../testlint/testCerts/subjectLocalityNameLengthGood.pem"
	desEnum := Pass
	out, _ := Lints["e_subject_locality_name_max_length"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}

func TestSubjectLocalityNameLong(t *testing.T) {
	inputPath := "../testlint/testCerts/subjectLocalityNameLong.pem"
	desEnum := Error
	out, _ := Lints["e_subject_locality_name_max_length"].ExecuteTest(ReadCertificate(inputPath))
	if out.Result != desEnum {
		t.Error(
			"For", inputPath, /* input path*/
			"expected", desEnum, /* The enum you expected */
			"got", out.Result, /* Actual Result */
		)
	}
}
