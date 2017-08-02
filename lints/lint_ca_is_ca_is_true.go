package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type CAIsCaIsTrue struct {
	// Internal data here
}

func (l *CAIsCaIsTrue) Initialize() error {
	return nil
}

func (l *CAIsCaIsTrue) CheckApplies(c *x509.Certificate) bool {
	return util.IsRootCA(c) || util.IsSubCA(c)
}

func (l *CAIsCaIsTrue) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.IsCA {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Error}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_ca_is_ca_is_true",
		Description:   "The CA field must be set to true.",
		Providence:    "CAB: 7.1.2.1",
		EffectiveDate: util.RFC2459Date,
		Test:          &CAIsCaIsTrue{},
		updateReport: func(report *LintReport, result ResultStruct) {
			report.ECaIsCaIsTrue = result
		},
	})
}

