package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertBasicConstraintsFalse struct {
	// Internal data here
}

func (l *subCertBasicConstraintsFalse) Initialize() error {
	return nil
}

func (l *subCertBasicConstraintsFalse) CheckApplies(c *x509.Certificate) bool {
	// Add conditions for application here
	return util.IsSubscriberCert(c)
}

func (l *subCertBasicConstraintsFalse) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.IsCA == true {
		return ResultStruct{Result: Error}, nil
	} else {
		return ResultStruct{Result: Pass}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_basic_constraints_ca_false",
		Description:   "Subscriber certificates basicConstraints:CA is false",
		Providence:    "CAB: 7.1.2.3",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertBasicConstraintsFalse{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertBasicConstraintsCaFalse = result },
	})
}
