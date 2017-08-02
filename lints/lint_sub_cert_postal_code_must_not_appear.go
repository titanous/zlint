package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertPostalCodeMustNotAppear struct {
	// Internal data here
}

func (l *subCertPostalCodeMustNotAppear) Initialize() error {
	return nil
}

func (l *subCertPostalCodeMustNotAppear) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c)
}

func (l *subCertPostalCodeMustNotAppear) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.Subject.GivenName == "" && len(c.Subject.Organization) == 0 && c.Subject.Surname == "" {
		if len(c.Subject.PostalCode) > 0 {
			return ResultStruct{Result: Error}, nil
		} else{
			return ResultStruct{Result: Pass}, nil
		}
	}
	return ResultStruct{Result: NA}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_postal_code_must_not_appear",
		Description:   "Subscriber Certificate: subject:postalCode MUST NOT appear if the subject:organizationName field, subject:givenName field, or subject:surname fields are absent.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertPostalCodeMustNotAppear{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertPostalCodeMustNotAppear = result },
	})
}

