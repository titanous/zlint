package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertLocalityNameMustAppear struct {
	// Internal data here
}

func (l *subCertLocalityNameMustAppear) Initialize() error {
	return nil
}

func (l *subCertLocalityNameMustAppear) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c)
}

func (l *subCertLocalityNameMustAppear) RunTest(c *x509.Certificate) (ResultStruct, error) {
	//If all fields are absent
	if c.Subject.GivenName == "" && len(c.Subject.Organization) == 0 && c.Subject.Surname == "" {
		if len(c.Subject.StreetAddress) > 0 {
			return ResultStruct{Result: Error}, nil
		} else {
			return ResultStruct{Result: Pass}, nil
		}
	}
	return ResultStruct{Result: NA}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_street_address_should_not_exist",
		Description:   "Subscriber Certificate: subject:streetAddress MUST NOT appear if subject:organizationName, subject:givenName, and subject:surname fields are absent.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertStreetAddressShouldNotExist{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertStreetAddressShouldNotExist = result },
	})
}

