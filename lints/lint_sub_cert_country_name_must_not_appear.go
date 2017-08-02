package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertCountryNameMustNotAppear struct {
	// Internal data here
}

func (l *subCertCountryNameMustNotAppear) Initialize() error {
	return nil
}

func (l *subCertCountryNameMustNotAppear) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c)
}

func (l *subCertCountryNameMustNotAppear) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.Subject.GivenName == "" && len(c.Subject.Organization) == 0 && c.Subject.Surname == "" {
		if len(c.Subject.Country) == 0 {
			return ResultStruct{Result: Pass}, nil
		} else {
			return ResultStruct{Result: Error}, nil
		}
	}
	return ResultStruct{Result: NA}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_country_name_must_not_appear",
		Description:   "Subscriber Certificate: subject:countryName MUST NOT appear if the subject:organizationName field, subject:givenName field, and subject:surname fields are absent.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertCountryNameMustNotAppear{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertCountryNameMustNotAppear = result },
	})
}



