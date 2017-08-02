package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertCountryNameMustAppear struct {
	// Internal data here
}

func (l *subCertCountryNameMustAppear) Initialize() error {
	return nil
}

func (l *subCertCountryNameMustAppear) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c)
}

func (l *subCertCountryNameMustAppear) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.Subject.GivenName != "" || len(c.Subject.Organization) > 0 || c.Subject.Surname != "" {
		if len(c.Subject.Country) == 0 {
			return ResultStruct{Result: Error}, nil
		} else {
			return ResultStruct{Result: Pass}, nil
		}
	}
	return ResultStruct{Result: NA}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_country_name_must_appear",
		Description:   "Subscriber Certificate: subject:countryName MUST appear if the subject:organizationName field, subject:givenName field, or subject:surname fields are present.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertCountryNameMustAppear{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertCountryNameMustAppear = result },
	})
}
