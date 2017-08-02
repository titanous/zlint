package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertProvinceMustNotAppear struct {
	// Internal data here
}

func (l *subCertProvinceMustNotAppear) Initialize() error {
	return nil
}

func (l *subCertProvinceMustNotAppear) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c)
}

func (l *subCertProvinceMustNotAppear) RunTest(c *x509.Certificate) (ResultStruct, error) {
	if c.Subject.GivenName == "" && len(c.Subject.Organization) == 0 && c.Subject.Surname == "" {
		if len(c.Subject.Province) > 0 {
			return ResultStruct{Result: Error}, nil
		} else{
			return ResultStruct{Result: Pass}, nil
		}
	}
	return ResultStruct{Result: NA}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_province_must_not_appear",
		Description:   "Subscriber Certificate: subject:stateOrProvinceName MUST NOT appeear if the subject:organizationName, subject:givenName, and subject:surname fields are absent.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertProvinceMustNotAppear{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertProvinceMustNotAppear = result },
	})
}
