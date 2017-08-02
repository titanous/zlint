package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type subCertSubjectGnOrSnContainsPolicy struct {
	// Internal data here
}

func (l *subCertSubjectGnOrSnContainsPolicy) Initialize() error {
	return nil
}

func (l *subCertSubjectGnOrSnContainsPolicy) CheckApplies(c *x509.Certificate) bool {
	//Check if GivenName or Surname fields are filled out
	return util.IsSubscriberCert(c) && (c.Subject.GivenName != "" || c.Subject.Surname != "")
}

func (l *subCertSubjectGnOrSnContainsPolicy) RunTest(c *x509.Certificate) (ResultStruct, error) {
	for _, policyIds := range c.PolicyIdentifiers {
		if policyIds.Equal(util.BRIndividualValidatedOID) {
			return ResultStruct{Result: Pass}, nil
		}
	}
	return ResultStruct{Result: Error}, nil
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_sub_cert_givename_surname_contains_correct_policy_id",
		Description:   "Subscriber Certificate: A certificate containing a subject:givenName field or subject:surname field MUST contain the (2.23.140.1.2.3) certPolicy OID.",
		Providence:    "CAB: 7.1.4.2.2",
		EffectiveDate: util.CABEffectiveDate,
		Test:          &subCertSubjectGnOrSnContainsPolicy{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ESubCertGivenNameSurnameContainsPolicy = result },
	})
}
