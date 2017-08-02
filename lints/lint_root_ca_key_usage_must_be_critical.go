package lints

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/util"
)

type rootCAKeyUsageMustBeCritical struct {
	// Internal data here
}

func (l *rootCAKeyUsageMustBeCritical) Initialize() error {
	return nil
}

func (l *rootCAKeyUsageMustBeCritical) CheckApplies(c *x509.Certificate) bool {
	// Add conditions for application here
	return util.IsRootCA(c)
}

func (l *rootCAKeyUsageMustBeCritical) RunTest(c *x509.Certificate) (ResultStruct, error) {
	keyUsageExtension := util.GetExtFromCert(c, util.KeyUsageOID)
	if keyUsageExtension.Critical {
		return ResultStruct{Result: Pass}, nil
	} else {
		return ResultStruct{Result: Error}, nil
	}
}

func init() {
	RegisterLint(&Lint{
		Name:          "e_root_ca_key_usage_must_be_critical",
		Description:   "Root CA certificates MUST have Key Usage Extension marked critical",
		Providence:    "CAB: 7.1.2.1",
		EffectiveDate: util.RFC2459Date,
		Test:          &rootCAKeyUsageMustBeCritical{},
		updateReport:  func(report *LintReport, result ResultStruct) { report.ERootCaKeyUsageMustBeCritical = result },
	})
}

