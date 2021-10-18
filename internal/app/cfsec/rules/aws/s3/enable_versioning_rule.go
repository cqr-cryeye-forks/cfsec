package s3

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/s3"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  BadExample:
    Type: AWS::S3::Bucket
`,
		},

		GoodExample: []string{
			`---
AWSTemplateFormatVersion: 2010-09-09
Resources:
  GoodExample:
    Properties:
      VersioningConfiguration:
        Status: Enabled
    Type: AWS::S3::Bucket
`,
		},

		Base: s3.CheckVersioningIsEnabled,
	})
}
