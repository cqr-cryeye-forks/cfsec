package ebs

// ATTENTION!
// This rule was autogenerated!
// Before making changes, consider updating the generator.

// generator-locked
import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/result"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rule"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{

		Service:   "ebs",
		ShortCode: "enable-volume-encryption",
		Documentation: rule.RuleDocumentation{

			BadExample: []string{`
resource "aws_ebs_volume" "bad_example" {
  availability_zone = "us-west-2a"
  size              = 40

  tags = {
    Name = "HelloWorld"
  }
  encrypted = false
}
`},
			GoodExample: []string{`
resource "aws_ebs_volume" "good_example" {
  availability_zone = "us-west-2a"
  size              = 40

  tags = {
    Name = "HelloWorld"
  }
  encrypted = true
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"aws_ebs_volume",
		},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, r resource.Resource) {

		},
	})
}
