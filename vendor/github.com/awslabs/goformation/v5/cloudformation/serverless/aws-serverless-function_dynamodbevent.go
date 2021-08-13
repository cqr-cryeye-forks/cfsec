package serverless

import (
	"github.com/awslabs/goformation/v5/cloudformation/policies"
)

// Function_DynamoDBEvent AWS CloudFormation Resource (AWS::Serverless::Function.DynamoDBEvent)
// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
type Function_DynamoDBEvent struct {

	// BatchSize AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	BatchSize int `json:"BatchSize,omitempty"`

	// BisectBatchOnFunctionError AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	BisectBatchOnFunctionError bool `json:"BisectBatchOnFunctionError,omitempty"`

	// DestinationConfig AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	DestinationConfig *Function_DestinationConfig `json:"DestinationConfig,omitempty"`

	// Enabled AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	Enabled bool `json:"Enabled,omitempty"`

	// MaximumBatchingWindowInSeconds AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	MaximumBatchingWindowInSeconds int `json:"MaximumBatchingWindowInSeconds,omitempty"`

	// MaximumRecordAgeInSeconds AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	MaximumRecordAgeInSeconds int `json:"MaximumRecordAgeInSeconds,omitempty"`

	// MaximumRetryAttempts AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	MaximumRetryAttempts int `json:"MaximumRetryAttempts,omitempty"`

	// ParallelizationFactor AWS CloudFormation Property
	// Required: false
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	ParallelizationFactor int `json:"ParallelizationFactor,omitempty"`

	// StartingPosition AWS CloudFormation Property
	// Required: true
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	StartingPosition string `json:"StartingPosition,omitempty"`

	// Stream AWS CloudFormation Property
	// Required: true
	// See: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#dynamodb
	Stream string `json:"Stream,omitempty"`

	// AWSCloudFormationDeletionPolicy represents a CloudFormation DeletionPolicy
	AWSCloudFormationDeletionPolicy policies.DeletionPolicy `json:"-"`

	// AWSCloudFormationUpdateReplacePolicy represents a CloudFormation UpdateReplacePolicy
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`

	// AWSCloudFormationDependsOn stores the logical ID of the resources to be created before this resource
	AWSCloudFormationDependsOn []string `json:"-"`

	// AWSCloudFormationMetadata stores structured data associated with this resource
	AWSCloudFormationMetadata map[string]interface{} `json:"-"`

	// AWSCloudFormationCondition stores the logical ID of the condition that must be satisfied for this resource to be created
	AWSCloudFormationCondition string `json:"-"`
}

// AWSCloudFormationType returns the AWS CloudFormation resource type
func (r *Function_DynamoDBEvent) AWSCloudFormationType() string {
	return "AWS::Serverless::Function.DynamoDBEvent"
}
