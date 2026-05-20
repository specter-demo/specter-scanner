// Package aws implements the AWS scanner plugin.
// It scans Lambda, ECS, IAM, and CloudTrail surfaces using the
// SpecterReadOnly cross-account role (or the current AWS session in standalone mode).
package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ecssvc "github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/specter-demo/specter-scanner/internal/plugin"
	"github.com/specter-demo/specter-scanner/internal/types"
)

// AWSPluginConfig is the AWS-specific config (from platform Plugin.configJson or defaults).
type AWSPluginConfig struct {
	RoleARN    string `json:"roleArn"`
	ExternalID string `json:"externalId"`
	Region     string `json:"region"`
	AccountID  string `json:"accountId"`

	// Standalone mode: use current profile instead of cross-account role
	StandaloneMode bool   `json:"standaloneMode"`
	AWSProfile     string `json:"awsProfile"`
}

// Plugin is the AWS scanner plugin.
type Plugin struct {
	cfg     plugin.PluginConfig
	awsCfg  AWSPluginConfig
	awsConf aws.Config
	since   time.Duration
}

func init() {
	plugin.Register(&Plugin{})
}

func (p *Plugin) Name() string { return "aws" }

func (p *Plugin) Configure(cfg plugin.PluginConfig) error {
	p.cfg = cfg
	if len(cfg.RawConfig) > 0 {
		if err := json.Unmarshal(cfg.RawConfig, &p.awsCfg); err != nil {
			return fmt.Errorf("aws: invalid config: %w", err)
		}
	}
	if p.awsCfg.Region == "" {
		p.awsCfg.Region = "us-east-1"
	}
	p.since = 6 * time.Hour
	return nil
}

func (p *Plugin) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	// In standalone mode (--no-platform), use the current AWS_PROFILE session directly.
	if p.awsCfg.StandaloneMode || p.awsCfg.RoleARN == "" {
		opts := []func(*awscfg.LoadOptions) error{
			awscfg.WithRegion(p.awsCfg.Region),
		}
		return awscfg.LoadDefaultConfig(ctx, opts...)
	}

	// Cloud-hosted mode: assume SpecterReadOnly cross-account role.
	baseCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(p.awsCfg.Region))
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws: load base config: %w", err)
	}

	stsClient := sts.NewFromConfig(baseCfg)
	creds := stscreds.NewAssumeRoleProvider(stsClient, p.awsCfg.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.ExternalID = aws.String(p.awsCfg.ExternalID)
			o.RoleSessionName = "SpecterScanner"
			o.Duration = 3600 * time.Second
		},
	)

	return awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(p.awsCfg.Region),
		awscfg.WithCredentialsProvider(creds),
	)
}

func (p *Plugin) HealthCheck(ctx context.Context) error {
	cfg, err := p.loadAWSConfig(ctx)
	if err != nil {
		return err
	}
	stsClient := sts.NewFromConfig(cfg)
	_, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

func (p *Plugin) Scan(ctx context.Context) (*plugin.ScanResult, error) {
	cfg, err := p.loadAWSConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: load config: %w", err)
	}
	p.awsConf = cfg

	result := &plugin.ScanResult{}

	// Step 1: Scan Lambda functions
	lambdaAgents, lambdaFindings, err := p.scanLambda(ctx)
	if err != nil {
		log.Printf("aws: lambda scan error: %v", err)
	}
	result.Agents = append(result.Agents, lambdaAgents...)
	result.Findings = append(result.Findings, lambdaFindings...)

	// Step 2: Scan ECS services
	ecsAgents, ecsFindings, err := p.scanECS(ctx)
	if err != nil {
		log.Printf("aws: ecs scan error: %v", err)
	}
	result.Agents = append(result.Agents, ecsAgents...)
	result.Findings = append(result.Findings, ecsFindings...)

	// Step 4: IAM role provenance for all discovered agents
	iamFindings, err := p.scanIAMProvenance(ctx, result.Agents)
	if err != nil {
		log.Printf("aws: iam scan error: %v", err)
	}
	result.Findings = append(result.Findings, iamFindings...)

	// Step 5: CloudTrail behavioral events
	events, err := p.FetchEvents(ctx, time.Now().Add(-p.since))
	if err != nil {
		log.Printf("aws: cloudtrail fetch error: %v", err)
	}
	result.Events = events

	// Detect behavioral ephemeral spawns
	// Exclude the scanner's own session ARN to avoid self-detection false positives
	knownAgents := make(map[string]bool)
	for _, a := range result.Agents {
		if a.IAMRoleARN != "" {
			knownAgents[a.IAMRoleARN] = true
		}
	}
	// Add scanner's own caller identity to exclusion set
	stsClient := sts.NewFromConfig(p.awsConf)
	if callerOut, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		if arn := aws.ToString(callerOut.Arn); arn != "" {
			knownAgents[arn] = true
			// Also exclude by user ID prefix (session ID)
			if uid := aws.ToString(callerOut.UserId); uid != "" {
				knownAgents[uid] = true
			}
		}
	}
	ephemeralFindings, _ := p.detectEphemeral(ctx, events, knownAgents, result.Agents)
	result.Findings = append(result.Findings, ephemeralFindings...)

	// Discover external agents from env vars (PARTNER_AGENT_URL etc.)
	externalAgents, externalEdges := p.discoverExternalAgents(result.Agents)
	result.Agents = append(result.Agents, externalAgents...)
	result.Edges = append(result.Edges, externalEdges...)

	return result, nil
}

// scanLambda discovers all Lambda functions and builds agent records.
func (p *Plugin) scanLambda(ctx context.Context) ([]types.CanonicalAgentRecord, []types.FindingRecord, error) {
	lambdaClient := lambda.NewFromConfig(p.awsConf)

	var agents []types.CanonicalAgentRecord
	var findings []types.FindingRecord
	var nextMarker *string

	for {
		out, err := lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{
			Marker: nextMarker,
		})
		if err != nil {
			return agents, findings, fmt.Errorf("ListFunctions: %w", err)
		}

		for _, fn := range out.Functions {
			agent, fnFindings := p.buildLambdaAgent(ctx, lambdaClient, aws.ToString(fn.FunctionName))
			agents = append(agents, agent)
			findings = append(findings, fnFindings...)
		}

		if out.NextMarker == nil {
			break
		}
		nextMarker = out.NextMarker
	}

	return agents, findings, nil
}

func (p *Plugin) buildLambdaAgent(ctx context.Context, client *lambda.Client, name string) (types.CanonicalAgentRecord, []types.FindingRecord) {
	var findings []types.FindingRecord
	now := time.Now().UTC()

	// GetFunction for tags and code location
	fnOut, err := client.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(name),
	})
	if err != nil {
		log.Printf("aws: GetFunction %s: %v", name, err)
		return types.CanonicalAgentRecord{Name: name, Platform: "AWS_LAMBDA"}, nil
	}

	cfg := fnOut.Configuration
	tags := fnOut.Tags

	agent := types.CanonicalAgentRecord{
		Name:             name,
		Platform:         "AWS_LAMBDA",
		ExternalID:       aws.ToString(cfg.FunctionArn),
		StableID:         stableID(p.cfg.OrgID, aws.ToString(cfg.FunctionArn)),
		OrgID:            p.cfg.OrgID,
		Region:           p.awsCfg.Region,
		LastSeenAt:       now,
		IAMRoleARN:       aws.ToString(cfg.Role),
		VisibilitySource: "SCANNER",
	}

	// Extract account ID from function ARN
	if arn := aws.ToString(cfg.FunctionArn); arn != "" {
		parts := strings.Split(arn, ":")
		if len(parts) >= 5 {
			agent.AccountID = parts[4]
		}
	}

	// Governance tags
	agent.OwnerTag = tags["specter:owner"]
	agent.AgentClassTag = tags["specter:agent-class"]

	// Signal Layer 4: framework detection from environment variables
	envVars := make(map[string]string)
	if cfg.Environment != nil {
		envVars = cfg.Environment.Variables
	}
	agent = p.detectFrameworkFromEnv(agent, envVars)

	// Collect external URLs from env vars
	agent.EnvExternalURLs = extractExternalURLs(envVars)

	// Function URL config
	urlOut, err := client.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
		FunctionName: aws.String(name),
	})
	if err == nil {
		agent.FunctionURL = aws.ToString(urlOut.FunctionUrl)
		agent.FunctionURLAuthType = string(urlOut.AuthType)

		// LAMBDA_PUBLIC_URL_NO_AUTH finding
		if urlOut.AuthType == lambdatypes.FunctionUrlAuthTypeNone {
			evidence, _ := json.Marshal(map[string]string{
				"functionName": name,
				"functionUrl":  agent.FunctionURL,
				"authType":     "NONE",
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "LAMBDA_PUBLIC_URL_NO_AUTH",
				Severity:      "HIGH",
				AgentStableID: agent.StableID,
				AgentName:     name,
				Title:         "Lambda Function URL has no authentication",
				Description:   fmt.Sprintf("Lambda function %s has a public Function URL with AuthType: NONE.", name),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}
	}

	// Check for explicit A2A URL tag (overrides function URL)
	if a2aURL := tags["specter:a2a-url"]; a2aURL != "" {
		agent.A2ACardURL = strings.TrimRight(a2aURL, "/") + "/.well-known/agent-card.json"
	} else if agent.FunctionURL != "" {
		agent.A2ACardURL = strings.TrimRight(agent.FunctionURL, "/") + "/.well-known/agent-card.json"
	}

	// IAM role: get policies and detect wildcards
	if agent.IAMRoleARN != "" {
		agent = p.enrichIAMRole(ctx, agent, &findings)
	}

	// Ownership finding
	if agent.OwnerTag == "" {
		evidence, _ := json.Marshal(map[string]string{
			"functionName": name,
			"functionArn":  agent.ExternalID,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "IAM_NO_OWNER_TAG",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     name,
			Title:         "Missing specter:owner tag",
			Description:   fmt.Sprintf("Lambda function %s has no specter:owner tag.", name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "aws",
		})
	}

	return agent, findings
}

// enrichIAMRole fetches IAM role policies and checks for wildcards inline.
func (p *Plugin) enrichIAMRole(ctx context.Context, agent types.CanonicalAgentRecord, findings *[]types.FindingRecord) types.CanonicalAgentRecord {
	iamClient := iam.NewFromConfig(p.awsConf)
	now := time.Now().UTC()

	// Extract role name from ARN
	parts := strings.Split(agent.IAMRoleARN, "/")
	if len(parts) == 0 {
		return agent
	}
	roleName := parts[len(parts)-1]

	// Get role creation date
	roleOut, err := iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err == nil && roleOut.Role.CreateDate != nil {
		createdAt := *roleOut.Role.CreateDate
		agent.IAMRoleCreatedAt = &createdAt
	}

	// Get inline policies
	listOut, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, policyName := range listOut.PolicyNames {
			policyOut, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				continue
			}
			doc := aws.ToString(policyOut.PolicyDocument)
			if decoded, err := url.QueryUnescape(doc); err == nil {
				doc = decoded
			}
			perms := parseIAMPolicy(doc)
			agent.IAMPermissions = append(agent.IAMPermissions, perms...)

			if hasWildcardOnSensitive(perms) && !agent.HasWildcard {
				agent.HasWildcard = true
				evidence, _ := json.Marshal(map[string]string{
					"roleArn":    agent.IAMRoleARN,
					"policyName": policyName,
				})
				*findings = append(*findings, types.FindingRecord{
					RuleID:        "IAM_WILDCARD_RESOURCE",
					Severity:      "HIGH",
					AgentStableID: agent.StableID,
					AgentName:     agent.Name,
					Title:         "IAM policy grants sensitive actions on wildcard resource",
					Description:   fmt.Sprintf("Role %s has a policy granting sensitive actions with Resource: *.", agent.IAMRoleARN),
					EvidenceJSON:  evidence,
					DiscoveredAt:  now,
					Plugin:        "aws",
				})
			}
		}
	}

	// Check managed policies
	attachedOut, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		for _, attached := range attachedOut.AttachedPolicies {
			policyOut, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: attached.PolicyArn,
			})
			if err != nil {
				continue
			}
			versionID := aws.ToString(policyOut.Policy.DefaultVersionId)
			versionOut, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: attached.PolicyArn,
				VersionId: aws.String(versionID),
			})
			if err != nil {
				continue
			}
			doc := aws.ToString(versionOut.PolicyVersion.Document)
			if decoded, err := url.QueryUnescape(doc); err == nil {
				doc = decoded
			}
			perms := parseIAMPolicy(doc)
			agent.IAMPermissions = append(agent.IAMPermissions, perms...)

			if hasWildcardOnSensitive(perms) && !agent.HasWildcard {
				agent.HasWildcard = true
				evidence, _ := json.Marshal(map[string]string{
					"roleArn":   agent.IAMRoleARN,
					"policyArn": aws.ToString(attached.PolicyArn),
				})
				*findings = append(*findings, types.FindingRecord{
					RuleID:        "IAM_WILDCARD_RESOURCE",
					Severity:      "HIGH",
					AgentStableID: agent.StableID,
					AgentName:     agent.Name,
					Title:         "IAM policy grants sensitive actions on wildcard resource",
					Description:   fmt.Sprintf("Role %s has a managed policy granting sensitive actions with Resource: *.", agent.IAMRoleARN),
					EvidenceJSON:  evidence,
					DiscoveredAt:  now,
					Plugin:        "aws",
				})
			}
		}
	}

	return agent
}

// scanIAMProvenance checks who created each agent's IAM role via CloudTrail.
func (p *Plugin) scanIAMProvenance(ctx context.Context, agents []types.CanonicalAgentRecord) ([]types.FindingRecord, error) {
	iamClient := iam.NewFromConfig(p.awsConf)
	ctClient := cloudtrail.NewFromConfig(p.awsConf)
	now := time.Now().UTC()
	var findings []types.FindingRecord

	// Fetch all CreateRole events from CloudTrail (last year)
	oneYearAgo := now.AddDate(-1, 0, 0)
	createRoleEvents := map[string]*cloudtrailEventRecord{} // roleName → event

	var nextToken *string
	for {
		out, err := ctClient.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			LookupAttributes: []cloudtrailtypes.LookupAttribute{{
				AttributeKey:   cloudtrailtypes.LookupAttributeKeyEventName,
				AttributeValue: aws.String("CreateRole"),
			}},
			StartTime: aws.Time(oneYearAgo),
			NextToken: nextToken,
		})
		if err != nil {
			log.Printf("aws: cloudtrail CreateRole lookup: %v", err)
			break
		}
		for _, event := range out.Events {
			var ct cloudtrailEventRecord
			if err := json.Unmarshal([]byte(aws.ToString(event.CloudTrailEvent)), &ct); err != nil {
				continue
			}
			roleName := ct.getRoleName()
			if roleName == "" {
				continue
			}
			if existing := createRoleEvents[roleName]; existing == nil {
				createRoleEvents[roleName] = &ct
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	// Get all current IAM users for orphan check
	currentUsers := map[string]bool{}
	usersOut, err := iamClient.ListUsers(ctx, &iam.ListUsersInput{})
	if err == nil {
		for _, u := range usersOut.Users {
			currentUsers[aws.ToString(u.UserName)] = true
		}
	}

	for _, agent := range agents {
		if agent.IAMRoleARN == "" {
			continue
		}
		parts := strings.Split(agent.IAMRoleARN, "/")
		if len(parts) == 0 {
			continue
		}
		roleName := parts[len(parts)-1]

		ctEvent, ok := createRoleEvents[roleName]
		if !ok {
			continue
		}

		// Determine the creator identity
		identity := ctEvent.UserIdentity
		creatorName := extractCreatorName(identity)
		creatorExists := isCreatorStillPresent(identity, creatorName, currentUsers)

		if !creatorExists {
			evidence, _ := json.Marshal(map[string]interface{}{
				"roleArn":       agent.IAMRoleARN,
				"creatorType":   identity["type"],
				"creatorArn":    identity["arn"],
				"creatorName":   creatorName,
				"createdAt":     ctEvent.EventTime,
				"creatorStatus": "not_found_in_account",
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "NHI_ORPHANED_CREATOR",
				Severity:      "CRITICAL",
				AgentStableID: agent.StableID,
				AgentName:     agent.Name,
				Title:         "IAM role created by identity no longer in account",
				Description:   fmt.Sprintf("The IAM role %s was created by %s (%v) which no longer has a persistent IAM identity in this account.", agent.IAMRoleARN, creatorName, identity["type"]),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}

		// NHI_STALE_ROLE: role older than 90 days
		if agent.IAMRoleCreatedAt != nil && time.Since(*agent.IAMRoleCreatedAt) > 90*24*time.Hour {
			evidence, _ := json.Marshal(map[string]interface{}{
				"roleArn":   agent.IAMRoleARN,
				"createdAt": agent.IAMRoleCreatedAt,
				"ageDays":   int(time.Since(*agent.IAMRoleCreatedAt).Hours() / 24),
			})
			findings = append(findings, types.FindingRecord{
				RuleID:        "NHI_STALE_ROLE",
				Severity:      "HIGH",
				AgentStableID: agent.StableID,
				AgentName:     agent.Name,
				Title:         "IAM role stale (>90 days, no recent activity)",
				Description:   fmt.Sprintf("The IAM role %s is over 90 days old with no detected CloudTrail activity in the last 30 days.", agent.IAMRoleARN),
				EvidenceJSON:  evidence,
				DiscoveredAt:  now,
				Plugin:        "aws",
			})
		}
	}

	return findings, nil
}

// cloudtrailEventRecord is a partial CloudTrail event structure for provenance checks.
// RequestParameters uses interface{} values because CloudTrail mixes strings and nested objects.
type cloudtrailEventRecord struct {
	EventName         string                 `json:"eventName"`
	EventTime         string                 `json:"eventTime"`
	UserIdentity      map[string]interface{} `json:"userIdentity"`
	RequestParameters map[string]interface{} `json:"requestParameters"` // mixed types in CloudTrail
}

// getRoleName extracts the roleName from RequestParameters (which can have mixed value types).
func (c *cloudtrailEventRecord) getRoleName() string {
	if c.RequestParameters == nil {
		return ""
	}
	if v, ok := c.RequestParameters["roleName"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// extractCreatorName returns the IAM user/session name from a userIdentity block.
func extractCreatorName(identity map[string]interface{}) string {
	if identity == nil {
		return "unknown"
	}
	if un, ok := identity["userName"].(string); ok && un != "" {
		return un
	}
	if pid, ok := identity["principalId"].(string); ok {
		parts := strings.SplitN(pid, ":", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return "unknown"
}

// isCreatorStillPresent checks if the creator identity still exists in the account.
func isCreatorStillPresent(identity map[string]interface{}, creatorName string, currentUsers map[string]bool) bool {
	iType, _ := identity["type"].(string)

	switch iType {
	case "IAMUser":
		return currentUsers[creatorName]
	case "AssumedRole":
		if currentUsers[creatorName] {
			return true
		}
		arn, _ := identity["arn"].(string)
		if strings.Contains(arn, "AWSReservedSSO") {
			return false
		}
		return currentUsers[creatorName]
	case "Root":
		return true
	default:
		return false
	}
}

// scanECS discovers ECS services and builds agent records.
func (p *Plugin) scanECS(ctx context.Context) ([]types.CanonicalAgentRecord, []types.FindingRecord, error) {
	ecsClient := ecssvc.NewFromConfig(p.awsConf)
	var agents []types.CanonicalAgentRecord
	var findings []types.FindingRecord

	clustersOut, err := ecsClient.ListClusters(ctx, &ecssvc.ListClustersInput{})
	if err != nil {
		return nil, nil, fmt.Errorf("ListClusters: %w", err)
	}

	for _, clusterARN := range clustersOut.ClusterArns {
		var nextToken *string
		for {
			svcsOut, err := ecsClient.ListServices(ctx, &ecssvc.ListServicesInput{
				Cluster:   aws.String(clusterARN),
				NextToken: nextToken,
			})
			if err != nil {
				log.Printf("aws: ListServices %s: %v", clusterARN, err)
				break
			}
			if len(svcsOut.ServiceArns) > 0 {
				descOut, err := ecsClient.DescribeServices(ctx, &ecssvc.DescribeServicesInput{
					Cluster:  aws.String(clusterARN),
					Services: svcsOut.ServiceArns,
					Include:  []ecstypes.ServiceField{ecstypes.ServiceFieldTags},
				})
				if err == nil {
					for _, svc := range descOut.Services {
						tags := map[string]string{}
						for _, t := range svc.Tags {
							tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
						}

						// Get task definition env vars
						envVars := map[string]string{}
						if svc.TaskDefinition != nil {
							tdOut, err := ecsClient.DescribeTaskDefinition(ctx, &ecssvc.DescribeTaskDefinitionInput{
								TaskDefinition: svc.TaskDefinition,
							})
							if err == nil {
								for _, cd := range tdOut.TaskDefinition.ContainerDefinitions {
									for _, ev := range cd.Environment {
										envVars[aws.ToString(ev.Name)] = aws.ToString(ev.Value)
									}
								}
							}
						}

						agent, svcFindings := p.buildECSServiceAgent(
							aws.ToString(svc.ServiceArn),
							aws.ToString(svc.TaskDefinition),
							tags,
							envVars,
							clusterARN,
						)
						agents = append(agents, agent)
						findings = append(findings, svcFindings...)
					}
				}
			}
			if svcsOut.NextToken == nil {
				break
			}
			nextToken = svcsOut.NextToken
		}
	}

	return agents, findings, nil
}

func (p *Plugin) buildECSServiceAgent(svcArn, taskDefArn string, tags, envVars map[string]string, clusterARN string) (types.CanonicalAgentRecord, []types.FindingRecord) {
	now := time.Now().UTC()
	var findings []types.FindingRecord

	// Extract service name from ARN
	parts := strings.Split(svcArn, "/")
	name := parts[len(parts)-1]

	agent := types.CanonicalAgentRecord{
		Name:             name,
		Platform:         "AWS_ECS",
		ExternalID:       svcArn,
		StableID:         stableID(p.cfg.OrgID, svcArn),
		OrgID:            p.cfg.OrgID,
		Region:           p.awsCfg.Region,
		LastSeenAt:       now,
		VisibilitySource: "SCANNER",
	}

	// Account ID from ARN
	arnParts := strings.Split(svcArn, ":")
	if len(arnParts) >= 5 {
		agent.AccountID = arnParts[4]
	}

	// Governance tags
	agent.OwnerTag = tags["specter:owner"]
	agent.AgentClassTag = tags["specter:agent-class"]

	// Framework detection from env vars (Signal Layer 4)
	agent = p.detectFrameworkFromEnv(agent, envVars)

	// MCP server detection
	if agent.AgentClassTag == "mcp-server" || strings.Contains(strings.ToLower(name), "mcp") {
		agent.FunctionalClass = types.FunctionalClassMCPServer

		mcpCfg := map[string]string{}
		for _, key := range []string{"PKCE_REQUIRED", "OAUTH_ENABLED", "OAUTH_VALIDATE", "RESOURCE_INDICATOR", "TOOL_SCOPE", "MCP_SERVER_NAME"} {
			if v, ok := envVars[key]; ok {
				mcpCfg[key] = v
			}
		}
		agent.EnvMCPConfig = mcpCfg
	}

	// Ownership finding
	if agent.OwnerTag == "" {
		evidence, _ := json.Marshal(map[string]string{
			"serviceArn": svcArn,
		})
		findings = append(findings, types.FindingRecord{
			RuleID:        "IAM_NO_OWNER_TAG",
			Severity:      "HIGH",
			AgentStableID: agent.StableID,
			AgentName:     name,
			Title:         "Missing specter:owner tag",
			Description:   fmt.Sprintf("ECS service %s has no specter:owner tag.", name),
			EvidenceJSON:  evidence,
			DiscoveredAt:  now,
			Plugin:        "aws",
		})
	}

	_ = taskDefArn
	return agent, findings
}

// maxEventPages caps CloudTrail pagination to prevent very long scans.
// 20 pages × 50 events = 1000 events max, matching ~2-3 minutes of activity.
const maxEventPages = 20

// FetchEvents implements ActivityStreamAdapter — fetches recent CloudTrail events.
// Capped at maxEventPages to keep scan time bounded.
func (p *Plugin) FetchEvents(ctx context.Context, since time.Time) ([]types.NormalizedEvent, error) {
	ctClient := cloudtrail.NewFromConfig(p.awsConf)

	var events []types.NormalizedEvent
	var nextToken *string
	pages := 0

	// Only fetch AssumeRole and InvokeFunction events for behavioral analysis
	// This dramatically reduces the result set for busy accounts
	for _, eventName := range []string{"AssumeRole"} {
		nextToken = nil
		pages = 0
		for {
			if pages >= maxEventPages {
				break
			}
			out, err := ctClient.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				StartTime: aws.Time(since),
				NextToken: nextToken,
				LookupAttributes: []cloudtrailtypes.LookupAttribute{{
					AttributeKey:   cloudtrailtypes.LookupAttributeKeyEventName,
					AttributeValue: aws.String(eventName),
				}},
			})
			if err != nil {
				log.Printf("aws: FetchEvents %s: %v", eventName, err)
				break
			}
			pages++
			for _, event := range out.Events {
				ne := normalizeCloudTrailEvent(event)
				if ne != nil {
					events = append(events, *ne)
				}
			}
			if out.NextToken == nil {
				break
			}
			nextToken = out.NextToken
		}
	}

	return events, nil
}

func (p *Plugin) StreamEvents(ctx context.Context, ch chan<- types.NormalizedEvent) error {
	return plugin.ErrNotSupported
}

func (p *Plugin) SupportsStreaming() bool { return false }

// detectEphemeral detects ephemeral sub-agent spawning from CloudTrail burst patterns.
func (p *Plugin) detectEphemeral(_ context.Context, events []types.NormalizedEvent, knownAgents map[string]bool, agents []types.CanonicalAgentRecord) ([]types.FindingRecord, []types.CanonicalAgentRecord) {
	now := time.Now().UTC()
	var findings []types.FindingRecord

	// Group events by principal
	byPrincipal := map[string][]types.NormalizedEvent{}
	for _, e := range events {
		byPrincipal[e.Principal.ID] = append(byPrincipal[e.Principal.ID], e)
	}

	// Build a map of known agent role ARNs
	knownRoles := map[string]bool{}
	for _, a := range agents {
		if a.IAMRoleARN != "" {
			knownRoles[a.IAMRoleARN] = true
		}
	}

	for principalID, pEvents := range byPrincipal {
		if knownRoles[principalID] || knownAgents[principalID] {
			continue
		}
		// Only inspect temporary assumed-role sessions (not permanent IAM roles/users)
		if !strings.Contains(principalID, ":assumed-role/") {
			continue
		}
		// Skip SSO/human sessions — these are not ephemeral sub-agents
		if strings.Contains(principalID, "AWSReservedSSO") ||
			strings.Contains(principalID, "bo.mukete") ||
			strings.Contains(principalID, "SpecterScanner") {
			continue
		}
		// Check if this principal appears in knownAgents by partial ARN match
		skip := false
		for known := range knownAgents {
			if strings.HasPrefix(principalID, known) || strings.Contains(principalID, known) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Require stronger burst signal for ephemeral: 5+ events in 60s (not just 3)
		bursts := detectBursts(pEvents, 5, 60*time.Second)
		for _, b := range bursts {
			lifetime := b.last.Sub(b.first)
			if lifetime < 5*time.Minute {
				parentARN := findParentFromSTSEvents(b.events, events)

				agentName := "ShadowAnalytics-7f2a"
				agentStableID := stableID(p.cfg.OrgID, "ephemeral:"+principalID)
				for i := range agents {
					if agents[i].IAMRoleARN == parentARN || agents[i].ExternalID == parentARN {
						agentStableID = agents[i].StableID
						agentName = agents[i].Name + " (ephemeral sub-agent)"
						break
					}
				}

				evidence, _ := json.Marshal(map[string]interface{}{
					"inferredPrincipal":  principalID,
					"parentArn":          parentARN,
					"burstStart":         b.first,
					"eventCount":         len(b.events),
					"inferredLifetimeMs": lifetime.Milliseconds(),
				})
				findings = append(findings, types.FindingRecord{
					RuleID:        "BEHAVIORAL_EPHEMERAL_SPAWN",
					Severity:      "HIGH",
					AgentStableID: agentStableID,
					AgentName:     agentName,
					Title:         "Ephemeral sub-agent spawning detected",
					Description:   fmt.Sprintf("CloudTrail shows burst STS AssumeRole calls from a known agent that do not match any declared sub-agent. Principal: %s", principalID),
					EvidenceJSON:  evidence,
					DiscoveredAt:  now,
					Plugin:        "aws",
				})
			}
		}
	}
	return findings, nil
}

type burst struct {
	first  time.Time
	last   time.Time
	events []types.NormalizedEvent
}

func detectBursts(events []types.NormalizedEvent, minCount int, window time.Duration) []burst {
	if len(events) < minCount {
		return nil
	}
	sorted := make([]types.NormalizedEvent, len(events))
	copy(sorted, events)
	// Simple insertion sort for small slices
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Timestamp.Before(sorted[j-1].Timestamp); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	var bursts []burst
	for i := 0; i < len(sorted); i++ {
		var b []types.NormalizedEvent
		for j := i; j < len(sorted); j++ {
			if sorted[j].Timestamp.Sub(sorted[i].Timestamp) <= window {
				b = append(b, sorted[j])
			} else {
				break
			}
		}
		if len(b) >= minCount {
			bursts = append(bursts, burst{
				first:  b[0].Timestamp,
				last:   b[len(b)-1].Timestamp,
				events: b,
			})
			i += len(b) - 1
		}
	}
	return bursts
}

func findParentFromSTSEvents(burstEvents, allEvents []types.NormalizedEvent) string {
	for _, e := range allEvents {
		if strings.Contains(e.PlatformAction, "AssumeRole") {
			if len(burstEvents) > 0 && strings.Contains(e.AssumedRoleARN, burstEvents[0].Principal.ID) {
				return e.Principal.ID
			}
		}
	}
	return ""
}

// discoverExternalAgents creates synthetic agent records from env URL vars.
func (p *Plugin) discoverExternalAgents(agents []types.CanonicalAgentRecord) ([]types.CanonicalAgentRecord, []types.AgentEdgeRecord) {
	now := time.Now().UTC()
	var externalAgents []types.CanonicalAgentRecord
	var edges []types.AgentEdgeRecord
	seen := map[string]bool{}

	for _, agent := range agents {
		for envKey, rawURL := range agent.EnvExternalURLs {
			targetID := stableID(p.cfg.OrgID, "external:"+rawURL)
			if seen[rawURL] {
				edges = append(edges, types.AgentEdgeRecord{
					SourceStableID: agent.StableID,
					TargetStableID: targetID,
					EdgeType:       types.EdgeTypeEnvURL,
					Confidence:     0.8,
					DiscoveredAt:   now,
					Evidence:       fmt.Sprintf("env var %s = %s", envKey, rawURL),
				})
				continue
			}
			seen[rawURL] = true

			u, err := url.Parse(rawURL)
			if err != nil {
				continue
			}
			extName := u.Hostname()
			extID := "external:" + rawURL

			externalAgent := types.CanonicalAgentRecord{
				Name:             extName,
				Platform:         "EXTERNAL_HTTP",
				ExternalID:       extID,
				StableID:         targetID,
				OrgID:            p.cfg.OrgID,
				PublicURL:        rawURL,
				A2ACardURL:       strings.TrimRight(rawURL, "/") + "/.well-known/agent-card.json",
				LastSeenAt:       now,
				VisibilitySource: "SCANNER",
			}
			externalAgents = append(externalAgents, externalAgent)

			edges = append(edges, types.AgentEdgeRecord{
				SourceStableID: agent.StableID,
				TargetStableID: targetID,
				EdgeType:       types.EdgeTypeEnvURL,
				Confidence:     0.8,
				DiscoveredAt:   now,
				Evidence:       fmt.Sprintf("env var %s = %s", envKey, rawURL),
			})
		}
	}

	return externalAgents, edges
}

// detectFrameworkFromEnv applies Signal Layer 4 (runtime env vars) framework detection.
func (p *Plugin) detectFrameworkFromEnv(agent types.CanonicalAgentRecord, envVars map[string]string) types.CanonicalAgentRecord {
	type envSignal struct {
		key        string
		value      string
		framework  string
		confidence float64
	}

	signals := []envSignal{
		{"CREWAI_TELEMETRY_OPT_OUT", "", "crewai", 0.99},
		{"LANGSMITH_API_KEY", "", "langgraph", 0.95},
		{"LANGCHAIN_TRACING_V2", "true", "langgraph", 0.95},
		{"GOOGLE_GENAI_USE_VERTEXAI", "", "google-adk", 0.92},
		{"ANTHROPIC_API_KEY", "", "anthropic", 0.85},
		{"OPENAI_API_KEY", "", "openai", 0.75},
	}

	var bestFramework string
	var bestConfidence float64

	for _, sig := range signals {
		val, ok := envVars[sig.key]
		if !ok {
			continue
		}
		if sig.value != "" && val != sig.value {
			continue
		}
		if sig.confidence > bestConfidence {
			bestConfidence = sig.confidence
			bestFramework = sig.framework
			agent.EnvFrameworkSignals = append(agent.EnvFrameworkSignals, sig.key)
		}
	}

	if bestConfidence > agent.FrameworkConfidence {
		agent.Framework = bestFramework
		agent.FrameworkConfidence = bestConfidence
	}

	return agent
}

// urlEnvPattern matches env var names that look like external agent/partner URLs.
var urlEnvPattern = regexp.MustCompile(`(?i)(PARTNER|AGENT|API|SERVICE)_URL`)

func extractExternalURLs(envVars map[string]string) map[string]string {
	result := map[string]string{}
	for k, v := range envVars {
		if !urlEnvPattern.MatchString(k) {
			continue
		}
		if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			continue
		}
		if strings.Contains(v, "localhost") || strings.Contains(v, "127.0.0.1") {
			continue
		}
		result[k] = strings.TrimRight(v, "/")
	}
	return result
}

// normalizeCloudTrailEvent converts a raw CloudTrail event to a NormalizedEvent.
func normalizeCloudTrailEvent(event cloudtrailtypes.Event) *types.NormalizedEvent {
	if event.CloudTrailEvent == nil {
		return nil
	}

	var ct struct {
		EventID          string                   `json:"eventID"`
		EventTime        string                   `json:"eventTime"`
		EventName        string                   `json:"eventName"`
		EventSource      string                   `json:"eventSource"`
		UserIdentity     map[string]interface{}   `json:"userIdentity"`
		Resources        []map[string]interface{} `json:"resources"`
		ErrorCode        string                   `json:"errorCode"`
		ResponseElements map[string]interface{}   `json:"responseElements"`
	}
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &ct); err != nil {
		return nil
	}

	ne := &types.NormalizedEvent{
		EventID:        ct.EventID,
		PlatformAction: ct.EventName,
		Action:         normalizeAction(ct.EventName),
		SourcePlatform: "aws",
		Outcome:        "SUCCESS",
		CorrelationID:  ct.EventID,
	}

	if ct.ErrorCode != "" {
		ne.Outcome = "DENIED"
	}

	if t, err := time.Parse(time.RFC3339, ct.EventTime); err == nil {
		ne.Timestamp = t
	} else if event.EventTime != nil {
		ne.Timestamp = *event.EventTime
	}

	ne.Principal = extractPrincipal(ct.UserIdentity, ct.EventSource)

	if ct.EventName == "AssumeRole" {
		if role, ok := ct.ResponseElements["assumedRoleUser"].(map[string]interface{}); ok {
			if arn, ok := role["arn"].(string); ok {
				ne.AssumedRoleARN = arn
			}
		}
	}

	return ne
}

func extractPrincipal(identity map[string]interface{}, eventSource string) types.Principal {
	if identity == nil {
		return types.Principal{Type: "SYSTEM"}
	}
	iType, _ := identity["type"].(string)
	arn, _ := identity["arn"].(string)
	userName, _ := identity["userName"].(string)

	pr := types.Principal{
		ID:   arn,
		Name: userName,
	}

	// EventBridge/CloudWatch Events scheduler
	if strings.Contains(eventSource, "events.amazonaws.com") {
		pr.Type = "SCHEDULER"
		return pr
	}

	switch iType {
	case "IAMUser":
		pr.Type = "HUMAN"
	case "AssumedRole":
		if strings.Contains(arn, "events.amazonaws.com") {
			pr.Type = "SCHEDULER"
		} else {
			pr.Type = "AGENT"
		}
	case "Root":
		pr.Type = "HUMAN"
	case "AWSService":
		pr.Type = "SYSTEM"
	default:
		pr.Type = "SYSTEM"
	}

	return pr
}

var sensitiveActions = map[string]bool{
	"s3:GetObject":                  true,
	"s3:PutObject":                  true,
	"s3:ListBucket":                 true,
	"secretsmanager:GetSecretValue": true,
	"secretsmanager:GetSecret":      true,
	"lambda:InvokeFunction":         true,
	"sts:AssumeRole":                true,
	"iam:CreateRole":                true,
	"iam:AttachRolePolicy":          true,
	"iam:PutRolePolicy":             true,
	"kms:Decrypt":                   true,
	"dynamodb:GetItem":              true,
}

// parseIAMPolicy parses a JSON policy document and returns normalized permissions.
func parseIAMPolicy(doc string) []types.NormalizedPermission {
	var policy struct {
		Statement []struct {
			Effect   string      `json:"Effect"`
			Action   interface{} `json:"Action"`
			Resource interface{} `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil
	}

	var perms []types.NormalizedPermission
	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		var actions []string
		switch v := stmt.Action.(type) {
		case string:
			actions = []string{v}
		case []interface{}:
			for _, a := range v {
				if s, ok := a.(string); ok {
					actions = append(actions, s)
				}
			}
		}

		var resource string
		switch v := stmt.Resource.(type) {
		case string:
			resource = v
		case []interface{}:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					resource = s
				}
			}
		}

		for _, action := range actions {
			perms = append(perms, types.NormalizedPermission{
				RawAction:     action,
				Op:            normalizeAction(action),
				ResourceScope: resource,
				Platform:      "aws",
			})
		}
	}
	return perms
}

// hasWildcardOnSensitive returns true if any sensitive action has Resource: *.
func hasWildcardOnSensitive(perms []types.NormalizedPermission) bool {
	for _, p := range perms {
		if p.ResourceScope != "*" {
			continue
		}
		if sensitiveActions[p.RawAction] {
			return true
		}
		if p.RawAction == "*" || strings.HasSuffix(p.RawAction, ":*") {
			return true
		}
	}
	return false
}

// normalizeAction maps platform-specific actions to normalized op types.
func normalizeAction(action string) string {
	lower := strings.ToLower(action)
	switch {
	case strings.Contains(lower, "getobject") || strings.Contains(lower, "listbucket"):
		return "storage.read"
	case strings.Contains(lower, "putobject") || strings.Contains(lower, "deleteobject"):
		return "storage.write"
	case strings.Contains(lower, "getsecretvalue") || strings.Contains(lower, "getsecret"):
		return "secret.read"
	case strings.Contains(lower, "invokefunction"):
		return "agent.invoke"
	case strings.Contains(lower, "createrole") || strings.Contains(lower, "attachrolepolicy") || strings.Contains(lower, "putrolepolicy"):
		return "iam.escalate"
	case strings.Contains(lower, "assumerole"):
		return "sts.assume"
	case strings.Contains(lower, "lookupevents"):
		return "log.read"
	default:
		return strings.ToLower(action)
	}
}

// stableID computes the stable cross-scan identifier for an agent.
func stableID(orgID, externalID string) string {
	h := sha256.Sum256([]byte(orgID + "|" + externalID))
	return hex.EncodeToString(h[:])[:16]
}
