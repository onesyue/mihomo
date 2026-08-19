package workflowsecurity

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var fullActionCommitPattern = regexp.MustCompile(`^[^/@\s]+/[^@\s]+@[0-9a-f]{40}$`)

var workflowPermissionPolicy = map[string]map[string]map[string]string{
	filepath.FromSlash(".github/workflows/build.yml"): {
		"build":             {"contents": "read"},
		"Upload-Prerelease": {"contents": "write"},
		"Upload-Release":    {"contents": "write"},
		"Docker":            {"contents": "read"},
	},
	filepath.FromSlash(".github/workflows/test.yml"): {
		"test": {"contents": "read"},
	},
}

func TestWorkflowSecurityContracts(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	workflowDir := filepath.Join(repoRoot, filepath.FromSlash(".github/workflows"))
	entries, err := os.ReadDir(workflowDir)
	require.NoError(t, err)

	seen := make(map[string]bool, len(workflowPermissionPolicy))
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yml" && filepath.Ext(entry.Name()) != ".yaml") {
			continue
		}
		relPath := filepath.Join(filepath.FromSlash(".github/workflows"), entry.Name())
		policy, ok := workflowPermissionPolicy[relPath]
		require.Truef(t, ok, "workflow %s has no fail-closed permission policy", relPath)
		path := filepath.Join(workflowDir, entry.Name())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, validateWorkflowSecurity(data, policy), path)
		seen[relPath] = true
	}

	require.Len(t, seen, len(workflowPermissionPolicy), "a policy names a missing workflow")
}

func TestWorkflowSecurityContractsRejectMutations(t *testing.T) {
	policy := map[string]map[string]string{"test": {"contents": "read"}}
	valid := `
jobs:
  test:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
      - uses: ./local-action
`
	require.NoError(t, validateWorkflowSecurity([]byte(valid), policy))

	tests := map[string]string{
		"mutable action": strings.Replace(valid, "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803", "actions/checkout@v6", 1),
		"write-all":      strings.Replace(valid, "permissions:\n      contents: read", "permissions: write-all", 1),
		"excess scope":   strings.Replace(valid, "contents: read", "contents: read\n      issues: write", 1),
		"missing comment": strings.Replace(
			valid,
			"@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0",
			"@d23441a48e516b6c34aea4fa41551a30e30af803",
			1,
		),
	}
	for name, mutated := range tests {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateWorkflowSecurity([]byte(mutated), policy))
		})
	}
}

func validateWorkflowSecurity(data []byte, policy map[string]map[string]string) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse workflow: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("workflow root must be a mapping")
	}
	root := document.Content[0]
	if err := validateActionReferences(root); err != nil {
		return err
	}

	jobs := mappingValue(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return fmt.Errorf("jobs must be a mapping")
	}
	if len(jobs.Content)/2 != len(policy) {
		return fmt.Errorf("jobs count %d does not match permission policy count %d", len(jobs.Content)/2, len(policy))
	}
	for i := 0; i < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		expected, ok := policy[jobName]
		if !ok {
			return fmt.Errorf("job %q has no fail-closed permission policy", jobName)
		}
		permissions := mappingValue(job, "permissions")
		if permissions == nil || permissions.Kind != yaml.MappingNode {
			return fmt.Errorf("job %q permissions must be an explicit mapping (write-all is forbidden)", jobName)
		}
		actual := make(map[string]string, len(permissions.Content)/2)
		for j := 0; j < len(permissions.Content); j += 2 {
			actual[permissions.Content[j].Value] = permissions.Content[j+1].Value
		}
		if !reflect.DeepEqual(actual, expected) {
			return fmt.Errorf("job %q permissions %v do not match least-privilege policy %v", jobName, actual, expected)
		}
	}
	return nil
}

func validateActionReferences(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "permissions" && value.Kind == yaml.ScalarNode && value.Value == "write-all" {
				return fmt.Errorf("line %d: permissions: write-all is forbidden", value.Line)
			}
			if key.Value == "uses" {
				if value.Kind != yaml.ScalarNode {
					return fmt.Errorf("line %d: uses must be a scalar", value.Line)
				}
				if !strings.HasPrefix(value.Value, "./") {
					if !fullActionCommitPattern.MatchString(value.Value) {
						return fmt.Errorf("line %d: action %q is not pinned to a full commit SHA", value.Line, value.Value)
					}
					if strings.TrimSpace(value.LineComment) == "" {
						return fmt.Errorf("line %d: pinned action %q is missing its version comment", value.Line, value.Value)
					}
				}
			}
			if err := validateActionReferences(value); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateActionReferences(child); err != nil {
			return err
		}
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
