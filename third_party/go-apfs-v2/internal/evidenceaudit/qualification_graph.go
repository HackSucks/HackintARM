package evidenceaudit

import (
	"fmt"
	"io/fs"
	"strings"

	"go.yaml.in/yaml/v3"
)

type graphWorkflow struct {
	On   yaml.Node           `yaml:"on"`
	Jobs map[string]graphJob `yaml:"jobs"`
}
type graphJob struct {
	Uses  string    `yaml:"uses"`
	If    string    `yaml:"if"`
	Needs yaml.Node `yaml:"needs"`
	Steps []struct {
		Run string            `yaml:"run"`
		Env map[string]string `yaml:"env"`
	} `yaml:"steps"`
}

func graphEvents(w graphWorkflow) (map[string]bool, error) {
	if w.On.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("qualification events must be explicit")
	}
	result := map[string]bool{}
	for i := 0; i < len(w.On.Content); i += 2 {
		result[w.On.Content[i].Value] = true
	}
	return result, nil
}
func graphNeeds(n yaml.Node) ([]string, error) {
	switch n.Kind {
	case 0:
		return nil, nil
	case yaml.ScalarNode:
		return []string{n.Value}, nil
	case yaml.SequenceNode:
		var result []string
		if err := n.Decode(&result); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, fmt.Errorf("invalid qualification dependencies")
	}
}

// QualificationGraph prevents workflow consolidation from silently omitting a
// family, retaining duplicate change triggers, or accepting a skipped child.
// Callers supply the reviewed complete family inventory, independently of YAML.
func QualificationGraph(source fs.FS, entry, gate string, families []string) error {
	read := func(name string) (graphWorkflow, error) {
		var w graphWorkflow
		b, err := fs.ReadFile(source, name)
		if err != nil {
			return w, err
		}
		if err = yaml.Unmarshal(b, &w); err != nil {
			return w, err
		}
		if len(w.Jobs) == 0 {
			return w, fmt.Errorf("empty qualification workflow %s", name)
		}
		return w, nil
	}
	root, err := read(entry)
	if err != nil {
		return err
	}
	events, err := graphEvents(root)
	if err != nil {
		return err
	}
	if !events["pull_request"] || !events["push"] {
		return fmt.Errorf("missing qualification event entry point")
	}
	wanted := map[string]bool{}
	for _, name := range families {
		if !fs.ValidPath(name) || wanted[name] || name == entry {
			return fmt.Errorf("invalid or duplicate qualification family %s", name)
		}
		wanted[name] = true
		child, err := read(name)
		if err != nil {
			return err
		}
		on, err := graphEvents(child)
		if err != nil {
			return err
		}
		if !on["workflow_call"] || on["push"] || on["pull_request"] {
			return fmt.Errorf("missing reusable family or duplicate change trigger %s", name)
		}
	}
	if len(wanted) == 0 {
		return fmt.Errorf("empty qualification family inventory")
	}
	seen := map[string]bool{}
	for _, job := range root.Jobs {
		if !strings.HasPrefix(job.Uses, "./.github/workflows/") {
			continue
		}
		name := strings.TrimPrefix(job.Uses, "./")
		if !wanted[name] || seen[name] || job.If != "" {
			return fmt.Errorf("unknown duplicate or conditional qualification family %s", name)
		}
		seen[name] = true
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("omitted qualification family")
	}
	completion, ok := root.Jobs[gate]
	if !ok || completion.If != "always()" {
		return fmt.Errorf("missing unconditional qualification completion gate")
	}
	needs, err := graphNeeds(completion.Needs)
	if err != nil {
		return err
	}
	if len(needs) != len(root.Jobs)-1 {
		return fmt.Errorf("incomplete qualification completion dependencies")
	}
	unique := map[string]bool{}
	for _, name := range needs {
		if _, ok := root.Jobs[name]; !ok || name == gate || unique[name] {
			return fmt.Errorf("invalid qualification completion dependency %s", name)
		}
		unique[name] = true
	}
	for _, step := range completion.Steps {
		if step.Env["RESULTS"] == "${{ toJSON(needs) }}" && strings.Contains(step.Run, `jq -e 'all(.[]; .result == "success")'`) {
			return nil
		}
	}
	return fmt.Errorf("completion gate does not reject skipped failed or cancelled prerequisites")
}
