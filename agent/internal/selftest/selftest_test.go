package selftest

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/threattape/nitewatch/agent/internal/detect"
	"github.com/threattape/nitewatch/agent/internal/intel"
	"github.com/threattape/nitewatch/agent/internal/ledger"
	"github.com/threattape/nitewatch/agent/internal/rules"
	rulesdata "github.com/threattape/nitewatch/agent/rules"
)

type capture struct{ alerts []ledger.Alert }

func (c *capture) RecordAlert(a ledger.Alert) (bool, error) {
	c.alerts = append(c.alerts, a)
	return true, nil
}

func engine(t *testing.T) (*detect.Engine, *intel.Store, *rules.Set) {
	t.Helper()
	// The real shipped packs, embedded exactly as the binary ships them. A
	// broken pack must fail here rather than in front of a user.
	entries, err := rulesdata.Packs.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var packs []*rules.Pack
	for _, ent := range entries {
		if filepath.Ext(ent.Name()) != ".yaml" {
			continue
		}
		data, err := rulesdata.Packs.ReadFile(ent.Name())
		if err != nil {
			t.Fatal(err)
		}
		pk, err := rules.LoadPack(data)
		if err != nil {
			t.Fatalf("shipped pack %s does not load: %v", ent.Name(), err)
		}
		packs = append(packs, pk)
	}
	set := rules.NewSet(packs...)
	feeds := intel.New()
	return detect.New(set, feeds), feeds, set
}

// The whole point: every alert the product can raise, on demand. If a rule
// cannot be triggered by its own scenario, it will not fire in the field
// either.
func TestSelfTestFiresEveryScenario(t *testing.T) {
	e, feeds, _ := engine(t)
	var rec capture
	res, err := Run(e, feeds, &rec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("%s", Describe(res))
	}
	if len(rec.alerts) != res.Expected {
		t.Errorf("recorded %d alerts, expected %d", len(rec.alerts), res.Expected)
	}
}

// Coverage guard: a new rule added to a shipped pack without a scenario here is
// a rule nobody can demonstrate. This is the test that makes the suite stay
// complete rather than drift.
func TestEveryShippedRuleHasAScenario(t *testing.T) {
	_, _, set := engine(t)
	covered := map[string]bool{}
	for _, sc := range Explain(time.Now()) {
		covered[sc.RuleID] = true
	}
	for _, r := range set.All() {
		if !covered[r.ID] {
			t.Errorf("rule %q has no self-test scenario — add one to selftest.go", r.ID)
		}
	}
}

// Nothing the drill produces may look like a real address or a real program.
func TestDrillUsesOnlyReservedNames(t *testing.T) {
	e, feeds, _ := engine(t)
	var rec capture
	if _, err := Run(e, feeds, &rec, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, a := range rec.alerts {
		if a.Evidence[DrillField] != true {
			t.Errorf("%s: not marked as a drill", a.RuleID)
		}
		blob := a.Title + " " + a.Narrative + " " + strings.Join(a.Playbook, " ")
		if ip, _ := a.Evidence["RemoteIP"].(string); ip != "" &&
			!strings.HasPrefix(ip, "203.0.113.") && !strings.HasPrefix(ip, "2001:db8:") {
			t.Errorf("%s: address %q is not a reserved documentation address", a.RuleID, ip)
		}
		if strings.Contains(blob, `C:\Users\`) && !strings.Contains(blob, "SelfTest") {
			t.Errorf("%s: names a real-looking user path:\n%s", a.RuleID, blob)
		}
	}
}

// Every scenario must explain, in plain words, what the computer would actually
// be doing — that is the question a person is really asking.
func TestEveryScenarioExplainsItself(t *testing.T) {
	for _, sc := range Explain(time.Now()) {
		if sc.Title == "" || sc.Real == "" || sc.Why == "" {
			t.Errorf("%s: incomplete explanation", sc.RuleID)
		}
		if len(sc.Real) < 40 {
			t.Errorf("%s: 'what is actually happening' is too thin: %q", sc.RuleID, sc.Real)
		}
	}
}

// A feature the user switched off is not a fault. Reporting it as one sends
// somebody chasing a failure they cannot fix.
func TestFeedScenarioIsSkippedNotFailedWhenFeedsAreOff(t *testing.T) {
	e, _, _ := engine(t)
	var rec capture
	res, err := Run(e, nil, &rec, time.Now()) // no feed store: --no-feeds
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("with feeds off the run should still be OK, got: %s", Describe(res))
	}
	if res.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", res.Skipped)
	}
	var found bool
	for _, sc := range res.Scenarios {
		if sc.RuleID == "c2-feed-flagged-connection" {
			found = true
			if !sc.Skipped || sc.Skip == "" {
				t.Error("the feed scenario should be marked skipped, with a reason")
			}
			if sc.Fired {
				t.Error("it cannot have fired with no feed store")
			}
		}
	}
	if !found {
		t.Error("feed scenario missing from the result entirely")
	}
}
