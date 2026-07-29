package help

import (
	"regexp"
	"strings"
	"testing"
)

// The disclaimer tells people to read these. Somebody running the exe has no
// repository, so if they are not in the binary the instruction is worthless.
func TestBothDocumentsAreEmbedded(t *testing.T) {
	docs := Docs()
	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}
	want := map[string]bool{"limits": false, "roadmap": false}
	for _, d := range docs {
		if _, ok := want[d.ID]; !ok {
			t.Errorf("unexpected document %q", d.ID)
			continue
		}
		want[d.ID] = true
		if len(d.Markdown) < 1000 {
			t.Errorf("%s: only %d bytes — is the file really embedded?", d.ID, len(d.Markdown))
		}
		if !strings.HasPrefix(d.Title, "NiteWatch") {
			t.Errorf("%s: title %q should come from the document's own heading", d.ID, d.Title)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("document %q is missing", id)
		}
	}
}

// The roadmap's job is to say where this is going AND what it will never do.
// Losing the second half would turn a commitment into a vague promise.
func TestRoadmapStatesWhatIsNeverComing(t *testing.T) {
	r := Roadmap()
	for _, needle := range []string{
		"No kernel driver", "No automatic response", "Windows only",
		"No LLM in the alert path", "threattape@gmail.com",
	} {
		if !strings.Contains(r, needle) {
			t.Errorf("roadmap no longer states %q", needle)
		}
	}
	for _, section := range []string{"## Built and working", "## Next", "## Later", "## Never"} {
		if !strings.Contains(r, section) {
			t.Errorf("roadmap is missing the %q section", section)
		}
	}
}

// A title is read from the first heading so a panel cannot drift from the
// document it displays.
func TestTitleComesFromTheHeading(t *testing.T) {
	if got := titleOf("# A Heading\nbody", "fallback"); got != "A Heading" {
		t.Errorf("titleOf = %q", got)
	}
	if got := titleOf("no heading here", "fallback"); got != "fallback" {
		t.Errorf("titleOf without a heading = %q, want the fallback", got)
	}
}

// Anything these documents point at has to be reachable by somebody holding
// only the executable.
//
// A guard against a specific repeated mistake, not a style rule. The documents
// were written inside the repository, where "see docs/feed-licensing.md" reads
// as helpful; to the person they are FOR it is a dead end — they have an exe
// and no repository, and the repository is private, so finding it would not
// help either. A pointer the reader cannot follow is worse than no pointer,
// because it implies the real answer is being withheld.
//
// The same drift left the disclaimer saying the known bugs are "listed under
// Limits in the header" after that button had been renamed to About. Signposts
// rot silently, because nothing compiles them.
func TestDocsDoNotPointAtThingsAUserCannotOpen(t *testing.T) {
	// Backticked spans only: prose naming a concept is fine, but a path in code
	// formatting reads as something to go and open.
	code := regexp.MustCompile("`([^`]+)`")
	unreachable := []struct {
		what  string
		match func(string) bool
	}{
		{"a repository path", func(s string) bool {
			return strings.Contains(s, "docs/") || strings.Contains(s, "internal/")
		}},
		{"a source or plan file", func(s string) bool {
			for _, ext := range []string{".md", ".go", ".jsonl", ".yaml", ".yml"} {
				if strings.HasSuffix(s, ext) {
					return true
				}
			}
			return false
		}},
		{"a Go test name", regexp.MustCompile(`^Test[A-Z]`).MatchString},
	}

	for _, d := range Docs() {
		for _, m := range code.FindAllStringSubmatch(d.Markdown, -1) {
			span := strings.TrimSpace(m[1])
			for _, u := range unreachable {
				if u.match(span) {
					t.Errorf("%s references %s: %q\n"+
						"Somebody running the exe cannot open that. State what it says "+
						"inline, or point at threattape@gmail.com instead.", d.ID, u.what, span)
				}
			}
		}
	}
}

// Both documents have to leave a way back to a human. They are the two a person
// reads when something has gone wrong in a pre-release tool.
func TestDocsCarryTheContactAddress(t *testing.T) {
	for _, d := range Docs() {
		if !strings.Contains(d.Markdown, "threattape@gmail.com") {
			t.Errorf("%s: no contact address, so a reader with a problem has nowhere to go", d.ID)
		}
	}
}
