package help

import (
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
