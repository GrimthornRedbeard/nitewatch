// Package help carries the documents that must travel with the binary.
//
// The startup disclaimer tells the user to read the known-limitations document.
// Somebody running nitewatch.exe has no repository to read it in, so pointing
// at a path on disk was pointing at nothing. It is compiled in and served to the
// dashboard instead.
//
// The file lives HERE, not in docs/, and is not copied at build time. go:embed
// cannot reach outside its module and the module root is agent/, which put
// docs/ out of reach — but the deciding argument is the one already recorded in
// rules/embed.go: a duplicate kept in step by a build step silently went stale
// once before. One copy, one truth.
package help

import (
	_ "embed"
	"strings"
)

//go:embed known-limitations.md
var knownLimitations string

//go:embed roadmap.md
var roadmap string

// Doc is one embedded document, ready to render.
type Doc struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Markdown string `json:"markdown"`
}

// Docs returns everything that ships with the binary, in reading order:
// what it cannot do, then where it is going. Both are things a person deciding
// whether to trust this deserves before they decide.
func Docs() []Doc {
	return []Doc{
		{ID: "limits", Title: titleOf(knownLimitations, "Known limitations"), Markdown: knownLimitations},
		{ID: "roadmap", Title: titleOf(roadmap, "Roadmap"), Markdown: roadmap},
	}
}

// KnownLimitations is the honest account of what the software does not do.
func KnownLimitations() string { return knownLimitations }

// Roadmap is what is built, what is coming, and what never is.
func Roadmap() string { return roadmap }

// Title is the known-limitations heading, kept for callers that only want that
// one.
func Title() string { return titleOf(knownLimitations, "Known limitations") }

// titleOf reads a document's first heading, so a panel's title cannot drift
// from the document it is showing.
func titleOf(md, fallback string) string {
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return fallback
}
