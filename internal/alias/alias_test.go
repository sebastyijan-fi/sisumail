package alias

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	m := NewManager()

	tests := []struct {
		input              string
		wantLocal, wantTag string
	}{
		{"mail+shopping@niklas.sisumail.fi", "mail", "shopping"},
		{"mail@niklas.sisumail.fi", "mail", ""},
		{"user+tag+extra@domain.fi", "user", "tag+extra"},
		{"mail+@niklas.sisumail.fi", "mail", ""},
		{"+tag@niklas.sisumail.fi", "", "tag"},
		{"justlocal", "justlocal", ""},
		{"local+tag", "local", "tag"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			local, tag := m.Parse(tt.input)
			if local != tt.wantLocal {
				t.Errorf("local: got %q, want %q", local, tt.wantLocal)
			}
			if tag != tt.wantTag {
				t.Errorf("tag: got %q, want %q", tag, tt.wantTag)
			}
		})
	}
}

func TestRecordUseAndStats(t *testing.T) {
	m := NewManager()

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	m.RecordUse("shopping", "store.com", t1)
	m.RecordUse("shopping", "store.com", t2) // same domain
	m.RecordUse("shopping", "newsletter.store.com", t3)

	stats, err := m.Stats("shopping")
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if stats.UseCount != 3 {
		t.Errorf("UseCount: got %d, want 3", stats.UseCount)
	}
	if stats.UniqueSenders != 2 {
		t.Errorf("UniqueSenders: got %d, want 2", stats.UniqueSenders)
	}
	if !stats.FirstSeen.Equal(t1) {
		t.Errorf("FirstSeen: got %v, want %v", stats.FirstSeen, t1)
	}
	if !stats.LastSeen.Equal(t3) {
		t.Errorf("LastSeen: got %v, want %v", stats.LastSeen, t3)
	}
	if stats.ProbableLeak {
		t.Error("should not be leaked with 2 senders")
	}
}

func TestStatsUnknownTag(t *testing.T) {
	m := NewManager()
	stats, err := m.Stats("nonexistent")
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.UseCount != 0 {
		t.Errorf("UseCount: got %d, want 0", stats.UseCount)
	}
}

func TestDetectLeak(t *testing.T) {
	m := NewManager()
	m.LeakThreshold = 3

	now := time.Now()
	m.RecordUse("leaked", "domain1.com", now)
	m.RecordUse("leaked", "domain2.com", now)

	if m.DetectLeak("leaked") {
		t.Error("should not detect leak with 2 domains (threshold=3)")
	}

	m.RecordUse("leaked", "domain3.com", now)
	if !m.DetectLeak("leaked") {
		t.Error("should detect leak with 3 domains (threshold=3)")
	}

	m.RecordUse("leaked", "domain4.com", now)
	if !m.DetectLeak("leaked") {
		t.Error("should still detect leak with 4 domains")
	}
}

func TestDetectLeakUnknownTag(t *testing.T) {
	m := NewManager()
	if m.DetectLeak("unknown") {
		t.Error("unknown tag should not be detected as leaked")
	}
}

func TestListTags(t *testing.T) {
	m := NewManager()
	now := time.Now()

	m.RecordUse("tag1", "a.com", now)
	m.RecordUse("tag2", "b.com", now)
	m.RecordUse("tag3", "c.com", now)

	tags, err := m.ListTags()
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 3 {
		t.Fatalf("expected 3 tags, got %d", len(tags))
	}

	tagSet := map[string]bool{}
	for _, tag := range tags {
		tagSet[tag] = true
	}
	for _, want := range []string{"tag1", "tag2", "tag3"} {
		if !tagSet[want] {
			t.Errorf("missing tag: %s", want)
		}
	}
}

func TestCaseInsensitiveSenderDomain(t *testing.T) {
	m := NewManager()
	now := time.Now()

	m.RecordUse("tag", "Example.COM", now)
	m.RecordUse("tag", "example.com", now)

	stats, _ := m.Stats("tag")
	if stats.UniqueSenders != 1 {
		t.Errorf("expected 1 unique sender (case-insensitive), got %d", stats.UniqueSenders)
	}
}
