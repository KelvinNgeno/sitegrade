package audit

import "testing"

func TestScore(t *testing.T) {
	if got := Score(nil); got != 100 {
		t.Errorf("empty score = %d, want 100", got)
	}

	findings := []Finding{
		{Category: CatHeaders, Penalty: 20},
		{Category: CatTLS, Penalty: 15},
	}
	if got := Score(findings); got != 65 {
		t.Errorf("score = %d, want 65", got)
	}

	huge := []Finding{{Category: CatTLS, Penalty: 500}}
	if got := Score(huge); got != 0 {
		t.Errorf("score = %d, want 0 (floored)", got)
	}
}

func TestScoreCapsCookiePenalties(t *testing.T) {
	var findings []Finding
	for i := 0; i < 4; i++ {
		findings = append(findings, Finding{Category: CatCookies, Penalty: 9})
	}
	// 36 raw penalty, capped at 15.
	if got := Score(findings); got != 85 {
		t.Errorf("score = %d, want 85", got)
	}
}

func TestGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "A+"}, {95, "A"}, {90, "A"}, {85, "B"}, {80, "B"},
		{75, "C"}, {70, "C"}, {65, "D"}, {60, "D"}, {59, "F"}, {0, "F"},
	}
	for _, tc := range tests {
		if got := Grade(tc.score, nil); got != tc.want {
			t.Errorf("Grade(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestCriticalFailureForcesF(t *testing.T) {
	findings := []Finding{{Category: CatTLS, Status: StatusFail, Critical: true, Penalty: 25}}
	if got := Grade(100, findings); got != "F" {
		t.Errorf("grade = %s, want F", got)
	}

	notFailing := []Finding{{Category: CatTLS, Status: StatusPass, Critical: true}}
	if got := Grade(100, notFailing); got != "A+" {
		t.Errorf("grade = %s, want A+ (critical flag on a passing check)", got)
	}
}

func TestGradeAtLeast(t *testing.T) {
	tests := []struct {
		grade, min string
		want       bool
	}{
		{"A+", "A", true}, {"A", "A", true}, {"B", "A", false},
		{"B", "B", true}, {"F", "D", false}, {"C", "F", true},
		{"X", "A", false}, {"A", "X", false},
	}
	for _, tc := range tests {
		if got := GradeAtLeast(tc.grade, tc.min); got != tc.want {
			t.Errorf("GradeAtLeast(%s, %s) = %v, want %v", tc.grade, tc.min, got, tc.want)
		}
	}
}
