package audit

// categoryCaps limit how much one noisy category can cost. A site with many
// cookies should not be graded down to zero for cookie flags alone.
var categoryCaps = map[string]int{CatCookies: 15}

// gradeOrder runs from best to worst.
var gradeOrder = []string{"A+", "A", "B", "C", "D", "F"}

// Score starts at 100 and subtracts each finding's penalty.
func Score(findings []Finding) int {
	perCategory := make(map[string]int)
	for _, f := range findings {
		perCategory[f.Category] += f.Penalty
	}

	total := 0
	for category, penalty := range perCategory {
		if limit, ok := categoryCaps[category]; ok && penalty > limit {
			penalty = limit
		}
		total += penalty
	}

	score := 100 - total
	if score < 0 {
		score = 0
	}
	return score
}

// Grade converts a score to a letter. Any critical failure (no HTTPS, an
// untrusted or expired certificate, no modern TLS) forces an F.
func Grade(score int, findings []Finding) string {
	for _, f := range findings {
		if f.Critical && f.Status == StatusFail {
			return "F"
		}
	}
	switch {
	case score >= 100:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// GradeRank returns the position of a grade (0 is best), or -1 if unknown.
func GradeRank(grade string) int {
	for i, g := range gradeOrder {
		if g == grade {
			return i
		}
	}
	return -1
}

// GradeAtLeast reports whether grade is as good as or better than minGrade.
func GradeAtLeast(grade, minGrade string) bool {
	g, m := GradeRank(grade), GradeRank(minGrade)
	return g >= 0 && m >= 0 && g <= m
}
