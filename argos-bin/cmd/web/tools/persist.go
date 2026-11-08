package tools

// publishFindings returns scanner output for agent review.
func (e *Env) publishFindings(res map[string]interface{}, findings []Finding) {
	res["findings"] = findingsToMaps(findings)
}
