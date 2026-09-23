package entropy

import "math"

func Shannon(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	result := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		result -= p * math.Log2(p)
	}
	return result
}
