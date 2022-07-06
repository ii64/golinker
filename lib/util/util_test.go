package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunk(t *testing.T) {
	exp := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	mb := make([]int, 64)
	for i := range mb {
		mb[i] = i % 16
	}
	for _, b := range Chunk(mb, 16) {
		assert.Equal(t, exp, b)
	}

}
