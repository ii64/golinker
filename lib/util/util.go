package util

// Chunk
func Chunk[T any](collection []T, size int) [][]T {
	ret := make([][]T, 0, len(collection)/size+1)
	for i := 0; i < len(collection); i = i + size {
		var bound int
		if i+size < len(collection) {
			bound = i + size
		} else {
			bound = len(collection)
		}
		ret = append(ret, collection[i:bound])
	}
	return ret
}
