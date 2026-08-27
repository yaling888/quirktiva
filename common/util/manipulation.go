package util

import (
	"iter"
)

func ValuesFunc[Slice ~[]E, E any](s Slice, f func(E) E) iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, v := range s {
			if !yield(f(v)) {
				return
			}
		}
	}
}

func ValuesFuncMap[Slice ~[]E, E any, R any](s Slice, f func(E) R) iter.Seq[R] {
	return func(yield func(R) bool) {
		for _, v := range s {
			if !yield(f(v)) {
				return
			}
		}
	}
}

func ValuesFuncSeq[E any](s iter.Seq[E], f func(E) E) iter.Seq[E] {
	return func(yield func(E) bool) {
		for v := range s {
			if !yield(f(v)) {
				return
			}
		}
	}
}

func FilterFunc[Slice ~[]E, E any](s Slice, f func(E) bool) iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, v := range s {
			if f(v) {
				if !yield(v) {
					return
				}
			}
		}
	}
}

func FilterFuncSeq[E any](s iter.Seq[E], f func(E) bool) iter.Seq[E] {
	return func(yield func(E) bool) {
		for v := range s {
			if f(v) {
				if !yield(v) {
					return
				}
			}
		}
	}
}

func ValuesNonZero[Slice ~[]E, E comparable](s Slice) iter.Seq[E] {
	var zero E
	return FilterFunc(s, func(s E) bool { return s != zero })
}

func ValuesNonZeroSeq[E comparable](s iter.Seq[E]) iter.Seq[E] {
	var zero E
	return FilterFuncSeq(s, func(s E) bool { return s != zero })
}

func MapValuesFuncMap[Map ~map[K]V, K comparable, K2 comparable, V any, V2 any](m Map, f func(K, V) (K2, V2)) iter.Seq2[K2, V2] {
	return func(yield func(K2, V2) bool) {
		for k, v := range m {
			if !yield(f(k, v)) {
				return
			}
		}
	}
}

func MapValuesFuncMapSeq[K comparable, K2 comparable, V any, V2 any](m iter.Seq2[K, V], f func(K, V) (K2, V2)) iter.Seq2[K2, V2] {
	return func(yield func(K2, V2) bool) {
		for k, v := range m {
			if !yield(f(k, v)) {
				return
			}
		}
	}
}

func EmptyOr[T comparable](v T, def T) T {
	ret, _ := Coalesce(v, def)
	return ret
}

func Coalesce[T comparable](values ...T) (T, bool) {
	var zero T

	for i := range values {
		if values[i] != zero {
			return values[i], true
		}
	}

	return zero, false
}

func FromPtrOr[T any](x *T, fallback T) T {
	if x == nil {
		return fallback
	}

	return *x
}
