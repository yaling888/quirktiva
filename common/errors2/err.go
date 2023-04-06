package errors2

import (
	"fmt"
	"reflect"
)

func New(err error) error {
	return NewSplit(", ", err)
}

func Cause(err error) error {
	return NewSplit(", cause: ", err)
}

func Join(errs ...error) error {
	return JoinSplit(", ", errs...)
}

func NewSplit(split string, err error) error {
	if err == nil {
		return nil
	}

	if reflect.TypeOf(err) == wrapErrorsType {
		return err
	}

	if x, ok := err.(interface{ Unwrap() []error }); ok {
		if x == nil {
			return err
		}
		u := x.Unwrap()
		e := &joinError{
			split: split,
			errs:  make([]error, 0, len(u)<<2),
		}
		for _, m := range u {
			if m == nil {
				continue
			}
			if reflect.TypeOf(m) == wrapErrorsType {
				e.errs = append(e.errs, m)
				continue
			}
			n := NewSplit(split, m)
			if n == nil {
				continue
			}
			if y, ok1 := n.(interface{ Unwrap() []error }); ok1 {
				if y == nil {
					e.errs = append(e.errs, n)
					continue
				}
				v := y.Unwrap()
				for _, z := range v {
					if z == nil {
						continue
					}
					e.errs = append(e.errs, z)
				}
				continue
			}
			e.errs = append(e.errs, n)
		}
		return e
	}

	return err
}

func JoinSplit(split string, errs ...error) error {
	n := 0
	for _, err := range errs {
		if err != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	e := &joinError{
		errs:  make([]error, 0, n),
		split: split,
	}
	for _, err := range errs {
		if err != nil {
			e.errs = append(e.errs, err)
		}
	}
	return e
}

type joinError struct {
	errs  []error
	split string
}

func (e *joinError) Error() string {
	var b []byte
	for i, err := range e.errs {
		if i > 0 {
			b = append(b, e.split...)
		}
		b = append(b, err.Error()...)
	}
	return string(b)
}

func (e *joinError) Unwrap() []error {
	return e.errs
}

var wrapErrorsType = reflect.TypeOf(fmt.Errorf("%w%w", nil, nil))
