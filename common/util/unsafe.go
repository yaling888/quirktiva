package util

import (
	"fmt"
	"reflect"
	"unsafe"
)

func SetUnexportedField(targetField reflect.Value, value any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if er, ok := r.(error); ok {
				err = er
			} else {
				err = fmt.Errorf("%v", r)
			}
		}
	}()
	if !targetField.IsValid() {
		return fmt.Errorf("target field %s is invalid", targetField.Type().String())
	}
	if !targetField.CanSet() {
		setSetCanSetFlag(&targetField)
	}
	switch v := value.(type) {
	case *reflect.Value:
		if !v.Type().AssignableTo(targetField.Type()) {
			return fmt.Errorf("type %v can not assignable to type %v", v.Kind(), targetField.Kind())
		}
		if !v.CanSet() {
			setSetCanSetFlag(v)
		}
		targetField.Set(*v)
	case reflect.Value:
		if !v.Type().AssignableTo(targetField.Type()) {
			return fmt.Errorf("type %v can not assignable to type %v", v.Kind(), targetField.Kind())
		}
		if !v.CanSet() {
			setSetCanSetFlag(&v)
		}
		targetField.Set(v)
	default:
		if v == nil && !targetField.IsZero() {
			targetField.SetZero()
			return nil
		}
		vv := reflect.ValueOf(v)
		if !vv.Type().AssignableTo(targetField.Type()) {
			return fmt.Errorf("type %v can not assignable to type %v", vv.Kind(), targetField.Kind())
		}
		targetField.Set(vv)
	}
	return nil
}

func setSetCanSetFlag(field *reflect.Value) {
	const (
		flagAddr uintptr = 1 << 8
		flagRO   uintptr = 96
	)
	flag := reflect.ValueOf(field).Elem().FieldByName("flag")
	f := (*uintptr)(unsafe.Pointer(flag.UnsafeAddr()))
	if *f&flagRO != 0 {
		*f &= ^flagRO
	}
	if *f&flagAddr == 0 {
		*f |= flagAddr
	}
}
