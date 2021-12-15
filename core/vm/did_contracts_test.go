package vm

import "testing"

func Test_isCtrlEqual(t *testing.T) {
	type args struct {
		newCtrl interface{}
		oldCtrl interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		//// TODO: Add test cases.
		{
			"array equal",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),interface{}([]interface{}{"i1", "i2", "i3"})},
			true,
		},
		{
			"len equal array not equal",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),interface{}([]interface{}{"i1", "i2", "i4"})},
			false,
		},
		{
			"len not equal array ",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),interface{}([]interface{}{"i1", "i2"})},
			false,
		},
		{
			" array interface slice and byte slice  ",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),interface{}([]string{"i1", "i2"})},
			false,
		},
		{
			"array equal unsorted ",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),interface{}([]interface{}{"i3", "i2", "i1"})},
			true,
		},
		{
			"string equal ",
			args{interface{}("i1"),interface{}("i1")},
			true,
		},
		{
			"string not equal ",
			args{interface{}("i1"),interface{}("i2")},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCtrlEqual(tt.args.newCtrl, tt.args.oldCtrl); got != tt.want {
				t.Errorf("isCtrlEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_haveCtrl(t *testing.T) {
	type args struct {
		docCtrl    interface{}
		controller string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
		{
			"doc array controller str  ",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),"i3"},
			true,
		},
		{
			"doc array, controller str  include",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),"i3"},
			true,
		},
		{
			"doc array, controller str  exlude",
			args{interface{}([]interface{}{"i1", "i2", "i3"}),"i4"},
			false,
		},
		{
			"doc empty array, controller str  exlude",
			args{interface{}([]interface{}{}),"i4"},
			false,
		},
		{
			"doc array, controller str  same",
			args{interface{}("i1"),"i1"},
			true,
		},
		{
			"doc array, controller str  not same",
			args{interface{}("i1"),"i4"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HaveCtrl(tt.args.docCtrl, tt.args.controller); got != tt.want {
				t.Errorf("HaveCtrl() = %v, want %v", got, tt.want)
			}
		})
	}
}