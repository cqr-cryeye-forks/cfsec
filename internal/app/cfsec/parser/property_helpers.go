package parser

import (
	"strings"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/cftypes"
	"github.com/aquasecurity/defsec/types"
)

func (p *Property) IsNil() bool {
	return p == nil || p.Inner.Value == nil
}

func (p *Property) IsNotNil() bool {
	return !p.IsNil()
}

func (p *Property) IsString() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		return p.resolveValue().IsString()
	}
	return p.Inner.Type == cftypes.String
}

func (p *Property) IsNotString() bool {
	return !p.IsString()
}

func (p *Property) IsInt() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		return p.resolveValue().IsInt()
	}
	return p.Inner.Type == cftypes.Int
}

func (p *Property) IsNotInt() bool {
	return !p.IsInt()
}

func (p *Property) IsMap() bool {
	if p.IsNil() {
		return false
	}
	return p.Inner.Type == cftypes.Map
}

func (p *Property) IsNotMap() bool {
	return !p.IsMap()
}

func (p *Property) IsList() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		return p.resolveValue().IsList()
	}
	return p.Inner.Type == cftypes.List
}

func (p *Property) IsNotList() bool {
	return !p.IsList()
}

func (p *Property) IsBool() bool {
	if p.IsNil() {
		return false
	}
	if p.isFunction() {
		return p.resolveValue().IsBool()
	}
	return p.Inner.Type == cftypes.Bool
}

func (p *Property) IsNotBool() bool {
	return !p.IsBool()
}

func (p *Property) AsString() string {
	if p.isFunction() {
		return p.resolveValue().AsString()
	}
	return p.Inner.Value.(string)
}

func (p *Property) AsStringValue() types.StringValue {
	return types.StringExplicit(p.AsString(), p.Metadata())
}

func (p *Property) AsInt() int {
	if p.isFunction() {
		return p.resolveValue().AsInt()
	}
	return p.Inner.Value.(int)
}

func (p *Property) AsIntValue() types.IntValue {
	return types.IntExplicit(p.AsInt(), p.Metadata())
}

func (p *Property) AsBool() bool {
	if p.isFunction() {
		return p.resolveValue().AsBool()
	}
	return p.Inner.Value.(bool)
}

func (p *Property) AsBoolValue() types.BoolValue {
	return types.Bool(p.AsBool(), p.Metadata())
}

func (p *Property) AsMap() map[string]*Property {
	return p.Inner.Value.(map[string]*Property)
}

func (p *Property) AsList() []*Property {
	return p.Inner.Value.([]*Property)
}

func (p *Property) EqualTo(checkValue interface{}, equalityOptions ...EqualityOptions) bool {
	var ignoreCase bool
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}

	if p.IsNil() {
		return checkValue == nil
	}

	if p.RawValue() == checkValue {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		if ignoreCase {
			return strings.EqualFold(p.AsString(), checkValue.(string))
		}
		return p.AsString() == checkValue.(string)
	default:
		return false
	}
}

func (p *Property) IsTrue() bool {
	if p.IsNil() || !p.IsBool() {
		return false
	}

	return p.AsBool()
}

func (p *Property) IsEmpty() bool {

	if p.IsNil() {
		return true
	}

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
}

func (p *Property) Contains(checkVal interface{}) bool {
	if p == nil || p.IsNil() {
		return false
	}

	switch p.Type() {
	case cftypes.List:
		for _, p := range p.AsList() {
			if p.EqualTo(checkVal) {
				return true
			}
		}
	case cftypes.Map:
		for key := range p.AsMap() {
			if key == checkVal.(string) {
				return true
			}
		}
	case cftypes.String:
		return strings.Contains(p.AsString(), checkVal.(string))
	}
	return false
}
