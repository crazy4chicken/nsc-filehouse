package iamfixture

import (
	"fmt"
	"strings"
)

// evalContext carries the values a fixture condition is allowed to inspect.
type evalContext struct {
	SubjectID string
	OwnerID   string
	TeamID    string
	Attrs     map[string]any
}

// condition is a compiled fixture condition.
type condition struct {
	source string
	match  func(evalContext) (bool, error)
}

// parseCondition compiles a condition from the restricted grammar the fixture
// supports:
//
//	expr      := term ( "||" term )*
//	term      := atom ( "&&" atom )*
//	atom      := ( "subject.id" | "resource.owner_id" | "resource.team_id" ) "==" string
//	           | "resource.attrs[" string "]" "==" string
//	string    := '"' ( char | '\"' | '\\' )* '"'
//
// Anything outside this grammar is rejected; callers must then fail closed.
// An empty condition matches unconditionally.
func parseCondition(source string) (*condition, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return &condition{}, nil
	}
	tokens, err := tokenizeCondition(source)
	if err != nil {
		return nil, err
	}
	parser := &conditionParser{tokens: tokens}
	match, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if token := parser.peek(); token.kind != condEOF {
		return nil, fmt.Errorf("condition: unexpected %q", token.text)
	}
	return &condition{source: source, match: match}, nil
}

// eval evaluates the condition against ctx. A nil condition matches; every
// parse-time or evaluation-time problem is returned as an error so the caller
// can deny the request.
func (c *condition) eval(ctx evalContext) (bool, error) {
	if c == nil || c.match == nil {
		return true, nil
	}
	return c.match(ctx)
}

type condTokenKind int

const (
	condEOF condTokenKind = iota
	condIdent
	condString
	condEq
	condAnd
	condOr
	condLBracket
	condRBracket
)

type condToken struct {
	kind condTokenKind
	text string
}

// tokenizeCondition splits a condition into the tokens of the restricted grammar.
func tokenizeCondition(source string) ([]condToken, error) {
	tokens := make([]condToken, 0, 8)
	for i := 0; i < len(source); {
		char := source[i]
		switch {
		case char == ' ' || char == '\t' || char == '\n' || char == '\r':
			i++
		case char == '&':
			if i+1 >= len(source) || source[i+1] != '&' {
				return nil, fmt.Errorf("condition: unsupported operator %q", "&")
			}
			tokens = append(tokens, condToken{kind: condAnd, text: "&&"})
			i += 2
		case char == '|':
			if i+1 >= len(source) || source[i+1] != '|' {
				return nil, fmt.Errorf("condition: unsupported operator %q", "|")
			}
			tokens = append(tokens, condToken{kind: condOr, text: "||"})
			i += 2
		case char == '=':
			if i+1 >= len(source) || source[i+1] != '=' {
				return nil, fmt.Errorf("condition: unsupported operator %q", "=")
			}
			tokens = append(tokens, condToken{kind: condEq, text: "=="})
			i += 2
		case char == '[':
			tokens = append(tokens, condToken{kind: condLBracket, text: "["})
			i++
		case char == ']':
			tokens = append(tokens, condToken{kind: condRBracket, text: "]"})
			i++
		case char == '"':
			value, next, err := readConditionString(source, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, condToken{kind: condString, text: value})
			i = next
		case isConditionIdentStart(char):
			start := i
			for i < len(source) && isConditionIdentPart(source[i]) {
				i++
			}
			tokens = append(tokens, condToken{kind: condIdent, text: source[start:i]})
		default:
			return nil, fmt.Errorf("condition: unsupported character %q", string(char))
		}
	}
	return append(tokens, condToken{kind: condEOF}), nil
}

func isConditionIdentStart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_'
}

func isConditionIdentPart(char byte) bool {
	return isConditionIdentStart(char) || (char >= '0' && char <= '9') || char == '.'
}

// readConditionString reads a double quoted literal starting at start.
func readConditionString(source string, start int) (string, int, error) {
	var builder strings.Builder
	for i := start + 1; i < len(source); i++ {
		switch source[i] {
		case '"':
			return builder.String(), i + 1, nil
		case '\\':
			if i+1 >= len(source) {
				return "", 0, fmt.Errorf("condition: trailing escape sequence")
			}
			switch source[i+1] {
			case '"', '\\':
				builder.WriteByte(source[i+1])
				i++
			default:
				return "", 0, fmt.Errorf("condition: unsupported escape %q", "\\"+string(source[i+1]))
			}
		default:
			builder.WriteByte(source[i])
		}
	}
	return "", 0, fmt.Errorf("condition: unterminated string literal")
}

type conditionParser struct {
	tokens []condToken
	pos    int
}

func (p *conditionParser) peek() condToken {
	if p.pos >= len(p.tokens) {
		return condToken{kind: condEOF}
	}
	return p.tokens[p.pos]
}

func (p *conditionParser) next() condToken {
	token := p.peek()
	if token.kind != condEOF {
		p.pos++
	}
	return token
}

func (p *conditionParser) parseOr() (func(evalContext) (bool, error), error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == condOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		previous, next := left, right
		left = func(ctx evalContext) (bool, error) {
			matched, err := previous(ctx)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
			return next(ctx)
		}
	}
	return left, nil
}

func (p *conditionParser) parseAnd() (func(evalContext) (bool, error), error) {
	left, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == condAnd {
		p.next()
		right, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		previous, next := left, right
		left = func(ctx evalContext) (bool, error) {
			matched, err := previous(ctx)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
			return next(ctx)
		}
	}
	return left, nil
}

func (p *conditionParser) parseAtom() (func(evalContext) (bool, error), error) {
	token := p.next()
	if token.kind != condIdent {
		return nil, fmt.Errorf("condition: expected a field reference, found %q", token.text)
	}
	if token.text == "resource.attrs" {
		return p.parseAttrComparison()
	}
	var read func(evalContext) string
	switch token.text {
	case "subject.id":
		read = func(ctx evalContext) string { return ctx.SubjectID }
	case "resource.owner_id":
		read = func(ctx evalContext) string { return ctx.OwnerID }
	case "resource.team_id":
		read = func(ctx evalContext) string { return ctx.TeamID }
	default:
		return nil, fmt.Errorf("condition: unsupported field %q", token.text)
	}
	if operator := p.next(); operator.kind != condEq {
		return nil, fmt.Errorf("condition: expected == after %q, found %q", token.text, operator.text)
	}
	value := p.next()
	if value.kind != condString {
		return nil, fmt.Errorf("condition: expected a string literal for %q, found %q", token.text, value.text)
	}
	want := value.text
	return func(ctx evalContext) (bool, error) {
		return read(ctx) == want, nil
	}, nil
}

func (p *conditionParser) parseAttrComparison() (func(evalContext) (bool, error), error) {
	if token := p.next(); token.kind != condLBracket {
		return nil, fmt.Errorf("condition: expected [ after resource.attrs, found %q", token.text)
	}
	key := p.next()
	if key.kind != condString {
		return nil, fmt.Errorf("condition: expected an attribute name string, found %q", key.text)
	}
	if token := p.next(); token.kind != condRBracket {
		return nil, fmt.Errorf("condition: expected ] after the attribute name, found %q", token.text)
	}
	if token := p.next(); token.kind != condEq {
		return nil, fmt.Errorf("condition: expected == after the attribute, found %q", token.text)
	}
	value := p.next()
	if value.kind != condString {
		return nil, fmt.Errorf("condition: expected a string literal for attribute %q, found %q", key.text, value.text)
	}
	attrName, want := key.text, value.text
	return func(ctx evalContext) (bool, error) {
		raw, ok := ctx.Attrs[attrName]
		if !ok {
			return false, fmt.Errorf("condition: attribute %q is missing", attrName)
		}
		actual, ok := raw.(string)
		if !ok {
			return false, fmt.Errorf("condition: attribute %q is not a string", attrName)
		}
		return actual == want, nil
	}, nil
}
