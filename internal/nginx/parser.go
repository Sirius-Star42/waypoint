// Package nginx reads nginx configuration and turns it into routes:
// which hostnames and paths are served by which upstream, directory or redirect.
package nginx

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type Directive struct {
	Name     string
	Args     []string
	Block    []*Directive
	HasBlock bool
	File     string
	Line     int
}

func (d *Directive) Pos() string { return fmt.Sprintf("%s:%d", d.File, d.Line) }

type tokenKind int

const (
	tokWord tokenKind = iota
	tokOpen
	tokClose
	tokSemi
)

type token struct {
	kind tokenKind
	text string
	line int
}

func lex(src string) ([]token, error) {
	var toks []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '{':
			toks = append(toks, token{tokOpen, "{", line})
			i++
		case c == '}':
			toks = append(toks, token{tokClose, "}", line})
			i++
		case c == ';':
			toks = append(toks, token{tokSemi, ";", line})
			i++
		case c == '"' || c == '\'':
			start := line
			q := c
			i++
			var b strings.Builder
			for {
				if i >= len(src) {
					return nil, fmt.Errorf("line %d: unterminated quote", start)
				}
				if src[i] == '\\' && i+1 < len(src) {
					if src[i+1] == q || src[i+1] == '\\' {
						b.WriteByte(src[i+1])
					} else {
						b.WriteByte('\\')
						b.WriteByte(src[i+1])
					}
					i += 2
					continue
				}
				if src[i] == q {
					i++
					break
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
				i++
			}
			toks = append(toks, token{tokWord, b.String(), start})
		default:
			var b strings.Builder
			for i < len(src) {
				c := src[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' || c == '}' {
					// "${var}" keeps its braces inside the word.
					if c == '{' && b.Len() > 0 && strings.HasSuffix(b.String(), "$") {
						for i < len(src) && src[i] != '}' {
							b.WriteByte(src[i])
							i++
						}
						if i < len(src) {
							b.WriteByte('}')
							i++
						}
						continue
					}
					break
				}
				if c == '\\' && i+1 < len(src) {
					b.WriteByte(c)
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				b.WriteByte(c)
				i++
			}
			toks = append(toks, token{tokWord, b.String(), line})
		}
	}
	return toks, nil
}

type FS interface {
	ReadFile(path string) (string, error)
	Glob(pattern string) ([]string, error)
}

type parser struct {
	fs       FS
	prefix   string
	files    []string
	seen     map[string]bool
	warnings []string
}

func (p *parser) parseFile(path string, depth int) ([]*Directive, error) {
	if depth > 20 {
		return nil, fmt.Errorf("%s: include depth limit reached", path)
	}
	src, err := p.fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !p.seen[path] {
		p.seen[path] = true
		p.files = append(p.files, path)
	}
	toks, err := lex(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pos := 0
	dirs, err := p.parseBlock(toks, &pos, path, depth, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return dirs, nil
}

func (p *parser) parseBlock(toks []token, pos *int, file string, depth int, inBlock bool) ([]*Directive, error) {
	var out []*Directive
	for *pos < len(toks) {
		t := toks[*pos]
		switch t.kind {
		case tokClose:
			if !inBlock {
				return nil, fmt.Errorf("line %d: unexpected }", t.line)
			}
			*pos++
			return out, nil
		case tokSemi:
			*pos++
			continue
		case tokOpen:
			return nil, fmt.Errorf("line %d: unexpected {", t.line)
		}
		d := &Directive{Name: t.text, File: file, Line: t.line}
		*pos++
	args:
		for *pos < len(toks) {
			t := toks[*pos]
			switch t.kind {
			case tokWord:
				d.Args = append(d.Args, t.text)
				*pos++
			case tokSemi:
				*pos++
				break args
			case tokOpen:
				*pos++
				d.HasBlock = true
				block, err := p.parseBlock(toks, pos, file, depth, true)
				if err != nil {
					return nil, err
				}
				d.Block = block
				break args
			case tokClose:
				return nil, fmt.Errorf("line %d: missing ; after %s", t.line, d.Name)
			}
		}
		if d.Name == "include" && !d.HasBlock && len(d.Args) == 1 {
			out = append(out, p.include(d, depth)...)
			continue
		}
		out = append(out, d)
	}
	if inBlock {
		return nil, fmt.Errorf("unexpected end of file, missing }")
	}
	return out, nil
}

func (p *parser) include(d *Directive, depth int) []*Directive {
	pattern := d.Args[0]
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(p.prefix, pattern)
	}
	var matches []string
	if strings.ContainsAny(pattern, "*?[") {
		m, err := p.fs.Glob(pattern)
		if err != nil {
			p.warnings = append(p.warnings, fmt.Sprintf("%s: include %s: %v", d.Pos(), d.Args[0], err))
			return nil
		}
		matches = m
	} else {
		matches = []string{pattern}
	}
	sort.Strings(matches)
	var out []*Directive
	for _, m := range matches {
		dirs, err := p.parseFile(m, depth+1)
		if err != nil {
			p.warnings = append(p.warnings, fmt.Sprintf("%s: include %s: %v", d.Pos(), m, err))
			continue
		}
		out = append(out, dirs...)
	}
	return out
}

func Parse(fs FS, path string) (dirs []*Directive, files []string, warnings []string, err error) {
	p := &parser{fs: fs, prefix: filepath.Dir(path), seen: map[string]bool{}}
	dirs, err = p.parseFile(path, 0)
	return dirs, p.files, p.warnings, err
}
