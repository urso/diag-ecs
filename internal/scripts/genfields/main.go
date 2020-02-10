// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	wordwrap "github.com/mitchellh/go-wordwrap"
	yaml "gopkg.in/yaml.v2"
)

type schema struct {
	Version    string
	Base       map[string]*value     // toplevel values
	Top        map[string]*namespace // toplevel namespaces
	Namespaces map[string]*namespace // all namespaces with full name
	Values     map[string]*value     // all values with full name in schema
}

type namespace struct {
	Parent *namespace

	Name        string
	FlatName    string
	Description string

	Children []*namespace
	Values   []*value
}

type value struct {
	Parent      *namespace
	Type        typeInfo
	Name        string
	FlatName    string
	Description string
}

type typeInfo struct {
	Package     string
	Name        string
	Constructor string
}

// definition represent in yaml file field specifications.
type definition struct {
	Name        string
	Type        string
	Description string
	Fields      map[string]definition
}

type stringsFlag []string

func (f *stringsFlag) String() string {
	return strings.Join(([]string)(*f), ",")
}

func (f *stringsFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var (
	boolType  = typeInfo{Name: "bool", Constructor: "Bool"}
	strType   = typeInfo{Name: "string", Constructor: "String"}
	intType   = typeInfo{Name: "int", Constructor: "Int"}
	longType  = typeInfo{Name: "int64", Constructor: "Int64"}
	floatType = typeInfo{Name: "float64", Constructor: "Float64"}
	dateType  = typeInfo{Package: "time", Name: "time.Time", Constructor: "Time"}
	durType   = typeInfo{Package: "time", Name: "time.Duration", Constructor: "Dur"}
	objType   = typeInfo{Name: "map[string]interface{}", Constructor: "Any"}
	ipType    = typeInfo{Name: "string", Constructor: "String"}
	geoType   = typeInfo{Name: "string", Constructor: "String"}
)

var codeTmpl = `
	package {{ .packageName }}
	
	import (
		{{ range $key := .packages }}
		  "{{ $key }}"
		{{ end }}

		"github.com/urso/diag"
	)

	type (
	{{ range $ns := .schema.Namespaces }}
	  ns{{ $ns.FlatName | goName }} struct {
		  {{ range $sub := $ns.Children }}
			{{ $sub.Description | goComment }}
			{{ $sub.Name | goName }} ns{{ $sub.FlatName | goName }}
			{{ end }}
		}
	{{ end }}
	)

	var (
	{{ range $ns := .schema.Top }}
	  // {{ $ns.Name | goName }} provides fields in the ECS {{ $ns.FlatName }} namespace.
		{{ if $ns.Description -}}{{ $ns.Description | goComment }}{{ end -}}
	  {{ $ns.Name | goName }} = ns{{ $ns.FlatName | goName }}{}
	{{ end }}
	)

  // Version is the current ECS version available in the ecs package.
	const Version = "{{ .schema.Version }}"

  func ecsField(key string, val diag.Value) diag.Field {
		return diag.Field{Key: key, Value: val, Standardized: true}
	}
		  
  func ecsAny(key string, val interface{}) diag.Field   { return ecsField(key, diag.ValAny(val)) }
	func ecsTime(key string, val time.Time) diag.Field    { return ecsField(key, diag.ValTime(val)) }
	func ecsDur(key string, val time.Duration) diag.Field { return ecsField(key, diag.ValDuration(val)) }
  func ecsString(key, val string) diag.Field            { return ecsField(key, diag.ValString(val)) }
	func ecsBool(key string, val bool) diag.Field         { return ecsField(key, diag.ValBool(val)) }
  func ecsInt(key string, val int) diag.Field           { return ecsField(key, diag.ValInt(val)) }
  func ecsInt64(key string, val int64) diag.Field       { return ecsField(key, diag.ValInt64(val)) }
  func ecsFloat64(key string, val float64) diag.Field   { return ecsField(key, diag.ValFloat(val)) }

	{{ range $value := .schema.Base }}
		{{ if ne $value.Type.Constructor "Any" }}
	  // {{ $value.Name | goName }} create the ECS complain '{{ $value.FlatName}}' field.
	  {{ $value.Description | goComment }}
		func {{ $value.Name | goName }}(value {{ $value.Type.Name }}) diag.Field {
					return ecs{{ $value.Type.Constructor }}("{{ $value.FlatName }}", value)
		}
		{{ end }}

	{{ end }}

	{{ range $ns := .schema.Namespaces }}
	// ## {{ $ns.FlatName }} fields

    {{ range $value := $ns.Values }}
		{{/* Filter out generic object types that would accept a map[string]interface */}}
		{{ if ne $value.Type.Constructor "Any" }}
			// {{ $value.Name | goName }} create the ECS complain '{{ $value.FlatName}}' field.
			{{ $value.Description | goComment }}
			func (ns{{ $ns.FlatName | goName }}) {{ $value.Name | goName }}(value {{ $value.Type.Name }}) diag.Field {
					return ecs{{ $value.Type.Constructor }}("{{ $value.FlatName }}", value)
			}
			{{ end }}
		{{ end }}
	{{ end }}
`

func main() {
	var (
		pkgName string
		outFile string
		version string
		fmtCode bool
		exclude []string
	)

	log.SetFlags(0)
	flag.StringVar(&pkgName, "pkg", "ecs", "Target package name")
	flag.StringVar(&outFile, "out", "", "Output directory (required)")
	flag.StringVar(&version, "version", "", "ECS version (required)")
	flag.BoolVar(&fmtCode, "fmt", false, "Format output")
	flag.Var((*stringsFlag)(&exclude), "e", "exclude fields")
	flag.Parse()
	files := flag.Args()

	if len(files) == 0 {
		log.Fatal("No schema files given")
	}

	checkFlag("version", version)

	ignoreNames := map[string]bool{}
	for _, name := range exclude {
		ignoreNames[name] = true
	}

	schema, err := loadSchema(version, files, ignoreNames)
	if err != nil {
		log.Fatalf("Error loading schema: %+v", err)
	}

	contents, err := execTemplate(codeTmpl, pkgName, schema)
	if err != nil {
		log.Fatalf("Error creating code: %+v", err)
	}

	if fmtCode {
		contents, err = format.Source(contents)
		if err != nil {
			log.Fatalf("failed to format code: %v", err)
		}
	}

	if outFile != "" {
		err := ioutil.WriteFile(outFile, contents, 0600)
		if err != nil {
			log.Fatalf("failed to write file '%v': %v", outFile, err)
		}
	} else {
		fmt.Printf("%s\n", contents)
	}
}

func execTemplate(tmpl, pkgName string, schema *schema) ([]byte, error) {
	funcs := template.FuncMap{
		"goName":    goTypeName,
		"goComment": goCommentify,
	}

	// collect packages to be imported
	packages := map[string]string{}
	for _, val := range schema.Values {
		pkg := val.Type.Package
		if pkg != "" {
			packages[pkg] = pkg
		}
	}

	var buf bytes.Buffer
	t := template.Must(template.New("").Funcs(funcs).Parse(tmpl))
	err := t.Execute(&buf, map[string]interface{}{
		"packageName": pkgName,
		"packages":    packages,
		"schema":      schema,
	})
	if err != nil {
		return nil, fmt.Errorf("executing code template failed: %+v", err)
	}

	return buf.Bytes(), nil
}

func loadSchema(version string, paths []string, exclude map[string]bool) (*schema, error) {
	defs, err := loadDefs(paths)
	if err != nil {
		return nil, err
	}

	schema := buildSchema(version, flattenDefs("", defs), exclude)
	copyDescriptions(schema, "", defs)
	return schema, nil
}

func loadDefs(paths []string) (map[string]definition, error) {
	var files []string

	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to access '%v': %+v", path, err)
		}

		if !stat.IsDir() {
			files = append(files, path)
			continue
		}

		local, err := filepath.Glob(filepath.Join(path, "*.yml"))
		if err != nil {
			return nil, fmt.Errorf("finding yml files in '%v' failed: %+v", path, err)
		}
		files = append(files, local...)
	}

	// load definitions
	defs := map[string]definition{}
	for _, file := range files {
		contents, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("error reading file %v: %+v", file, err)
		}

		var fileDefs map[string]definition
		if err := yaml.Unmarshal(contents, &fileDefs); err != nil {
			return nil, fmt.Errorf("error parsing file %v: %+v", file, err)
		}

		for k, v := range fileDefs {
			defs[k] = v
		}
	}

	return defs, nil
}

func flattenDefs(path string, in map[string]definition) map[string]typeInfo {
	filtered := map[string]typeInfo{}
	for fldPath, fld := range in {
		if path != "" {
			fldPath = fmt.Sprintf("%v.%v", path, fldPath)
		}

		if fld.Type != "group" {
			filtered[fldPath] = getType(fld.Type, fldPath)
		}

		for k, v := range flattenDefs(fldPath, fld.Fields) {
			filtered[k] = v
		}
	}
	return filtered
}

func buildSchema(version string, defs map[string]typeInfo, exclude map[string]bool) *schema {
	s := &schema{
		Version:    version,
		Base:       map[string]*value{},
		Top:        map[string]*namespace{},
		Namespaces: map[string]*namespace{},
		Values:     map[string]*value{},
	}

	for fullName, ti := range defs {
		if exclude[fullName] {
			continue
		}

		fullName = normalizePath(fullName)
		name, path := splitPath(fullName)
		isBase := path == "base" || path == ""

		var current *namespace
		val := &value{
			Type:     ti,
			Name:     name,
			FlatName: fullName,
		}

		if isBase {
			if exclude[name] {
				continue
			}

			s.Base[name] = val
			s.Values[name] = val
		} else {
			s.Values[fullName] = val
		}

		// iterate backwards through fully qualified and build namespaces.
		// Namespaces and values get dynamically interlinked
		for path != "" {
			fullPath := path
			name, path = splitPath(path)

			ns := s.Namespaces[fullPath]
			newNS := ns == nil
			if newNS {
				ns = &namespace{
					Name:     name,
					FlatName: fullPath,
				}
				s.Namespaces[fullPath] = ns
			}

			if val != nil {
				// first parent namespace. Let's add the value and reset, so it won't be added to another namespace
				val.Parent = ns
				ns.Values = append(ns.Values, val)
				val = nil
			}
			if current != nil && current.Parent == nil {
				// was new namespace, lets insert and link it
				current.Parent = ns
				ns.Children = append(ns.Children, current)
			}

			if !newNS { // we found a common ancestor in the tree, let's stop early
				current = nil
				break
			}

			current = ns // advance to parent namespace
		}

		if current != nil {
			// new top level namespace:
			s.Top[current.Name] = current
		}
	}

	return s
}

func copyDescriptions(schema *schema, root string, defs map[string]definition) {
	for fqName, def := range defs {
		if root != "" {
			fqName = fmt.Sprintf("%v.%v", root, fqName)
		}

		path := normalizePath(fqName)
		if path != "" && def.Description != "" {
			if def.Type == "group" {
				ns := schema.Namespaces[path]
				if ns == nil {
					panic(fmt.Sprintf("no namespace for: %v", path))
				}

				ns.Description = def.Description
			} else {
				val, ok := schema.Values[path]
				if !ok {
					continue
				}
				if val == nil {
					panic(fmt.Sprintf("no value for: %v", path))
				}

				val.Description = def.Description
			}
		}

		copyDescriptions(schema, fqName, def.Fields)
	}
}

func splitPath(in string) (name, parent string) {
	idx := strings.LastIndexByte(in, '.')
	if idx < 0 {
		return in, ""
	}

	return in[idx+1:], in[:idx]
}

func normalizePath(in string) string {
	var rootPaths = []string{"base"}

	for _, path := range rootPaths {
		if in == path {
			return ""
		}
		if strings.HasPrefix(in, path) && len(in) > len(path) && in[len(path)] == '.' {
			return in[len(path)+1:]
		}
	}
	return in
}

func checkFlag(name, s string) {
	if s == "" {
		log.Fatalf("Error: -%v required", name)
	}
}

func getType(typ, name string) typeInfo {
	switch typ {
	case "keyword", "text":
		return strType
	case "bool", "boolean":
		return boolType
	case "integer":
		return intType
	case "long":
		return longType
	case "float":
		return floatType
	case "date":
		return dateType
	case "duration":
		return durType
	case "object":
		return objType
	case "ip":
		return ipType
	case "geo_point":
		return geoType
	default:
		panic(fmt.Sprintf("unknown type '%v' in field '%v'", typ, name))
	}
}

func goCommentify(s string) string {
	s = strings.Join(strings.Split(s, "\n"), " ")
	textLength := 75 - len(strings.Replace("", "\t", "    ", 4)+" // ")
	lines := strings.Split(wordwrap.WrapString(s, uint(textLength)), "\n")

	if len(lines) > 0 {
		// Remove empty first line.
		if strings.TrimSpace(lines[0]) == "" {
			lines = lines[1:]
		}
	}
	if len(lines) > 0 {
		// Remove empty last line.
		if strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
	}

	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	// remove empty lines
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) == 0 {
			lines = lines[:i]
		}
		break
	}

	for i := range lines {
		lines[i] = "// " + lines[i]
	}

	return strings.Join(lines, "\n")
}

func goTypeName(name string) string {
	var b strings.Builder
	for _, w := range strings.FieldsFunc(name, isSeparator) {
		b.WriteString(strings.Title(abbreviations(w)))
	}
	return b.String()
}

// abbreviations capitalizes common abbreviations.
func abbreviations(abv string) string {
	switch strings.ToLower(abv) {
	case "id", "ppid", "pid", "mac", "ip", "iana", "uid", "ecs", "url", "os",
		"http", "dns", "ssl", "tls", "ttl", "uuid":
		return strings.ToUpper(abv)
	default:
		return abv
	}
}

// isSeparate returns true if the character is a field name separator. This is
// used to detect the separators in fields like ephemeral_id or instance.name.
func isSeparator(c rune) bool {
	switch c {
	case '.', '_':
		return true
	case '@':
		// This effectively filters @ from field names.
		return true
	default:
		return false
	}
}
