package evidenceaudit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
)

// StructuredStreams rejects Go JSON drivers which explicitly send diagnostics
// into their stdout sink. It audits every source driver, including green jobs;
// strict transcript parsing must never depend on a warm module cache.
func StructuredStreams(source fs.FS, roots []string) error {
	if len(roots) == 0 {
		return fmt.Errorf("missing structured-driver roots")
	}
	for _, root := range roots {
		found := 0
		err := fs.WalkDir(source, root, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			found++
			data, err := fs.ReadFile(source, name)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), name, data, 0)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				structured := false
				ast.Inspect(function.Body, func(node ast.Node) bool {
					literal, ok := node.(*ast.BasicLit)
					if ok && literal.Kind == token.STRING {
						value, _ := strconv.Unquote(literal.Value)
						if value == "-json" {
							structured = true
						}
					}
					return true
				})
				if !structured {
					continue
				}
				sinks := map[string]map[string]map[string]bool{}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					assignment, ok := node.(*ast.AssignStmt)
					if !ok || len(assignment.Lhs) != len(assignment.Rhs) {
						return true
					}
					for i, left := range assignment.Lhs {
						field, ok := left.(*ast.SelectorExpr)
						if !ok || (field.Sel.Name != "Stdout" && field.Sel.Name != "Stderr") {
							continue
						}
						command, ok := field.X.(*ast.Ident)
						if !ok {
							continue
						}
						if sinks[command.Name] == nil {
							sinks[command.Name] = map[string]map[string]bool{}
						}
						if sinks[command.Name][field.Sel.Name] == nil {
							sinks[command.Name][field.Sel.Name] = map[string]bool{}
						}
						streamDestinations(assignment.Rhs[i], sinks[command.Name][field.Sel.Name])
					}
					return true
				})
				for command, fields := range sinks {
					for sink := range fields["Stdout"] {
						if fields["Stderr"][sink] {
							return fmt.Errorf("%s/%s: %s mixes structured stdout and diagnostics in %s", name, function.Name.Name, command, sink)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if found == 0 {
			return fmt.Errorf("missing Go driver inventory %s", root)
		}
	}
	return nil
}
func streamDestinations(expression ast.Expr, sinks map[string]bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		sinks[value.Name] = true
	case *ast.UnaryExpr:
		streamDestinations(value.X, sinks)
	case *ast.ParenExpr:
		streamDestinations(value.X, sinks)
	case *ast.CallExpr:
		method, ok := value.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "MultiWriter" {
			return
		}
		for _, argument := range value.Args {
			streamDestinations(argument, sinks)
		}
	}
}
