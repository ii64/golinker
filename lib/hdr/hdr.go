package hdr

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

type Hdr struct {
	File     *ast.File
	ArchSize map[string]uint64
}

func ParseFile(path, source, arch string) (h Hdr, err error) {
	h.File, err = parser.ParseFile(token.NewFileSet(), path, source,
		parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return
	}
	var exist bool
	h.ArchSize, exist = archTypeSize[arch]
	if !exist {
		err = fmt.Errorf("arch size data not defined")
		return
	}
	return
}

func (h Hdr) PackageName() string {
	return h.File.Name.Name
}

func (h Hdr) GetFuncDecls(hasBody bool) (fs []*ast.FuncDecl) {
	for _, decl := range h.File.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if hasBody && fn.Body == nil {
			continue
		} else if !hasBody && fn.Body != nil {
			continue
		}
		fs = append(fs, fn)
	}
	return
}

type fieldt struct {
	typ   string
	field *ast.Field
}

type Var struct {
	Offset uint64
	Size   uint64
	Name   string
}

// GetFuncArgRetSize
func (h Hdr) GetFuncArgRetSize(f *ast.FuncDecl) (args []Var, rets []Var, sz uint64) {
	t := f.Type
	if t == nil {
		return
	}
	var fields []fieldt
	params := t.Params
	if params != nil {
		for _, field := range params.List {
			fields = append(fields, fieldt{"arg", field})
		}
	}
	results := t.Results
	if results != nil {
		for _, field := range results.List {
			fields = append(fields, fieldt{"ret", field})
		}
	}
	if len(fields) < 1 {
		return
	}

	// compute arg ret size
	var off uint64 = 0
	for _, fieldt := range fields {
		field := fieldt.field
		if len(field.Names) < 1 {
			panic(fmt.Sprintf("argument / return must have a name: fnName %q", f.Name.Name))
		}
		var typName string
		switch tx := field.Type.(type) {
		case *ast.Ident:
			typName = tx.Name
		case *ast.StarExpr:
			typName = "ptr"
		case *ast.ArrayType:
			typName = "array"
		case *ast.SelectorExpr:
			x, ok := tx.X.(*ast.Ident)
			if !ok {
				panic("unhandled SelectorExpr.X")
			}
			typName = x.Name + "." + tx.Sel.Name
		default:
			panic(fmt.Sprintf("unhandled type: %T", tx))
		}

		for _, name := range field.Names {
			sz, exist := h.ArchSize[typName]
			if !exist {
				panic(fmt.Sprintf("arch type size undefined: %s", typName))
			}

			if fieldt.typ == "arg" {
				args = append(args, Var{
					Offset: off,
					Size:   sz,
					Name:   name.Name,
				})
			} else {
				rets = append(rets, Var{
					Offset: off,
					Size:   sz,
					Name:   name.Name,
				})
			}
			off = off + sz
		}
		// spew.Dump(field)
	}
	sz = off
	return
}
