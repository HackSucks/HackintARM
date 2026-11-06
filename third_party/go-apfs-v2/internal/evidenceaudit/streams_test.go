package evidenceaudit

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestStructuredStreams(t *testing.T) {
	for _, scenario := range []struct {
		name, code string
		invalid    bool
	}{
		{"separate", `func f(){ args:=[]string{"-json"}; cmd.Stdout=io.MultiWriter(os.Stdout,log,&transcript); cmd.Stderr=diagnostic }`, false},
		{"shared", `func f(){args:=[]string{"-json"};cmd.Stdout=io.MultiWriter(os.Stdout,log,&transcript);cmd.Stderr=io.MultiWriter(os.Stderr,log)}`, true},
		{"tuple", `func f(){args:=[]string{"-json"};cmd.Stdout,cmd.Stderr=io.MultiWriter(os.Stdout,log),io.MultiWriter(os.Stderr,log)}`, true},
		{"buffer", `func f(){args:=[]string{"-json"};cmd.Stdout=(&transcript);cmd.Stderr=&transcript}`, true},
		{"nonjson", `func f(){cmd.Stdout,cmd.Stderr=log,log}`, false},
		{"different-command", `func f(){args:=[]string{"-json"};first.Stdout=log;second.Stderr=log}`, false},
		{"shared-api", `func f(){args:=[]string{"-json"};cmd.Stdout=io.MultiWriter(os.Stdout,log,&transcript);cmd.RunWithDiagnostics("tests.stderr.log")}`, false},
		{"command-helper", `func f(){args:=[]string{"-json"};cmd.Stdout=output();cmd.Stderr=diagnostic}`, false},
		{"package-streams", `func f(){args:=[]string{"-json"};cmd.Stdout,cmd.Stderr=os.Stdout,os.Stderr}`, false},
		{"nil-body", `func f()`, false},
		{"ordinary-declaration", `var x=[]string{"-json"}`, false},
		{"other-fields", `func f(){args:=[]string{"-json"};config.Options=log; cmd.Path="go"}`, false},
		{"struct-field", `func f(){args:=[]string{"-json"};object.command.Stdout=log}`, false},
		{"nonmethod-helper", `func f(){args:=[]string{"-json"};cmd.Stdout=output(log)}`, false},
		{"literal", `func f(){args:=[]string{"-json"};cmd.Stdout=nil;cmd.Stderr="text"}`, false},
		{"compound-assignment", `func f(){args:=[]string{"-json"}; a,b=both()}`, false},
		{"unrelated-number", `func f(){args:=[]string{"-json"};value:=4}`, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			source := fstest.MapFS{"scripts/driver.go": {Data: []byte("package main\n" + scenario.code)}, "scripts/README.md": {Data: []byte("ignored")}, "scripts/nested/a.txt": {Data: []byte("ignored")}, "scripts/driver_test.go": {Data: []byte("negative test fixture, not executable driver")}}
			err := StructuredStreams(source, []string{"scripts"})
			if (err != nil) != scenario.invalid {
				t.Fatal("wrong structured-stream result", err)
			}
		})
	}
}

type streamReadFailure struct{ fs.FS }

func (streamReadFailure) ReadFile(string) ([]byte, error) { return nil, fs.ErrPermission }

func TestStructuredStreamsRejectsIncompleteDriverInventory(t *testing.T) {
	source := fstest.MapFS{"scripts/a.go": {Data: []byte("package main\nfunc broken(")}, "empty/readme.txt": {Data: []byte("none")}}
	for _, roots := range [][]string{nil, {"absent"}, {"empty"}, {"scripts"}} {
		if err := StructuredStreams(source, roots); err == nil {
			t.Fatal("incomplete driver inventory accepted", roots)
		}
	}
	if err := StructuredStreams(streamReadFailure{source}, []string{"scripts"}); !errors.Is(err, fs.ErrPermission) {
		t.Fatal("read failure lost", err)
	}
}
