package main

import (
	"errors"
	"testing"
	"testing/fstest"
)

func TestVerifyFrontend(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fstest.MapFS
		wantErr error
	}{
		{
			name:    "empty FS",
			fsys:    fstest.MapFS{},
			wantErr: errFrontendNotBuilt,
		},
		{
			name: "only .gitkeep in frontend/dist",
			fsys: fstest.MapFS{
				"frontend/dist/.gitkeep": &fstest.MapFile{Data: []byte{}},
			},
			wantErr: errFrontendNotBuilt,
		},
		{
			name: "frontend/dist/index.html present",
			fsys: fstest.MapFS{
				"frontend/dist/index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>x</title>")},
			},
			wantErr: nil,
		},
		{
			name: "index.html present plus .gitkeep",
			fsys: fstest.MapFS{
				"frontend/dist/index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
				"frontend/dist/.gitkeep":   &fstest.MapFile{Data: []byte{}},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyFrontend(tt.fsys)
			if !errors.Is(got, tt.wantErr) {
				t.Fatalf("verifyFrontend() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}
