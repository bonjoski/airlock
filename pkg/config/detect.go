package config

import (
	"os"
	"path/filepath"
)

// DetectProjectType analyzes repository layout to infer the primary project profile type.
func DetectProjectType(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return "node"
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		return "rust"
	}
	if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err == nil {
		return "python"
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return "python"
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return "go"
	}
	if _, err := os.Stat(filepath.Join(dir, "pom.xml")); err == nil {
		return "java"
	}
	if _, err := os.Stat(filepath.Join(dir, "build.gradle")); err == nil {
		return "java"
	}
	if _, err := os.Stat(filepath.Join(dir, "build.gradle.kts")); err == nil {
		return "java"
	}
	if _, err := os.Stat(filepath.Join(dir, "Gemfile")); err == nil {
		return "ruby"
	}
	if _, err := os.Stat(filepath.Join(dir, "Package.swift")); err == nil {
		return "swift"
	}
	if _, err := os.Stat(filepath.Join(dir, "Podfile")); err == nil {
		return "swift"
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.xcworkspace")); len(matches) > 0 {
		return "swift"
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.xcodeproj")); len(matches) > 0 {
		return "swift"
	}
	if _, err := os.Stat(filepath.Join(dir, "global.json")); err == nil {
		return "dotnet"
	}
	if _, err := os.Stat(filepath.Join(dir, "nuget.config")); err == nil {
		return "dotnet"
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.sln")); len(matches) > 0 {
		return "dotnet"
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.csproj")); len(matches) > 0 {
		return "dotnet"
	}
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
		return "container"
	}
	if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); err == nil {
		return "container"
	}
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yaml")); err == nil {
		return "container"
	}
	if _, err := os.Stat(filepath.Join(dir, "Chart.yaml")); err == nil {
		return "container"
	}
	return "general"
}
