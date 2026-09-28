package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestMCPPrompts_List(t *testing.T) {
	handler := NewDefaultPromptHandler()
	res, err := handler.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("ListPrompts failed: %v", err)
	}

	if len(res.Prompts) != 3 {
		t.Fatalf("Expected 3 prompts, got %d", len(res.Prompts))
	}

	promptNames := make(map[string]bool)
	for _, p := range res.Prompts {
		promptNames[p.Name] = true
	}

	if !promptNames[PromptSecurityReview] {
		t.Errorf("Missing prompt: %s", PromptSecurityReview)
	}
	if !promptNames[PromptPreInstallAudit] {
		t.Errorf("Missing prompt: %s", PromptPreInstallAudit)
	}
	if !promptNames[PromptSandboxTroubleshoot] {
		t.Errorf("Missing prompt: %s", PromptSandboxTroubleshoot)
	}
}

func TestMCPPrompts_Get_SecurityReview(t *testing.T) {
	handler := NewDefaultPromptHandler()
	args := map[string]string{
		"target_path": "src/auth/jwt.go",
		"context":     "Reviewing third-party jwt library replacement",
	}

	res, err := handler.GetPrompt(context.Background(), PromptSecurityReview, args)
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if len(res.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(res.Messages))
	}

	msg := res.Messages[0]
	if msg.Role != RoleUser {
		t.Errorf("Expected role 'user', got %s", msg.Role)
	}

	if !strings.Contains(msg.Content.Text, "src/auth/jwt.go") {
		t.Errorf("Expected prompt text to contain target path 'src/auth/jwt.go'")
	}
	if !strings.Contains(msg.Content.Text, "Reviewing third-party jwt library replacement") {
		t.Errorf("Expected prompt text to contain context")
	}
	if !strings.Contains(msg.Content.Text, "airlock_vet") {
		t.Errorf("Expected prompt text to mention 'airlock_vet'")
	}
}

func TestMCPPrompts_Get_PreInstallAudit(t *testing.T) {
	handler := NewDefaultPromptHandler()
	args := map[string]string{
		"package_name": "event-stream",
		"ecosystem":    "npm",
		"version":      "3.3.6",
	}

	res, err := handler.GetPrompt(context.Background(), PromptPreInstallAudit, args)
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if len(res.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(res.Messages))
	}

	msg := res.Messages[0]
	if !strings.Contains(msg.Content.Text, "event-stream") {
		t.Errorf("Expected prompt text to contain package name 'event-stream'")
	}
	if !strings.Contains(msg.Content.Text, "npm") {
		t.Errorf("Expected prompt text to contain ecosystem 'npm'")
	}
	if !strings.Contains(msg.Content.Text, "3.3.6") {
		t.Errorf("Expected prompt text to contain version '3.3.6'")
	}
}

func TestMCPPrompts_Get_SandboxTroubleshoot(t *testing.T) {
	handler := NewDefaultPromptHandler()
	args := map[string]string{
		"error_message": "dial tcp: lookup evil-exfil.com: no such host",
		"command":       "pip install malicious-pkg",
		"domain":        "evil-exfil.com",
	}

	res, err := handler.GetPrompt(context.Background(), PromptSandboxTroubleshoot, args)
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if len(res.Messages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(res.Messages))
	}

	msg := res.Messages[0]
	if !strings.Contains(msg.Content.Text, "evil-exfil.com") {
		t.Errorf("Expected prompt text to contain domain 'evil-exfil.com'")
	}
	if !strings.Contains(msg.Content.Text, "pip install malicious-pkg") {
		t.Errorf("Expected prompt text to contain command 'pip install malicious-pkg'")
	}
	if !strings.Contains(msg.Content.Text, "airlock://audit/recent") {
		t.Errorf("Expected prompt text to reference audit recent resource")
	}
}

func TestMCPPrompts_Get_UnknownPrompt(t *testing.T) {
	handler := NewDefaultPromptHandler()
	_, err := handler.GetPrompt(context.Background(), "unknown_prompt", nil)
	if err == nil {
		t.Fatalf("Expected error for unknown prompt, got nil")
	}
}
