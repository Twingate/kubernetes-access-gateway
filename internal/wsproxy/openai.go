// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package wsproxy

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "os"
    "strings"
    "time"
)

type AISummary struct {
    Summary string
    Score   int
}

// summarizeAsciicastWithOpenAI sends a short prompt to OpenAI to obtain
// a compact, plain-text summary of the asciicast for audit logging.
// Behavior:
// - Off by default. Enable by setting env GATEWAY_AI_SUMMARY_ENABLED to "1" or "true".
// - Requires OPENAI_API_KEY. Model can be overridden via OPENAI_MODEL (default: gpt-4o-mini).
// - Hard time limit and best-effort; returns empty string on any error.
func summarizeAsciicastWithOpenAI(asciicast string) (AISummary, bool) {
    enabled := os.Getenv("GATEWAY_AI_SUMMARY_ENABLED")
    if enabled != "1" && strings.ToLower(enabled) != "true" {
        return AISummary{}, false
    }

    apiKey := os.Getenv("OPENAI_API_KEY")
    if apiKey == "" {
        return AISummary{}, false
    }

	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}

	// To keep requests small, trim very long sessions.
	const maxChars = 8000
    if len(asciicast) > maxChars {
        asciicast = asciicast[:maxChars]
    }

	system_prompt := os.Getenv("AI_SYSTEM_PROMPT")
	if system_prompt == "" {
		system_prompt = `
You are a Senior Security Engineer reviewing kubernetes remote shell sessions in asciicast format looking to flag dangerous sessions.
The fact that these remote shell sessions are to a kubernetes pod isn't a security risk on its own.
User is authorised to remote shell access.
Output should be in JSON format and contain 2 fields only: 'summary' and 'score'.
`
	}

	user_prompt := os.Getenv("AI_USER_PROMPT")
	if user_prompt == "" {
		user_prompt = "Summarize the following kubernetes remote shell session and provide a brief description of it in <= 20 words. Also provide a security score between 1 and 5 where 5 is a major security risk and 1 is no risk. The session: "
	}
	user_prompt = strings.Join([]string{user_prompt, asciicast}, "")

	// Chat Completions payload
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system_prompt},
			{"role": "user", "content": user_prompt},
		},
		//"max_tokens":  64,
		"temperature": 0.2,
	}

    b, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(b))
    if err != nil {
        return AISummary{}, false
    }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return AISummary{}, false
    }
	defer func() { _ = resp.Body.Close() }()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return AISummary{}, false
    }

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
    if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
        return AISummary{}, false
    }

    if len(parsed.Choices) == 0 {
        return AISummary{}, false
    }

    content := strings.TrimSpace(parsed.Choices[0].Message.Content)

    // The model is instructed to return JSON: {"summary": string, "score": number}
    // Be permissive in parsing the number type.
    var anyMap map[string]any
    if err := json.Unmarshal([]byte(content), &anyMap); err != nil {
        return AISummary{}, false
    }
    s, _ := anyMap["summary"].(string)
    if strings.TrimSpace(s) == "" {
        return AISummary{}, false
    }
    var scoreInt int
    switch v := anyMap["score"].(type) {
    case float64:
        scoreInt = int(v)
    case int:
        scoreInt = v
    case string:
        // try to parse numeric strings
        if v == "" {
            scoreInt = 0
        } else {
            // minimal fast path; ignore error -> treat as absent
            var tmp float64
            if err := json.Unmarshal([]byte(v), &tmp); err == nil {
                scoreInt = int(tmp)
            }
        }
    default:
        scoreInt = 0
    }

    return AISummary{Summary: strings.TrimSpace(s), Score: scoreInt}, true
}
