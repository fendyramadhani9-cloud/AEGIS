# AEGIS Multi-Provider AI Configuration Guide

## 1. Supported Providers
The AEGIS AI Incident Investigation Engine supports multiple AI providers with automatic fallback capabilities:

| Provider Key | Provider Name | Default Model | Primary Use Case |
| :--- | :--- | :--- | :--- |
| `gemini` | Google Gemini API | `gemini-3.5-flash-lite` | Live production analysis with high throughput & low latency. |
| `openai` | OpenAI Compatible | `gpt-4o-mini` | Enterprise endpoints, Azure OpenAI, or local gateways. |
| `mock` | Mock Offline | `mock-grounded-v1` | 100% offline testing, CI/CD pipelines, and air-gapped hosts. |
| `none` | Null Provider | `none` | AI gracefully disabled while maintaining 100% telemetry integrity. |

## 2. Environment Variables (.env)
```ini
# Primary Provider Selection
AEGIS_LLM_PROVIDER=gemini

# Primary API Key (Required for live analysis)
AEGIS_LLM_API_KEY=AQ.Ab8...

# Optional Multi-Key Rotation Pool (Used sequentially on rate limits or 429 errors)
AEGIS1=AQ.Ab8...
AEGIS2=AIzaSy...
AEGIS3=AIzaSy...

# Model Selection
AEGIS_LLM_MODEL=gemini-3.5-flash-lite

# Timeout (seconds)
AEGIS_LLM_TIMEOUT=30

# Force Offline Mock Provider (Set to true in CI/CD)
AEGIS_USE_MOCK_LLM=false
```

## 3. Key Rotation & Error Handling
`GeminiProvider` automatically manages key rotation:
1. When a `429 Too Many Requests` or `503 Service Unavailable` error is received from Google API, the client rotates to the next available key in `AEGIS_LLM_API_KEY`, `AEGIS1`, `AEGIS2`, and `AEGIS3`.
2. The failed request is retried once with the new key.
3. If all keys fail or no key is present, the engine returns a clean `AIAnalysisItem(analysis_status="failed")` with actionable administrator advice.
4. Error logs and HTTP responses redact all API key strings via `TelemetrySanitizer` to prevent credential exposure.

