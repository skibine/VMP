// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(7): ProviderPresets; TECH(6): static-data]
// @purpose Curated list of OpenAI-compatible LLM providers so the user picks the one whose key
// they own (or a local server) instead of typing a raw api_url. Compiled into the SPA: versioned
// with the app, no backend catalog needed. "Custom" keeps the raw api_url field for anything else.
// @invariants
//   - Every non-local preset is truly OpenAI-compatible (works with the single backend OpenAIProvider).
//   - Claude/Anthropic is intentionally absent (native API is not OpenAI-compat) — use OpenRouter.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: providers, presets, openai, openrouter, ollama, lmstudio, vllm, deepseek, groq, mistral, zai
// STRUCTURE: ▶ ┌presets[]┐ → ○ select → ⊕ fill api_url/model → 〈local? hide key〉 → ⎋ Settings

export const providers = [
  { id: 'openai',     label: 'OpenAI',            api_url: 'https://api.openai.com/v1',       default_model: 'gpt-4o-mini',          key_required: true,  local: false },
  { id: 'zai',        label: 'Z.AI (GLM)',        api_url: 'https://api.z.ai/api/paas/v4',    default_model: 'glm-4-flash',          key_required: true,  local: false,
    alt_urls: ['https://api.z.ai/api/coding/paas/v4'], alt_labels: ['coding plan'] },
  { id: 'zai-coding', label: 'Z.AI (GLM) Coding',  api_url: 'https://api.z.ai/api/coding/paas/v4', default_model: 'glm-4-flash',      key_required: true,  local: false },
  { id: 'zai-cn',     label: 'Z.AI (GLM) China',  api_url: 'https://open.bigmodel.cn/api/paas/v4', default_model: 'glm-4-flash',       key_required: true,  local: false,
    alt_urls: ['https://open.bigmodel.cn/api/coding/paas/v4'], alt_labels: ['coding plan'] },
  { id: 'deepseek',   label: 'DeepSeek',          api_url: 'https://api.deepseek.com/v1',     default_model: 'deepseek-chat',        key_required: true,  local: false },
  { id: 'groq',       label: 'Groq',              api_url: 'https://api.groq.com/openai/v1',  default_model: 'llama-3.3-70b-versatile', key_required: true, local: false },
  { id: 'mistral',    label: 'Mistral',           api_url: 'https://api.mistral.ai/v1',       default_model: 'mistral-small-latest', key_required: true,  local: false },
  { id: 'openrouter', label: 'OpenRouter',        api_url: 'https://openrouter.ai/api/v1',    default_model: '',                     key_required: true,  local: false },
  { id: 'ollama',     label: 'Ollama (local)',    api_url: 'http://127.0.0.1:11434/v1',       default_model: '',                     key_required: false, local: true },
  { id: 'lmstudio',   label: 'LM Studio (local)', api_url: 'http://127.0.0.1:1234/v1',        default_model: '',                     key_required: false, local: true },
  { id: 'vllm',       label: 'vLLM (local)',      api_url: 'http://127.0.0.1:8000/v1',         default_model: '',                     key_required: false, local: true },
  { id: 'custom',     label: 'Custom',            api_url: '',                                default_model: '',                     key_required: true,  local: false },
]

// findProvider returns the preset whose api_url OR one of its alt_urls matches, or null (-> Custom).
// alt_urls keep alternative official endpoints (e.g. the Z.AI coding plan) inside the preset
// instead of demoting the user's config to "custom" just because they own a different plan.
export function findProvider(api_url) {
  if (!api_url) return null
  return (
    providers.find((p) => p.id !== 'custom' && p.api_url === api_url) ||
    providers.find((p) => p.id !== 'custom' && (p.alt_urls || []).includes(api_url)) ||
    null
  )
}
