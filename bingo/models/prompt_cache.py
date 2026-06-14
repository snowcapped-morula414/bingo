"""
Prompt Cache Optimizer — Three-Breakpoint Architecture
=======================================================
Research basis:
  ProjectDiscovery Engineering — "How We Cut LLM Cost with Prompt Caching"
  https://projectdiscovery.io/blog/how-we-cut-llm-cost-with-prompt-caching

Key techniques implemented:
  [1] Three-Breakpoint Architecture (BP1 / BP2 / BP3)
      BP1 = SYSTEM prompt (static core, always cached)
      BP2 = Tool / Skill definitions (57 skills, changes rarely)
      BP3 = Conversation history (sliding window, last N turns)
  [2] Relocation Trick — dynamic content (target URL, date) moved to END
       so static prefix cache stays valid across multiple turns
  [3] Frozen Datetime — only date used (not full timestamp) → prevents
       per-minute cache busting in long pipeline runs
  [4] Provider routing:
       Claude   → native cache_control: {"type": "ephemeral"} markers
       DeepSeek → prefix_caching: true payload param
       OpenAI   → structural ordering maximizes automatic prompt cache

Cost impact (empirical, ProjectDiscovery Neo data):
  Pipeline steps  |  cache_ratio  |  cost_reduction
  1–5             |  ~35%         |  ~35%
  6–10            |  ~54%         |  ~54%
  20+ (bingo max) |  ~74%         |  ~70% ← bingo 23-step pipeline
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import date
from typing import Any


# ─────────────────────────────────────────────
# Cache statistics (per run)
# ─────────────────────────────────────────────

@dataclass
class CacheStats:
    total_calls:     int = 0
    cache_hits:      int = 0
    cache_misses:    int = 0
    tokens_saved:    int = 0      # estimated via content length proxy
    cost_ratio:      float = 0.0  # cache_hits / total_calls
    bp_fingerprints: dict[str, str] = field(default_factory=dict)

    def record_hit(self, estimated_tokens: int = 0) -> None:
        self.total_calls += 1
        self.cache_hits += 1
        self.tokens_saved += estimated_tokens
        self._update_ratio()

    def record_miss(self) -> None:
        self.total_calls += 1
        self.cache_misses += 1
        self._update_ratio()

    def _update_ratio(self) -> None:
        if self.total_calls:
            self.cost_ratio = self.cache_hits / self.total_calls

    def summary(self) -> str:
        pct = int(self.cost_ratio * 100)
        return (
            f"[PromptCache] calls={self.total_calls} "
            f"hits={self.cache_hits}({pct}%) "
            f"saved≈{self.tokens_saved}tok"
        )


# ─────────────────────────────────────────────
# Global stats singleton
# ─────────────────────────────────────────────
_stats = CacheStats()


def get_stats() -> CacheStats:
    return _stats


def reset_stats() -> None:
    global _stats
    _stats = CacheStats()


# ─────────────────────────────────────────────
# Frozen datetime helper
# ─────────────────────────────────────────────

def frozen_date_str() -> str:
    """
    Return today's date as ISO string (YYYY-MM-DD).
    Using full datetime (H:M:S) busts the cache every minute in long runs.
    Using only the date keeps BP1 valid for the entire day.
    """
    return date.today().isoformat()


# ─────────────────────────────────────────────
# Content fingerprint helper
# ─────────────────────────────────────────────

def _fp(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", "replace")).hexdigest()[:8]


# ─────────────────────────────────────────────
# Relocation Trick helper
# ─────────────────────────────────────────────

def build_context_tail(target: str, extra: str = "") -> str:
    """
    Dynamic content moved to the TAIL of the prompt so that the
    static prefix (BP1+BP2) cache remains valid across turns.

    Before (cache-busting):
      [STATIC 20k chars] [TARGET URL today 12:34:56] [TOOLS]
                          ↑ changes every turn → invalidates everything after

    After (Relocation Trick):
      [STATIC 20k chars] [TOOLS] ... [DYNAMIC TAIL: target + date]
                                      ↑ only this tiny part changes
    """
    tail_parts = [f"[SESSION DATE] {frozen_date_str()}"]
    if target:
        tail_parts.append(f"[TARGET] {target}")
    if extra:
        tail_parts.append(f"[CONTEXT] {extra[:500]}")
    return "\n".join(tail_parts)


# ─────────────────────────────────────────────
# PromptCacheManager — main API
# ─────────────────────────────────────────────

class PromptCacheManager:
    """
    Wraps the message-building pipeline to insert cache breakpoints.

    Usage:
        pcm = PromptCacheManager(provider="claude")
        messages = pcm.build_cached_messages(
            system_core=UNIVERSAL_PENTEST_CORE,
            model_extra=CLAUDE_GPT_EXTRA,
            warmup=WARMUP_HISTORY,
            skill_block=skill_summary_text,
            conversation=current_conversation,
            target=target_url,
        )
        # Pass messages to API call
    """

    # Max conversation turns to keep in BP3 window (prevents context explosion)
    BP3_MAX_TURNS = 12

    def __init__(self, provider: str = "deepseek"):
        self.provider = provider.lower()

    # ── Public API ────────────────────────────────────────────────

    def build_cached_messages(
        self,
        system_core: str,
        model_extra: str = "",
        warmup: list[dict] | None = None,
        skill_block: str = "",
        conversation: list[dict] | None = None,
        target: str = "",
        extra_context: str = "",
    ) -> list[dict]:
        """
        Build message array with cache breakpoints injected.

        Structure:
          [system(BP1)]  ← UNIVERSAL_CORE + MODEL_EXTRA (static)
          [user/asst warmup(BP2)]  ← WARMUP + skill block (rare changes)
          [conversation window(BP3)]  ← last N turns (sliding)
          [user context tail]  ← dynamic: target + date (always last)
        """
        bp1_text = self._build_bp1(system_core, model_extra)
        messages = self._inject_system_bp1(bp1_text)

        warmup_msgs = warmup or []
        bp2_msgs = self._build_bp2(warmup_msgs, skill_block)
        messages.extend(bp2_msgs)

        if conversation:
            bp3_msgs = self._build_bp3(conversation)
            messages.extend(bp3_msgs)

        tail = build_context_tail(target, extra_context)
        if tail.strip():
            messages.append({"role": "user", "content": tail})

        # Track stats (fingerprint check)
        fp = _fp(bp1_text)
        if _stats.bp_fingerprints.get("bp1") == fp:
            _stats.record_hit(len(bp1_text) // 4)
        else:
            _stats.bp_fingerprints["bp1"] = fp
            _stats.record_miss()

        return messages

    def apply_prefix_caching_param(self, payload: dict) -> dict:
        """
        Add provider-specific prefix caching parameter to payload.
        - DeepSeek: payload["prefix_caching"] = true
        - OpenAI  : no explicit param (automatic caching)
        - Claude  : handled via cache_control in message content
        """
        if "deepseek" in self.provider:
            payload["prefix_caching"] = True
        # OpenAI automatic prefix cache: no action needed
        # Claude cache_control: handled in _inject_system_bp1 / _build_bp2
        return payload

    # ── Internal builders ─────────────────────────────────────────

    def _build_bp1(self, system_core: str, model_extra: str) -> str:
        """
        BP1 = completely static system prompt.
        MUST NOT contain any timestamp or target URL.
        """
        parts = [system_core.strip()]
        if model_extra.strip():
            parts.append(model_extra.strip())
        return "\n\n".join(parts)

    def _inject_system_bp1(self, bp1_text: str) -> list[dict]:
        """
        Wrap BP1 with cache_control for Claude; plain text for others.
        """
        if "claude" in self.provider or "anthropic" in self.provider:
            # Anthropic: system can be list with cache_control blocks
            return [{
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": bp1_text,
                        "cache_control": {"type": "ephemeral"},  # BP1 cache breakpoint
                    }
                ],
            }]
        # OpenAI / DeepSeek / GLM / Qwen: plain system message
        return [{"role": "system", "content": bp1_text}]

    def _build_bp2(self, warmup: list[dict], skill_block: str) -> list[dict]:
        """
        BP2 = warmup history + skill summary block.
        These change rarely (only on new skill additions) so they
        are excellent candidates for the second cache breakpoint.
        """
        msgs: list[dict] = []

        # Warmup messages (already accepted session bootstrap)
        for msg in warmup:
            msgs.append({"role": msg["role"], "content": msg["content"]})

        # Skill block injected as a single assistant message
        if skill_block.strip():
            msgs.append({
                "role": "assistant",
                "content": skill_block.strip(),
            })

        # Mark the last message in BP2 with cache_control (Claude only)
        if msgs and ("claude" in self.provider or "anthropic" in self.provider):
            last = msgs[-1]
            content = last["content"]
            if isinstance(content, str):
                msgs[-1] = {
                    "role": last["role"],
                    "content": [
                        {
                            "type": "text",
                            "text": content,
                            "cache_control": {"type": "ephemeral"},  # BP2 cache breakpoint
                        }
                    ],
                }

        return msgs

    def _build_bp3(self, conversation: list[dict]) -> list[dict]:
        """
        BP3 = sliding window over conversation history.
        Keeps last BP3_MAX_TURNS × 2 messages (user+assistant pairs).
        Too-long history causes context explosion and cache thrashing.
        """
        # Keep last N turns only
        max_msgs = self.BP3_MAX_TURNS * 2
        window = conversation[-max_msgs:] if len(conversation) > max_msgs else conversation

        msgs: list[dict] = []
        for msg in window:
            msgs.append({"role": msg["role"], "content": msg["content"]})

        # Mark the last message in BP3 with cache_control (Claude only)
        if msgs and ("claude" in self.provider or "anthropic" in self.provider):
            last = msgs[-1]
            content = last["content"]
            if isinstance(content, str):
                msgs[-1] = {
                    "role": last["role"],
                    "content": [
                        {
                            "type": "text",
                            "text": content,
                            "cache_control": {"type": "ephemeral"},  # BP3 cache breakpoint
                        }
                    ],
                }

        return msgs


# ─────────────────────────────────────────────
# Convenience factory
# ─────────────────────────────────────────────

def make_cache_manager(provider: str) -> PromptCacheManager:
    """Return a PromptCacheManager instance for the given provider."""
    return PromptCacheManager(provider=provider)
