"""Thin wrapper so generate_report.py doesn't care how the summary gets written.

Runs a small open-weight model entirely on the GitHub Actions runner via
https://github.com/Mozilla-Ocho/llamafile -- no cloud API call, no
third-party account, real vulnerability findings never leave the runner.
scan.yml downloads and starts the model as a local OpenAI-compatible server
(127.0.0.1:8080) before this script runs; summarize() just points the
`openai` SDK at it.

This was a deliberate choice over first-party cloud models (Amazon Nova on
Bedrock, Azure OpenAI) that this project ran with earlier -- both worked
fine, but the user's own framing settled it: real vulnerability data leaving
the runner is itself the concern, even to a free/first-party API. See
CLAUDE.md's design decisions and Status history for that full pivot (and the
earlier one, off Claude, before it).

The prompt passed in must already be fully grounded (aggregate counts + the
specific top findings) -- the model is never given raw cloud access, and the
system prompt below forbids inventing findings not present in the input.
"""
import os
import re

SYSTEM_PROMPT = (
    "You are summarizing a cloud security scan for a named audience. "
    "Use ONLY the findings and numbers given to you in the user message. "
    "Never invent a finding, resource, or severity that isn't listed. "
    "Never change a finding's stated severity. Be concise and concrete."
)


def summarize(prompt: str) -> str:
    from openai import OpenAI

    # llamafile's server ignores the model name (it only ever serves the one
    # model baked into the running .llamafile) and never checks the API key,
    # so both are placeholders, required only by the SDK's client
    # constructor.
    base_url = os.environ.get("LLAMAFILE_BASE_URL", "http://127.0.0.1:8080/v1")
    client = OpenAI(base_url=base_url, api_key="llamafile-no-key-needed")

    response = client.chat.completions.create(
        model="llamafile",
        max_tokens=600,
        # Confirmed for real on 2026-09-08: without an explicit stop
        # sequence, llama.cpp's server sometimes emits the model's own
        # end-of-turn token as literal trailing text (e.g. "<|eot_id|>")
        # instead of treating it as a hidden stop marker. Belt-and-
        # suspenders: stop generation there AND strip it if it slips
        # through anyway.
        stop=["<|eot_id|>", "<|end_of_text|>"],
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    text = response.choices[0].message.content
    for token in ("<|eot_id|>", "<|end_of_text|>"):
        text = text.replace(token, "")
    text = text.strip()
    # Also confirmed for real on 2026-09-08: the model sometimes echoes the
    # instruction back as a meta-preamble ("Here is a 2-3 sentence executive
    # summary:") before the actual content. Strip a single leading line if
    # it looks like that framing rather than the summary itself.
    first_line, _, rest = text.partition("\n")
    if rest.strip() and re.match(r"^here('s| is)\b.*:$", first_line.strip(), re.IGNORECASE):
        text = rest.strip()
    return text
