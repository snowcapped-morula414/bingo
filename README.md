<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

**Hacker-style AI Terminal — Multi-Model · Multi-Language**

[![Python](https://img.shields.io/badge/python-3.10%2B-green?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-green)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## Installation

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

Or clone and install:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

Or clone and install:

```powershell
git clone https://github.com/bingook/bingo.git
cd bingo
.\install.ps1
```

### pip

```bash
pip install bingo-ai
```

> **Requirements:** Python 3.10+

---

## Usage

```bash
bingo
```

On first run: **select language → enter AI model API key → start chatting**.  
Settings are saved automatically.

```bash
bingo --reset    # Reset settings (re-run onboarding)
bingo --version  # Show version
bingo --help     # Show help
```

---

## Supported Models

| Provider | Default Model | API |
|----------|--------------|-----|
| **DeepSeek** | `deepseek-chat` | [platform.deepseek.com](https://platform.deepseek.com) |
| **Anthropic Claude** | `claude-opus-4-5` | [console.anthropic.com](https://console.anthropic.com) |
| **OpenAI GPT** | `gpt-4o` | [platform.openai.com](https://platform.openai.com) |
| **Zhipu GLM** | `glm-4` | [open.bigmodel.cn](https://open.bigmodel.cn) |
| **Alibaba Qwen** | `qwen-turbo` | [dashscope.aliyuncs.com](https://dashscope.aliyuncs.com) |
| **Ollama** (local) | `llama3` | [ollama.com](https://ollama.com) |
| **Custom** | — | Enter Base URL manually |

Switch models anytime with the `/model` command.

---

## Commands

Use `/` commands inside the chat:

| Command | Description |
|---------|-------------|
| `/help` | Show command list |
| `/model` | Add or switch AI model |
| `/clear` | Clear screen |
| `/config` | View current settings |
| `/history` | View conversation history |
| `/export` | Save conversation as `.md` |
| `/lang` | Change language |
| `/quit` | Exit |

---

## Languages

| Language | Code |
|----------|------|
| 한국어 | `ko` |
| 中文 | `zh` |
| English | `en` |

Select on first run or change anytime with `/lang`.

---

## Config File

Settings are saved automatically to the OS standard path:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

---

## Project Structure

```
bingo/
├── bingo/
│   ├── cli.py          # Entry point + onboarding
│   ├── config.py       # Settings (cross-platform)
│   ├── models/
│   │   ├── base.py     # Streaming HTTP (OpenAI-compatible + Claude)
│   │   └── registry.py # Provider registry
│   ├── ui/
│   │   └── terminal.py # Hacker green terminal UI
│   └── lang/
│       └── strings.py  # Multi-language strings
├── install.sh          # macOS/Linux installer
├── install.ps1         # Windows installer
└── pyproject.toml
```

---

## Contributing

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
pip install -e ".[dev]"
```

Pull requests are welcome.

---

## License

MIT © 2026 bingook
