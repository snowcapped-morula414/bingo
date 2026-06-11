SUPPORTED_LANGS = {"ko": "한국어", "zh": "中文", "en": "English"}

_STRINGS = {
    # ── 온보딩 ──────────────────────────────────────────────────
    "welcome": {
        "ko": "빙고에 오신 것을 환영합니다",
        "zh": "欢迎使用 Bingo",
        "en": "Welcome to Bingo",
    },
    "select_lang": {
        "ko": "언어를 선택하세요",
        "zh": "请选择语言",
        "en": "Select your language",
    },
    "lang_saved": {
        "ko": "언어가 저장되었습니다",
        "zh": "语言已保存",
        "en": "Language saved",
    },
    # ── 모델 설정 ────────────────────────────────────────────────
    "select_model": {
        "ko": "AI 모델을 선택하세요",
        "zh": "请选择 AI 模型",
        "en": "Select AI model",
    },
    "enter_api_key": {
        "ko": "API 키를 입력하세요",
        "zh": "请输入 API 密钥",
        "en": "Enter your API key",
    },
    "enter_base_url": {
        "ko": "Base URL을 입력하세요 (엔터 = 기본값 사용)",
        "zh": "输入 Base URL（回车使用默认值）",
        "en": "Enter Base URL (Enter = use default)",
    },
    "model_saved": {
        "ko": "모델 설정이 저장되었습니다",
        "zh": "模型配置已保存",
        "en": "Model configuration saved",
    },
    "model_name_prompt": {
        "ko": "모델명을 입력하세요 (예: deepseek-chat)",
        "zh": "请输入模型名称（例：deepseek-chat）",
        "en": "Enter model name (e.g. deepseek-chat)",
    },
    "add_model": {
        "ko": "새 모델 추가",
        "zh": "添加新模型",
        "en": "Add new model",
    },
    "switch_model": {
        "ko": "모델 전환",
        "zh": "切换模型",
        "en": "Switch model",
    },
    # ── 채팅 UI ──────────────────────────────────────────────────
    "you": {
        "ko": "나",
        "zh": "我",
        "en": "You",
    },
    "thinking": {
        "ko": "생각 중...",
        "zh": "思考中...",
        "en": "Thinking...",
    },
    "input_prompt": {
        "ko": "메시지 입력 (Ctrl+C = 종료, /help = 도움말)",
        "zh": "输入消息（Ctrl+C 退出，/help 帮助）",
        "en": "Type a message (Ctrl+C to quit, /help for help)",
    },
    "empty_input": {
        "ko": "메시지를 입력하세요",
        "zh": "请输入消息",
        "en": "Please enter a message",
    },
    "goodbye": {
        "ko": "빙고를 종료합니다. 안녕히 가세요!",
        "zh": "再见！感谢使用 Bingo。",
        "en": "Goodbye! Thanks for using Bingo.",
    },
    "error": {
        "ko": "오류",
        "zh": "错误",
        "en": "Error",
    },
    "api_error": {
        "ko": "API 오류가 발생했습니다",
        "zh": "API 调用失败",
        "en": "API call failed",
    },
    # ── 명령어 ────────────────────────────────────────────────────
    "help_text": {
        "ko": """/scan <url>              빠른 정찰: WAF + 핑거프린트 + 민감파일
/waf <url>               WAF 탐지 + 자동 우회 시도
/crack [hash]            해시 크랙 — 온라인 조회 → 오프라인 크랙
/stop                    실행 중인 크랙/스캔 중단
/tools                   도구 목록 + 자동 설치
/tools install <이름>    특정 도구 자동 설치
/tools install all       미설치 도구 전체 설치
/model                   AI 모델 추가/변경
/skill <키워드>          스킬 지식베이스 검색
/history                 대화 기록 보기
/export                  대화를 .md 파일로 저장
/config                  현재 설정 보기
/lang                    언어 변경 (ko / zh / en)
/clear                   화면 지우기
/quit                    종료""",
        "zh": """/scan <url>              快速侦察：WAF + 指纹识别 + 敏感文件
/waf <url>               WAF 检测 + 自动绕过尝试
/crack [hash]            哈希破解 — 在线查询 → 离线破解
/stop                    停止正在运行的破解/扫描
/tools                   工具列表 + 自动安装
/tools install <名称>    自动安装指定工具
/tools install all       安装所有缺失工具
/model                   添加/切换 AI 模型
/skill <关键词>          搜索技能知识库
/history                 查看对话历史
/export                  导出对话为 .md 文件
/config                  查看当前配置
/lang                    切换语言 (ko / zh / en)
/clear                   清屏
/quit                    退出""",
        "en": """/scan <url>              Quick recon: WAF + fingerprint + sensitive files
/waf <url>               WAF detection + auto bypass attempt
/crack [hash]            Hash crack — online lookup → offline crack
/stop                    Stop running crack/scan
/tools                   Tool list + auto-install
/tools install <name>    Auto-install a specific tool
/tools install all       Install all missing tools
/model                   Add or switch AI model
/skill <keyword>         Search skill knowledge base
/history                 View chat history
/export                  Export chat as .md file
/config                  View current settings
/lang                    Change language (ko / zh / en)
/clear                   Clear screen
/quit                    Quit""",
    },
    "config_view": {
        "ko": "현재 설정",
        "zh": "当前配置",
        "en": "Current config",
    },
    "history_empty": {
        "ko": "대화 내역이 없습니다",
        "zh": "暂无对话历史",
        "en": "No chat history yet",
    },
    "export_saved": {
        "ko": "대화가 저장되었습니다",
        "zh": "对话已导出",
        "en": "Chat exported",
    },
    "no_model_configured": {
        "ko": "모델이 설정되지 않았습니다. /model 명령어로 추가하세요.",
        "zh": "尚未配置模型，请使用 /model 命令添加。",
        "en": "No model configured. Use /model to add one.",
    },
}


_SLASH_DESC = {
    "/help":    {"ko": "도움말 표시",                  "zh": "显示帮助",             "en": "Show help"},
    "/clear":   {"ko": "화면 초기화",                  "zh": "清屏",                "en": "Clear screen"},
    "/model":   {"ko": "AI 모델 추가/변경",             "zh": "添加/切换 AI 模型",    "en": "Add or switch AI model"},
    "/config":  {"ko": "현재 설정 보기",               "zh": "查看当前配置",          "en": "View current settings"},
    "/history": {"ko": "대화 기록 보기",               "zh": "查看对话历史",          "en": "View chat history"},
    "/export":  {"ko": "대화 기록 파일로 저장",         "zh": "导出对话为 .md 文件",   "en": "Export chat as .md"},
    "/lang":    {"ko": "언어 변경",                    "zh": "切换语言",             "en": "Change language"},
    "/scan":    {"ko": "빠른 레드팀 스캔  /scan <url>", "zh": "快速侦察  /scan <url>","en": "Quick recon  /scan <url>"},
    "/waf":     {"ko": "WAF 탐지 + 자동 우회  /waf <url>","zh": "WAF检测+绕过  /waf <url>","en": "WAF detect + bypass  /waf <url>"},
    "/crack":   {"ko": "해시 크랙  /crack [hash]  (인자 없으면 자동 추출)",
                 "zh": "哈希破解  /crack [hash]  (省略则自动提取)",
                 "en": "Hash crack  /crack [hash]  (auto-extract if omitted)"},
    "/tools":   {"ko": "도구 목록 + 자동 설치  /tools [install <name>|all]",
                 "zh": "工具列表+自动安装  /tools [install <名称>|all]",
                 "en": "Tool list + auto-install  /tools [install <name>|all]"},
    "/skill":   {"ko": "스킬 검색  /skill <키워드>",   "zh": "技能搜索  /skill <关键词>","en": "Skill search  /skill <keyword>"},
    "/stop":    {"ko": "자동 크랙 중단",               "zh": "停止自动破解",          "en": "Stop running crack"},
    "/quit":    {"ko": "종료",                        "zh": "退出",                "en": "Quit"},
}


def get_slash_commands(lang: str = "en") -> list[tuple[str, str]]:
    """슬래시 자동완성 명령어 목록 (현재 언어 기준)"""
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return [(cmd, desc[lang]) for cmd, desc in _SLASH_DESC.items()]


def get_strings(lang: str = "en") -> dict:
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return {k: v[lang] for k, v in _STRINGS.items()}
