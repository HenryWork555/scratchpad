#!/usr/bin/env python3
"""
AI Scratchpad MCP Server

A secure Model Context Protocol server that manages AI scratchpad files for tracking
interruptions, ideas, tasks, and focus during development sessions.

Security Features:
- Input sanitization and validation
- Path traversal protection
- Rate limiting
- Content size limits
- Workspace boundary enforcement
- Error message sanitization
"""

import os
import sys
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from collections import deque
import asyncio

# MCP imports
try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    import mcp.server.stdio
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)


# ========================================
# SECURITY CONFIGURATION
# ========================================

class SecurityConfig:
    """Security configuration constants."""
    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = 60
    RATE_LIMIT_WINDOW = 60  # seconds
    
    # Content limits
    MAX_NOTE_LENGTH = 500
    MAX_TASK_LENGTH = 200
    MAX_FILE_SIZE = 1024 * 1024  # 1MB
    MAX_PATH_LENGTH = 256
    
    # Default scratchpad location
    DEFAULT_SCRATCHPAD_DIR = "scratchpad"  # Creates ~/Desktop/scratchpad/
    DEFAULT_SCRATCHPAD_FILE = "scratchpad.md"
    
    # Dangerous patterns to block
    BLOCKED_PATTERNS = [
        r'\.\.',  # Path traversal
        r'\$',    # Environment variables
        r'`',     # Command execution
        r'<script',  # XSS attempts
        r'javascript:',
        r'file://',
        r'\x00',  # Null bytes
    ]
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'.md', '.txt', '.markdown'}


# Configuration
def get_default_scratchpad_path() -> Path:
    """Get the default scratchpad path on Desktop."""
    home = Path.home()
    desktop = home / "Desktop"
    
    # Fallback to home directory if Desktop doesn't exist
    if not desktop.exists():
        desktop = home
    
    return desktop / SecurityConfig.DEFAULT_SCRATCHPAD_DIR / SecurityConfig.DEFAULT_SCRATCHPAD_FILE

TYPE_EMOJIS = {
    "idea": "💡",
    "bug": "🐛",
    "feature": "✨",
    "question": "❓",
    "contact": "📞",
    "refactor": "🔧",
    "task": "📝",
    "note": "📌",
}

PRIORITY_EMOJIS = {
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
}


# ========================================
# SECURITY UTILITIES
# ========================================

class RateLimiter:
    """Token bucket rate limiter."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
    
    def is_allowed(self) -> tuple[bool, Optional[float]]:
        """Check if request is allowed. Returns (allowed, wait_time)."""
        now = time.time()
        
        # Remove old requests outside the window
        while self.requests and self.requests[0] < now - self.window_seconds:
            self.requests.popleft()
        
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True, None
        
        # Calculate wait time
        oldest = self.requests[0]
        wait_time = self.window_seconds - (now - oldest)
        return False, wait_time


class InputValidator:
    """Input validation and sanitization."""
    
    @staticmethod
    def sanitize_text(text: str, max_length: int, allow_newlines: bool = False) -> str:
        """Sanitize text input."""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        
        # Strip and limit length
        text = text.strip()[:max_length]
        
        # Check for blocked patterns
        for pattern in SecurityConfig.BLOCKED_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                raise ValueError(f"Input contains blocked pattern: {pattern}")
        
        # Remove or escape special characters
        if not allow_newlines:
            text = text.replace('\n', ' ').replace('\r', ' ')
        
        # Escape markdown table pipes
        text = text.replace('|', '\\|')
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        return text
    
    @staticmethod
    def validate_filename(filename: str) -> str:
        """Validate filename (not path, just the file name)."""
        if not isinstance(filename, str):
            raise ValueError("Filename must be a string")
        
        if len(filename) > SecurityConfig.MAX_PATH_LENGTH:
            raise ValueError(f"Filename exceeds maximum length")
        
        # Check for blocked patterns
        for pattern in SecurityConfig.BLOCKED_PATTERNS:
            if re.search(pattern, filename):
                raise ValueError(f"Filename contains blocked pattern")
        
        # No path separators allowed
        if '/' in filename or '\\' in filename:
            raise ValueError("Filename cannot contain path separators")
        
        # Check file extension
        if not any(filename.endswith(ext) for ext in SecurityConfig.ALLOWED_EXTENSIONS):
            raise ValueError(f"File extension must be one of: {SecurityConfig.ALLOWED_EXTENSIONS}")
        
        return filename
    
    @staticmethod
    def validate_enum(value: str, allowed: List[str], default: str) -> str:
        """Validate enum value."""
        if not isinstance(value, str):
            return default
        
        value = value.lower().strip()
        return value if value in allowed else default


class ErrorSanitizer:
    """Sanitize error messages to prevent information disclosure."""
    
    @staticmethod
    def sanitize_error(error: Exception, user_message: str = None) -> str:
        """Sanitize error message."""
        if user_message:
            return user_message
        
        # Map specific errors to safe messages
        error_type = type(error).__name__
        
        safe_messages = {
            'FileNotFoundError': 'Scratchpad file not found',
            'PermissionError': 'Permission denied',
            'ValueError': str(error),  # ValueError messages are controlled by us
            'OSError': 'File system error',
            'UnicodeError': 'Invalid character encoding',
        }
        
        return safe_messages.get(error_type, 'An error occurred')


# ========================================
# SCRATCHPAD MANAGER
# ========================================

class ScratchpadManager:
    """Manages scratchpad file operations with security and validation."""
    
    def __init__(self):
        """Initialize scratchpad manager."""
        # Set default scratchpad location
        self.scratchpad_path = get_default_scratchpad_path()
        self.scratchpad_dir = self.scratchpad_path.parent
        
        self.rate_limiter = RateLimiter(
            SecurityConfig.MAX_REQUESTS_PER_MINUTE,
            SecurityConfig.RATE_LIMIT_WINDOW
        )
        
        # Log initialization
        print(f"🔒 Scratchpad MCP initialized", file=sys.stderr)
        print(f"📁 Scratchpad location: {self.scratchpad_path}", file=sys.stderr)
    
    def _check_rate_limit(self) -> None:
        """Check rate limit and raise error if exceeded."""
        allowed, wait_time = self.rate_limiter.is_allowed()
        if not allowed:
            raise ValueError(
                f"Rate limit exceeded. Please wait {wait_time:.1f} seconds. "
                f"(Max {SecurityConfig.MAX_REQUESTS_PER_MINUTE} requests per minute)"
            )
    
    def _validate_file_size(self, path: Path) -> None:
        """Validate file size is within limits."""
        if path.exists():
            size = path.stat().st_size
            if size > SecurityConfig.MAX_FILE_SIZE:
                raise ValueError(
                    f"File size ({size} bytes) exceeds maximum "
                    f"({SecurityConfig.MAX_FILE_SIZE} bytes)"
                )
    
    def scratchpad_exists(self) -> bool:
        """Check if scratchpad file exists."""
        self._check_rate_limit()
        return self.scratchpad_path.exists()
    
    def create_scratchpad(self) -> Path:
        """Create scratchpad file if it doesn't exist."""
        self._check_rate_limit()
        
        # Check if already exists
        if self.scratchpad_path.exists():
            raise ValueError(f"Scratchpad already exists at: {self.scratchpad_path}")
        
        # Create parent directory
        try:
            self.scratchpad_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ValueError(f"Failed to create directory: {e}")
        
        # Generate template
        today = datetime.now().strftime("%d/%m/%Y")
        template = self._get_template(today)
        
        # Validate template size
        if len(template.encode('utf-8')) > SecurityConfig.MAX_FILE_SIZE:
            raise ValueError("Template exceeds maximum file size")
        
        # Write file
        try:
            self.scratchpad_path.write_text(template, encoding="utf-8")
        except OSError as e:
            raise ValueError(f"Failed to write file: {e}")
        
        print(f"✅ Created scratchpad: {self.scratchpad_path}", file=sys.stderr)
        
        return self.scratchpad_path
    
    def read_scratchpad(self) -> str:
        """Read scratchpad contents."""
        self._check_rate_limit()
        
        if not self.scratchpad_path.exists():
            raise FileNotFoundError("Scratchpad not found. Create one first.")
        
        # Validate file size before reading
        self._validate_file_size(self.scratchpad_path)
        
        try:
            content = self.scratchpad_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ValueError("File contains invalid UTF-8 encoding")
        except OSError as e:
            raise ValueError(f"Failed to read file: {e}")
        
        return content
    
    def write_scratchpad(self, content: str) -> None:
        """Write scratchpad contents."""
        self._check_rate_limit()
        
        if not self.scratchpad_path.exists():
            raise FileNotFoundError("Scratchpad not found. Create one first.")
        
        # Validate content size
        content_bytes = content.encode('utf-8')
        if len(content_bytes) > SecurityConfig.MAX_FILE_SIZE:
            raise ValueError(
                f"Content size ({len(content_bytes)} bytes) exceeds maximum "
                f"({SecurityConfig.MAX_FILE_SIZE} bytes)"
            )
        
        try:
            self.scratchpad_path.write_text(content, encoding="utf-8")
        except OSError as e:
            raise ValueError(f"Failed to write file: {e}")
    
    def log_interruption(
        self,
        note: str,
        type_key: str = "idea",
        priority: str = "medium"
    ) -> Dict[str, Any]:
        """Log an interruption/idea to the scratchpad."""
        # Validate and sanitize inputs
        note = InputValidator.sanitize_text(note, SecurityConfig.MAX_NOTE_LENGTH)
        type_key = InputValidator.validate_enum(
            type_key,
            list(TYPE_EMOJIS.keys()),
            "idea"
        )
        priority = InputValidator.validate_enum(
            priority,
            list(PRIORITY_EMOJIS.keys()),
            "medium"
        )
        
        content = self.read_scratchpad()
        now = datetime.now()
        time_str = now.strftime("%H:%M")
        date_str = now.strftime("%d/%m/%Y")
        date_header = f"### 📅 {date_str}"
        
        # Get emojis and labels
        type_emoji = TYPE_EMOJIS[type_key]
        priority_emoji = PRIORITY_EMOJIS[priority]
        type_label = type_key.capitalize()
        
        new_entry = f"| `{time_str}` | {type_emoji} {type_label} | {note} | {priority_emoji} |"
        
        # Find or create today's section
        lines = content.split("\n")
        interruptions_idx = None
        date_section_idx = None
        table_end_idx = None
        
        for i, line in enumerate(lines):
            if "## 💡 Interruptions / Ideas" in line:
                interruptions_idx = i
            elif interruptions_idx and date_header in line:
                date_section_idx = i
            elif date_section_idx and line.startswith("|") and "---" not in line:
                table_end_idx = i
        
        if date_section_idx is not None and table_end_idx is not None:
            # Date section exists
            if "_No entries yet_" in lines[table_end_idx]:
                lines[table_end_idx] = new_entry
            else:
                lines.insert(table_end_idx + 1, new_entry)
        elif interruptions_idx is not None:
            # Create new date section
            insert_idx = interruptions_idx + 3
            new_section = [
                "",
                date_header,
                "",
                "| Time | Type | Note | Priority |",
                "|------|------|------|----------|",
                new_entry,
            ]
            for idx, section_line in enumerate(new_section):
                lines.insert(insert_idx + idx, section_line)
        else:
            raise ValueError("Invalid scratchpad format: missing Interruptions section")
        
        new_content = "\n".join(lines)
        self.write_scratchpad(new_content)
        
        print(f"📝 Logged: {type_label} - {note[:50]}...", file=sys.stderr)
        
        return {
            "success": True,
            "time": time_str,
            "date": date_str,
            "type": type_label,
            "priority": priority,
            "note": note
        }
    
    def update_focus(self, task: str) -> Dict[str, Any]:
        """Update the current focus section."""
        # Validate and sanitize input
        task = InputValidator.sanitize_text(task, SecurityConfig.MAX_TASK_LENGTH)
        
        content = self.read_scratchpad()
        now = datetime.now()
        time_str = now.strftime("%H:%M")
        
        lines = content.split("\n")
        focus_idx = None
        
        for i, line in enumerate(lines):
            if "## 🎯 Current Focus" in line:
                focus_idx = i
                break
        
        if focus_idx is None:
            raise ValueError("Invalid scratchpad format: missing Current Focus section")
        
        # Update focus section
        lines[focus_idx + 2] = f"**Started:** `{time_str}`  "
        lines[focus_idx + 3] = f"**Task:** {task}"
        
        new_content = "\n".join(lines)
        self.write_scratchpad(new_content)
        
        print(f"🎯 Focus updated: {task[:50]}...", file=sys.stderr)
        
        return {
            "success": True,
            "time": time_str,
            "task": task
        }
    
    def add_to_review_later(self, note: str) -> Dict[str, Any]:
        """Add an item to the 'To Review Later' section."""
        # Validate and sanitize input
        note = InputValidator.sanitize_text(note, SecurityConfig.MAX_NOTE_LENGTH)
        
        content = self.read_scratchpad()
        now = datetime.now()
        date_str = now.strftime("%d/%m/%Y")
        
        lines = content.split("\n")
        review_idx = None
        
        for i, line in enumerate(lines):
            if "## 🔄 To Review Later" in line:
                review_idx = i
                break
        
        if review_idx is None:
            raise ValueError("Invalid scratchpad format: missing To Review Later section")
        
        # Check if section is empty
        if "_Empty - all caught up!_" in lines[review_idx + 4]:
            # Replace empty message with first item
            lines[review_idx + 4] = f"- [ ] {note}"
        else:
            # Add to the list (insert before the "---" separator)
            insert_idx = review_idx + 4
            # Find where items end (before next section)
            for i in range(review_idx + 4, len(lines)):
                if lines[i].strip() == "---":
                    insert_idx = i
                    break
            lines.insert(insert_idx, f"- [ ] {note}")
        
        new_content = "\n".join(lines)
        self.write_scratchpad(new_content)
        self._update_statistics()
        
        print(f"📋 Added to review: {note[:50]}...", file=sys.stderr)
        
        return {
            "success": True,
            "note": note,
            "date": date_str
        }
    
    def mark_completed(self, note: str) -> Dict[str, Any]:
        """Mark an item as completed (adds to Completed Today section)."""
        # Validate and sanitize input
        note = InputValidator.sanitize_text(note, SecurityConfig.MAX_NOTE_LENGTH)
        
        content = self.read_scratchpad()
        now = datetime.now()
        time_str = now.strftime("%H:%M")
        date_str = now.strftime("%d/%m/%Y")
        date_header = f"### 📅 {date_str}"
        
        lines = content.split("\n")
        completed_idx = None
        date_section_idx = None
        
        for i, line in enumerate(lines):
            if "## ✅ Completed Today" in line:
                completed_idx = i
            elif completed_idx and date_header in line:
                date_section_idx = i
                break
        
        if completed_idx is None:
            raise ValueError("Invalid scratchpad format: missing Completed Today section")
        
        # Create completion entry
        completion_entry = f"- [x] {note} _({time_str})_"
        
        if date_section_idx is not None:
            # Date section exists, check if it's empty
            if "_No completions yet_" in lines[date_section_idx + 2]:
                lines[date_section_idx + 2] = completion_entry
            else:
                lines.insert(date_section_idx + 3, completion_entry)
        else:
            # Create new date section
            insert_idx = completed_idx + 3
            new_section = [
                "",
                date_header,
                "",
                completion_entry,
            ]
            for idx, section_line in enumerate(new_section):
                lines.insert(insert_idx + idx, section_line)
        
        new_content = "\n".join(lines)
        self.write_scratchpad(new_content)
        self._update_statistics()
        
        print(f"✅ Completed: {note[:50]}...", file=sys.stderr)
        
        return {
            "success": True,
            "note": note,
            "time": time_str,
            "date": date_str
        }
    
    def archive_item(self, note: str) -> Dict[str, Any]:
        """Archive/dismiss an item."""
        # Validate and sanitize input
        note = InputValidator.sanitize_text(note, SecurityConfig.MAX_NOTE_LENGTH)
        
        content = self.read_scratchpad()
        now = datetime.now()
        date_str = now.strftime("%d/%m/%Y")
        
        lines = content.split("\n")
        archived_idx = None
        
        for i, line in enumerate(lines):
            if "## 🗑️ Archived / Dismissed" in line:
                archived_idx = i
                break
        
        if archived_idx is None:
            raise ValueError("Invalid scratchpad format: missing Archived section")
        
        # Find the "Old Ideas / Resolved Items" section inside details
        old_ideas_idx = None
        for i in range(archived_idx, len(lines)):
            if "### Old Ideas / Resolved Items" in lines[i]:
                old_ideas_idx = i
                break
        
        if old_ideas_idx is None:
            raise ValueError("Invalid scratchpad format: missing Old Ideas section")
        
        # Check if section is empty
        if "_Nothing archived yet_" in lines[old_ideas_idx + 2]:
            lines[old_ideas_idx + 2] = f"- ~~{note}~~ _({date_str})_"
        else:
            lines.insert(old_ideas_idx + 3, f"- ~~{note}~~ _({date_str})_")
        
        new_content = "\n".join(lines)
        self.write_scratchpad(new_content)
        self._update_statistics()
        
        print(f"🗑️ Archived: {note[:50]}...", file=sys.stderr)
        
        return {
            "success": True,
            "note": note,
            "date": date_str
        }
    
    def _update_statistics(self) -> None:
        """Update usage statistics automatically."""
        content = self.read_scratchpad()
        now = datetime.now()
        date_str = now.strftime("%d/%m/%Y")
        
        lines = content.split("\n")
        
        # Count items in each section
        total_logged = 0
        total_completed = 0
        total_archived = 0
        
        in_interruptions = False
        in_completed = False
        in_archived = False
        
        for line in lines:
            if "## 💡 Interruptions / Ideas" in line:
                in_interruptions = True
                in_completed = False
                in_archived = False
            elif "## ✅ Completed Today" in line:
                in_interruptions = False
                in_completed = True
                in_archived = False
            elif "## 🗑️ Archived / Dismissed" in line:
                in_interruptions = False
                in_completed = False
                in_archived = True
            elif line.startswith("##"):
                in_interruptions = False
                in_completed = False
                in_archived = False
            
            # Count items
            if in_interruptions and line.startswith("| `"):
                total_logged += 1
            elif in_completed and line.startswith("- [x]"):
                total_completed += 1
            elif in_archived and line.startswith("- ~~"):
                total_archived += 1
        
        # Update statistics section
        stats_idx = None
        for i, line in enumerate(lines):
            if "## 📊 Usage Statistics" in line:
                stats_idx = i
                break
        
        if stats_idx is not None:
            # Update the statistics lines
            lines[stats_idx + 2] = f"- **Total Ideas Logged:** {total_logged}"
            lines[stats_idx + 3] = f"- **Items Completed:** {total_completed}"
            lines[stats_idx + 4] = f"- **Items Archived:** {total_archived}"
            lines[stats_idx + 5] = f"- **Last Updated:** {date_str}"
            
            new_content = "\n".join(lines)
            
            # Write without checking rate limit (internal update)
            content_bytes = new_content.encode('utf-8')
            if len(content_bytes) <= SecurityConfig.MAX_FILE_SIZE:
                try:
                    self.scratchpad_path.write_text(new_content, encoding="utf-8")
                except OSError:
                    pass  # Silently fail on stats update
    
    def _get_template(self, date: str) -> str:
        """Get scratchpad template."""
        return f"""# 📋 AI Scratchpad

A dynamic workspace for tracking tasks, ideas, and interruptions during development sessions.

---

## 🎯 Current Focus

**Started:** `--:--`  
**Task:** _No active task_

---

## 💡 Interruptions / Ideas

Quick-capture zone for thoughts that pop up during focused work.

### 📅 {date}

| Time | Type | Note | Priority |
|------|------|------|----------|
| _No entries yet_ | | | |

**Legend:**
- **Types:** 💡 Idea | 🐛 Bug | ✨ Feature | ❓ Question | 📞 Contact | 🔧 Refactor | 📝 Task | 📌 Note
- **Priority:** 🔴 High | 🟡 Medium | 🟢 Low

---

## 🔄 To Review Later

Items logged during work sessions that need follow-up or consideration.

_Empty - all caught up!_

---

## ✅ Completed Today

### 📅 {date}

_No completions yet_

---

## 🗑️ Archived / Dismissed

<details>
<summary>Click to expand archived items</summary>

### Old Ideas / Resolved Items

_Nothing archived yet_

</details>

---

## 📊 Usage Statistics

- **Total Ideas Logged:** 0
- **Items Completed:** 0
- **Items Archived:** 0
- **Last Updated:** {date}

---

## 🔧 Quick Reference

### Auto-logging Triggers
When these phrases are detected, items are automatically logged:
- "Remind me to..."
- "I should..."
- "Don't forget..."
- "Later I need to..."
- "Oh, I just thought of..."

### Workflow
1. **During Work:** Mention off-topic ideas → AI asks to log → Continues main task
2. **Starting Task:** Update Current Focus section
3. **Completing Items:** Move from "To Review Later" to "Completed Today"
4. **Dismissing Items:** Move to "Archived / Dismissed"

---

_Last session: {date} at --:--_
"""


# ========================================
# MCP SERVER
# ========================================

# Initialize MCP server
app = Server("scratchpad-mcp")

# Initialize manager
try:
    manager = ScratchpadManager()
except Exception as e:
    print(f"❌ Failed to initialize scratchpad manager: {e}", file=sys.stderr)
    sys.exit(1)


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available scratchpad management tools."""
    return [
        Tool(
            name="scratchpad_read",
            description="Read the contents of the scratchpad file. Rate limited to 60 requests/minute.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="scratchpad_create",
            description=(
                "Create a new scratchpad file at ~/Desktop/scratchpad/scratchpad.md. "
                "Creates the directory if it doesn't exist."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="scratchpad_log_interruption",
            description=(
                "Log an interruption, idea, bug, or task to the scratchpad. "
                f"Note limited to {SecurityConfig.MAX_NOTE_LENGTH} characters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The note/idea to log",
                        "maxLength": SecurityConfig.MAX_NOTE_LENGTH,
                    },
                    "type": {
                        "type": "string",
                        "description": "Type of entry",
                        "enum": list(TYPE_EMOJIS.keys()),
                        "default": "idea",
                    },
                    "priority": {
                        "type": "string",
                        "description": "Priority level",
                        "enum": list(PRIORITY_EMOJIS.keys()),
                        "default": "medium",
                    },
                },
                "required": ["note"],
            },
        ),
        Tool(
            name="scratchpad_update_focus",
            description=(
                "Update the current focus/task in the scratchpad. "
                f"Task limited to {SecurityConfig.MAX_TASK_LENGTH} characters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "Description of the current task",
                        "maxLength": SecurityConfig.MAX_TASK_LENGTH,
                    }
                },
                "required": ["task"],
            },
        ),
        Tool(
            name="scratchpad_get_path",
            description="Get the scratchpad file path and check if it exists",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="scratchpad_add_to_review_later",
            description=(
                "Add an item to the 'To Review Later' section for follow-up. "
                f"Note limited to {SecurityConfig.MAX_NOTE_LENGTH} characters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The item to add for review later",
                        "maxLength": SecurityConfig.MAX_NOTE_LENGTH,
                    }
                },
                "required": ["note"],
            },
        ),
        Tool(
            name="scratchpad_mark_completed",
            description=(
                "Mark an item as completed. Adds it to 'Completed Today' section. "
                f"Note limited to {SecurityConfig.MAX_NOTE_LENGTH} characters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The completed item",
                        "maxLength": SecurityConfig.MAX_NOTE_LENGTH,
                    }
                },
                "required": ["note"],
            },
        ),
        Tool(
            name="scratchpad_archive_item",
            description=(
                "Archive/dismiss an item. Moves it to 'Archived / Dismissed' section. "
                f"Note limited to {SecurityConfig.MAX_NOTE_LENGTH} characters."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": "The item to archive",
                        "maxLength": SecurityConfig.MAX_NOTE_LENGTH,
                    }
                },
                "required": ["note"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls with comprehensive error handling."""
    try:
        if name == "scratchpad_read":
            content = manager.read_scratchpad()
            return [TextContent(type="text", text=content)]
        
        elif name == "scratchpad_create":
            path = manager.create_scratchpad()
            return [TextContent(
                type="text",
                text=f"✅ Scratchpad created at: {path}"
            )]
        
        elif name == "scratchpad_log_interruption":
            note = arguments.get("note", "")
            if not note:
                raise ValueError("Note is required")
            
            type_key = arguments.get("type", "idea")
            priority = arguments.get("priority", "medium")
            
            result = manager.log_interruption(note, type_key, priority)
            
            response = (
                f"✅ Logged to scratchpad at {result['time']}\n\n"
                f"**Type:** {result['type']} | **Priority:** {priority.capitalize()}\n"
                f"**Note:** {result['note']}"
            )
            return [TextContent(type="text", text=response)]
        
        elif name == "scratchpad_update_focus":
            task = arguments.get("task", "")
            if not task:
                raise ValueError("Task is required")
            
            result = manager.update_focus(task)
            
            response = (
                f"✅ Current focus updated at {result['time']}\n\n"
                f"**Task:** {result['task']}"
            )
            return [TextContent(type="text", text=response)]
        
        elif name == "scratchpad_get_path":
            exists = manager.scratchpad_exists()
            status = "✅ exists" if exists else "❌ not found"
            return [TextContent(
                type="text",
                text=f"📍 Scratchpad location: {manager.scratchpad_path}\nStatus: {status}"
            )]
        
        elif name == "scratchpad_add_to_review_later":
            note = arguments.get("note", "")
            if not note:
                raise ValueError("Note is required")
            
            result = manager.add_to_review_later(note)
            
            response = (
                f"✅ Added to 'To Review Later'\n\n"
                f"**Note:** {result['note']}"
            )
            return [TextContent(type="text", text=response)]
        
        elif name == "scratchpad_mark_completed":
            note = arguments.get("note", "")
            if not note:
                raise ValueError("Note is required")
            
            result = manager.mark_completed(note)
            
            response = (
                f"✅ Marked as completed at {result['time']}\n\n"
                f"**Note:** {result['note']}"
            )
            return [TextContent(type="text", text=response)]
        
        elif name == "scratchpad_archive_item":
            note = arguments.get("note", "")
            if not note:
                raise ValueError("Note is required")
            
            result = manager.archive_item(note)
            
            response = (
                f"✅ Archived/dismissed\n\n"
                f"**Note:** {result['note']}"
            )
            return [TextContent(type="text", text=response)]
        
        else:
            return [TextContent(
                type="text",
                text=f"❌ Unknown tool: {name}"
            )]
    
    except Exception as e:
        # Sanitize error message
        safe_error = ErrorSanitizer.sanitize_error(e)
        error_msg = f"❌ Error: {safe_error}"
        
        # Log full error for debugging (stderr)
        print(f"⚠️ Error in {name}: {type(e).__name__}: {str(e)}", file=sys.stderr)
        
        return [TextContent(type="text", text=error_msg)]


async def main():
    """Run the MCP server."""
    print("🚀 Starting Scratchpad MCP Server...", file=sys.stderr)
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Scratchpad MCP Server stopped", file=sys.stderr)
    except Exception as e:
        print(f"❌ Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
