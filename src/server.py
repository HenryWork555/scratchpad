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
    
    # Allowed scratchpad locations (relative to workspace)
    ALLOWED_DIRECTORIES = {
        ".idea",
        ".vscode",
        ".dart_tool",
        ".cache",
        "docs",
        ".scratchpad",
    }
    
    # Dangerous patterns to block
    BLOCKED_PATTERNS = [
        r'\.\.',  # Path traversal
        r'~',     # Home directory
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
SCRATCHPAD_SEARCH_PATHS = [
    ".idea/scratchpad.md",
    ".vscode/scratchpad.md",
    ".dart_tool/scratchpad.md",
    ".cache/scratchpad.md",
    ".scratchpad/scratchpad.md",
]

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
    def validate_path(path: str, workspace: Path) -> Path:
        """Validate and resolve path safely."""
        if not isinstance(path, str):
            raise ValueError("Path must be a string")
        
        if len(path) > SecurityConfig.MAX_PATH_LENGTH:
            raise ValueError(f"Path exceeds maximum length of {SecurityConfig.MAX_PATH_LENGTH}")
        
        # Check for blocked patterns
        for pattern in SecurityConfig.BLOCKED_PATTERNS:
            if re.search(pattern, path):
                raise ValueError(f"Path contains blocked pattern")
        
        # Convert to Path and resolve
        try:
            full_path = (workspace / path).resolve()
        except (ValueError, OSError) as e:
            raise ValueError(f"Invalid path: {e}")
        
        # Ensure path is within workspace
        try:
            full_path.relative_to(workspace.resolve())
        except ValueError:
            raise ValueError("Path must be within workspace")
        
        # Check file extension
        if full_path.suffix.lower() not in SecurityConfig.ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension must be one of: {SecurityConfig.ALLOWED_EXTENSIONS}")
        
        # Check directory is allowed
        try:
            relative = full_path.relative_to(workspace.resolve())
            top_dir = relative.parts[0] if relative.parts else None
            
            if top_dir and top_dir not in SecurityConfig.ALLOWED_DIRECTORIES:
                raise ValueError(
                    f"Scratchpad must be in allowed directory: {SecurityConfig.ALLOWED_DIRECTORIES}"
                )
        except (ValueError, IndexError):
            raise ValueError("Invalid directory structure")
        
        return full_path
    
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
    
    def __init__(self, workspace_path: Optional[str] = None):
        """Initialize scratchpad manager."""
        # Set workspace
        if workspace_path:
            self.workspace_path = Path(workspace_path).resolve()
        else:
            self.workspace_path = Path.cwd().resolve()
        
        # Verify workspace exists and is accessible
        if not self.workspace_path.exists():
            raise ValueError(f"Workspace path does not exist: {self.workspace_path}")
        
        if not self.workspace_path.is_dir():
            raise ValueError(f"Workspace path is not a directory: {self.workspace_path}")
        
        self._scratchpad_path: Optional[Path] = None
        self.rate_limiter = RateLimiter(
            SecurityConfig.MAX_REQUESTS_PER_MINUTE,
            SecurityConfig.RATE_LIMIT_WINDOW
        )
        
        # Log initialization
        print(f"🔒 Scratchpad MCP initialized", file=sys.stderr)
        print(f"📁 Workspace: {self.workspace_path}", file=sys.stderr)
    
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
    
    def find_scratchpad(self) -> Optional[Path]:
        """Find scratchpad in standard locations."""
        self._check_rate_limit()
        
        if self._scratchpad_path and self._scratchpad_path.exists():
            return self._scratchpad_path
        
        for search_path in SCRATCHPAD_SEARCH_PATHS:
            try:
                full_path = InputValidator.validate_path(search_path, self.workspace_path)
                if full_path.exists():
                    self._validate_file_size(full_path)
                    self._scratchpad_path = full_path
                    return full_path
            except ValueError:
                continue  # Skip invalid paths
        
        return None
    
    def create_scratchpad(self, location: str = ".idea/scratchpad.md") -> Path:
        """Create a new scratchpad at specified location."""
        self._check_rate_limit()
        
        # Validate and resolve path
        full_path = InputValidator.validate_path(location, self.workspace_path)
        
        # Check if already exists
        if full_path.exists():
            raise ValueError(f"Scratchpad already exists at: {location}")
        
        # Create parent directories
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
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
            full_path.write_text(template, encoding="utf-8")
        except OSError as e:
            raise ValueError(f"Failed to write file: {e}")
        
        self._scratchpad_path = full_path
        print(f"✅ Created scratchpad: {full_path}", file=sys.stderr)
        
        return full_path
    
    def read_scratchpad(self) -> str:
        """Read scratchpad contents."""
        self._check_rate_limit()
        
        path = self.find_scratchpad()
        if not path:
            raise FileNotFoundError("Scratchpad not found. Create one first.")
        
        # Validate file size before reading
        self._validate_file_size(path)
        
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ValueError("File contains invalid UTF-8 encoding")
        except OSError as e:
            raise ValueError(f"Failed to read file: {e}")
        
        return content
    
    def write_scratchpad(self, content: str) -> None:
        """Write scratchpad contents."""
        self._check_rate_limit()
        
        path = self.find_scratchpad()
        if not path:
            raise FileNotFoundError("Scratchpad not found. Create one first.")
        
        # Validate content size
        content_bytes = content.encode('utf-8')
        if len(content_bytes) > SecurityConfig.MAX_FILE_SIZE:
            raise ValueError(
                f"Content size ({len(content_bytes)} bytes) exceeds maximum "
                f"({SecurityConfig.MAX_FILE_SIZE} bytes)"
            )
        
        try:
            path.write_text(content, encoding="utf-8")
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

# Initialize manager (will be created per-workspace)
try:
    workspace = os.getenv("WORKSPACE_PATH") or os.getcwd()
    manager = ScratchpadManager(workspace)
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
                "Create a new scratchpad at the specified location. "
                f"Location must be in allowed directories: {SecurityConfig.ALLOWED_DIRECTORIES}. "
                f"Must have extension: {SecurityConfig.ALLOWED_EXTENSIONS}"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "Path for scratchpad (default: .idea/scratchpad.md)",
                        "default": ".idea/scratchpad.md",
                        "maxLength": SecurityConfig.MAX_PATH_LENGTH,
                    }
                },
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
            name="scratchpad_find",
            description="Find the scratchpad location in the workspace",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
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
            location = arguments.get("location", ".idea/scratchpad.md")
            path = manager.create_scratchpad(location)
            rel_path = path.relative_to(manager.workspace_path)
            return [TextContent(
                type="text",
                text=f"✅ Scratchpad created at: {rel_path}"
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
        
        elif name == "scratchpad_find":
            path = manager.find_scratchpad()
            if path:
                rel_path = path.relative_to(manager.workspace_path)
                return [TextContent(
                    type="text",
                    text=f"📍 Scratchpad found at: {rel_path}"
                )]
            else:
                return [TextContent(
                    type="text",
                    text="❌ No scratchpad found. Use scratchpad_create to create one."
                )]
        
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
