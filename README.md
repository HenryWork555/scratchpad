# AI Scratchpad MCP Server

A secure Model Context Protocol (MCP) server for managing AI scratchpad files during development sessions. Track interruptions, ideas, tasks, and maintain focus while coding.

## 🔒 Security Features

* **Input Validation**: Comprehensive sanitization of all user inputs
* **Rate Limiting**: 60 requests/minute protection against abuse
* **Path Traversal Protection**: Workspace boundary enforcement
* **Content Size Limits**: Max 1MB file size, 500 char notes
* **Allowed Directory Restrictions**: Only approved locations
* **Error Sanitization**: Prevents sensitive information disclosure

## Features

* 📝 **Log Interruptions**: Capture ideas without losing focus
* 🎯 **Track Current Focus**: Update and maintain your current task
* 📊 **Organized Storage**: Markdown-based scratchpad with sections
* 🔐 **Secure by Design**: Input validation, rate limiting, path protection
* ⚡ **Fast & Lightweight**: Minimal dependencies, quick operations

## Installation

### Prerequisites

* Python 3.8+
* MCP-compatible client (Claude Desktop, etc.)

### Setup

1. **Clone or download this project**:
```bash
cd ~/Documents/GitHub/scratchpad
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Make the server executable**:
```bash
chmod +x src/server.py
```

## Usage

### As an MCP Server

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "scratchpad": {
      "command": "python3",
      "args": ["/path/to/scratchpad/src/server.py"],
      "env": {
        "WORKSPACE_PATH": "/path/to/your-project"
      }
    }
  }
}
```

### Available Tools

#### 1. `scratchpad_create`
Create a new scratchpad file.

**Parameters:**
- `location` (optional): Path relative to workspace (default: `.idea/scratchpad.md`)

**Example:**
```json
{
  "location": ".idea/scratchpad.md"
}
```

#### 2. `scratchpad_find`
Find existing scratchpad in workspace.

**No parameters required.**

#### 3. `scratchpad_read`
Read the entire scratchpad contents.

**No parameters required.**

#### 4. `scratchpad_log_interruption`
Log an idea, bug, or interruption.

**Parameters:**
- `note` (required): The note to log (max 500 chars)
- `type` (optional): One of: idea, bug, feature, question, contact, refactor, task, note
- `priority` (optional): One of: high, medium, low

**Example:**
```json
{
  "note": "Add error handling to API client",
  "type": "bug",
  "priority": "high"
}
```

#### 5. `scratchpad_update_focus`
Update your current focus/task.

**Parameters:**
- `task` (required): Description of current task (max 200 chars)

**Example:**
```json
{
  "task": "Implementing user authentication flow"
}
```

## 🔒 Security Configuration

### Allowed Directories
Scratchpads must be created in:
- `.idea/`
- `.vscode/`
- `.dart_tool/`
- `.cache/`
- `docs/`
- `.scratchpad/`

### File Restrictions
- **Extensions**: Only `.md`, `.txt`, `.markdown`
- **Max size**: 1MB
- **Path length**: 256 characters max

### Rate Limiting
- **Limit**: 60 requests per minute
- **Window**: Rolling 60-second window
- **Scope**: Per-process (resets on server restart)

### Input Sanitization
All inputs are sanitized to prevent:
- Path traversal attacks (`..`, `~`)
- Command injection (`` ` ``, `$`)
- XSS attempts (`<script>`, `javascript:`)
- Null byte injection (`\x00`)

### Content Limits
- **Notes**: 500 characters maximum
- **Tasks**: 200 characters maximum
- **File size**: 1MB maximum

## Security Best Practices

### 1. Workspace Isolation
Always set `WORKSPACE_PATH` to restrict operations to a specific directory:

```bash
export WORKSPACE_PATH="/path/to/your-project"
```

### 2. File Permissions
Ensure scratchpad directories have appropriate permissions:

```bash
chmod 755 .idea
chmod 644 .idea/scratchpad.md
```

### 3. Regular Cleanup
Monitor scratchpad file sizes and archive old content regularly.

### 4. Error Monitoring
Check stderr output for security warnings:

```bash
python3 src/server.py 2>scratchpad-errors.log
```

## Troubleshooting

### "Rate limit exceeded" Error
Wait for the specified time or restart the server to reset the rate limiter.

### "Path must be within workspace" Error
Ensure your `WORKSPACE_PATH` is set correctly and the location is valid.

### "File extension must be one of..." Error
Use only `.md`, `.txt`, or `.markdown` files.

### "Scratchpad not found" Error
Create a scratchpad first using `scratchpad_create`.

## Development

### Testing

Test the server directly:

```bash
cd ~/Documents/GitHub/scratchpad
python3 src/server.py
```

### Debugging

The server outputs operational info to stderr:

```
🔒 Scratchpad MCP initialized
📁 Workspace: /path/to/your-project
✅ Created scratchpad: .idea/scratchpad.md
📝 Logged: Bug - Add error handling...
```

## License

MIT License - feel free to use and modify as needed.

## Security Reporting

If you discover a security vulnerability, please report it privately rather than creating a public issue.

