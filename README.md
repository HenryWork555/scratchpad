# AI Scratchpad MCP Server

A secure Model Context Protocol (MCP) server for managing a global AI scratchpad file. Track interruptions, ideas, tasks, and maintain focus across all your projects with a single scratchpad on your Desktop.

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
* 🔄 **Review Later**: Queue items for follow-up consideration
* ✅ **Mark Completed**: Track accomplishments with timestamps
* 🗑️ **Archive Items**: Dismiss or archive old ideas
* 📊 **Auto Statistics**: Automatically tracks logged, completed, and archived items
* 🌍 **Global Scratchpad**: Single scratchpad on Desktop accessible from all projects
* 📋 **Organized Storage**: Markdown-based scratchpad with sections
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
      "args": ["/path/to/scratchpad/src/server.py"]
    }
  }
}
```

The scratchpad will be created at `~/Desktop/scratchpad/scratchpad.md` and accessible from all your projects.

### Available Tools

#### 1. `scratchpad_create`
Create a new scratchpad file at `~/Desktop/scratchpad/scratchpad.md`.

**No parameters required.**

#### 2. `scratchpad_get_path`
Get the scratchpad file path and check if it exists.

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

#### 6. `scratchpad_add_to_review_later`
Add an item to the "To Review Later" section for follow-up.

**Parameters:**
- `note` (required): The item to add (max 500 chars)

**Example:**
```json
{
  "note": "Research better caching strategy for API calls"
}
```

#### 7. `scratchpad_mark_completed`
Mark an item as completed. Adds it to "Completed Today" with timestamp and **removes it from Interruptions/Review Later**.

**Parameters:**
- `note` (required): The completed item (max 500 chars)

**Example:**
```json
{
  "note": "Fixed authentication bug in login flow"
}
```

#### 8. `scratchpad_archive_item`
Archive/dismiss an item. Moves it to "Archived / Dismissed" section and **removes it from Interruptions/Review Later**.

**Parameters:**
- `note` (required): The item to archive (max 500 chars)

**Example:**
```json
{
  "note": "Old idea that's no longer relevant"
}
```

## 🔒 Security Configuration

### Scratchpad Location
The scratchpad is always located at:
- **Primary**: `~/Desktop/scratchpad/scratchpad.md`
- **Fallback**: `~/scratchpad/scratchpad.md` (if Desktop doesn't exist)

This fixed location prevents path traversal attacks and unauthorized file access.

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

### 1. File Permissions
Ensure the scratchpad directory has appropriate permissions:

```bash
chmod 755 ~/Desktop/scratchpad
chmod 644 ~/Desktop/scratchpad/scratchpad.md
```

### 2. Regular Cleanup
Monitor scratchpad file sizes and archive old content regularly.

### 3. Error Monitoring
Check stderr output for security warnings:

```bash
python3 src/server.py 2>scratchpad-errors.log
```

## Troubleshooting

### "Rate limit exceeded" Error
Wait for the specified time or restart the server to reset the rate limiter.

### "Scratchpad not found" Error
The scratchpad doesn't exist yet. Use `scratchpad_create` to create it at `~/Desktop/scratchpad/scratchpad.md`.

### Desktop Not Found
If `~/Desktop` doesn't exist, the scratchpad will be created at `~/scratchpad/scratchpad.md` instead.

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
📁 Scratchpad location: /Users/username/Desktop/scratchpad/scratchpad.md
✅ Created scratchpad: /Users/username/Desktop/scratchpad/scratchpad.md
📝 Logged: Bug - Add error handling...
```

## License

MIT License - feel free to use and modify as needed.

## Security Reporting

If you discover a security vulnerability, please report it privately rather than creating a public issue.

