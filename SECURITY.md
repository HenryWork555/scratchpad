# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

### Input Validation
- All text inputs sanitized against injection attacks
- Path traversal protection with workspace boundary checks
- Enum validation for type and priority fields
- Maximum length enforcement on all inputs

### Rate Limiting
- 60 requests per minute per process
- Token bucket algorithm implementation
- Graceful degradation with wait time notifications

### File System Security
- Workspace isolation enforcement
- Allowed directory whitelist
- File extension restrictions
- File size limits (1MB max)
- Path length limits (256 chars max)

### Error Handling
- Sanitized error messages prevent information disclosure
- Separate debug logging to stderr
- Controlled error propagation

## Reporting a Vulnerability

To report a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email the maintainer directly with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

Expected response time: 48 hours

## Security Best Practices for Users

### 1. Set WORKSPACE_PATH
Always specify a workspace path to prevent unauthorized file access:

```bash
export WORKSPACE_PATH="/path/to/your/project"
```

### 2. Monitor Rate Limits
If you see rate limit errors, investigate potential abuse or misconfiguration.

### 3. Review Scratchpad Locations
Only create scratchpads in approved directories:
- `.idea/`
- `.vscode/`
- `.dart_tool/`
- `.cache/`
- `docs/`
- `.scratchpad/`

### 4. Check Permissions
Ensure proper file permissions on scratchpad files and directories.

### 5. Monitor Logs
Check stderr for security warnings and operational issues.

## Known Limitations

1. **Rate Limiting Scope**: Per-process, not global across multiple instances
2. **File Locking**: No concurrent write protection (use single instance per workspace)
3. **Encryption**: Scratchpad files stored in plaintext (don't store sensitive data)

## Security Updates

Security patches will be released as needed. Check releases for security updates.

