# SkyVault 🔒📁

A secure, modern file transfer server with authentication and extension filtering capabilities.

![SkyVault Interface](https://github.com/PiCarODD/filevault-server/blob/main/image.png)

## Features ✨
- 🔑 Password protection for all operations
- 🎨 Modern UI with drag-and-drop capabilities
- ⚙️ Configurable file extension rules (whitelist/blacklist)
- 📤📥 Secure file upload/download functionality
- 🔒 Built-in security measures:
  - File type validation
  - Secure filename handling
  - HTTP Basic Authentication
- ⚡️ Real-time upload feedback
- 📱 Responsive design
- 🛠️ CLI configuration options

## Installation 💻

### Requirements
- Python 3.8+
- pip package manager

```bash
# Clone repository
git clone https://github.com/PiCarODD/filevault-server.git
cd filevault-server

# Install dependencies
pip install -r requirements.txt
```

## Usage
# Basic Usage
```python filevault.py```

# Advanced Examples
1. Password protected server on port 9000:

```python filevault.py -pass MyStrongPassword! --port 9000```

2. Whitelist only image files:

```python filevault.py -ext png jpg jpeg gif -type whitelist```

3. Blacklist dangerous extensions:

```python filevault.py -ext exe bat sh -type blacklist```

4. Specify directory
```python filevault.py -dir /tmp```

4. Combined configuration:

```python filevault.py -pass Admin123 -ext pdf docx xlsx -type whitelist --port 8080 -dir .```

# Command-Line Options

| Option        | Description                    | Default |
|---------------|--------------------------------|---------|
| `-p`, `--port` | Server port                   | 5000    |
| `-pass`       | Set password protection        | None    |
| `-ext`        | File extensions to filter      | All allowed |
| `-type`       | Filter type (whitelist/blacklist) | None |
| `-dir`       | Specify Directory | None |

---

## Security Considerations 🔐

- Always use HTTPS in production environments.
- Regularly rotate passwords.
- Combine with firewall rules for network protection.
- Use a whitelisting approach for maximum security.
- Store uploaded files in an isolated environment.

---

## License 📄

**MIT License** - See [LICENSE](LICENSE) for details.

---

## Warning

This is a development server. For production use, consider adding:

1. Reverse proxy (e.g., Nginx).
2. SSL encryption.
3. Rate limiting.
4. Detailed audit logging.
5. Virus scanning integration.


