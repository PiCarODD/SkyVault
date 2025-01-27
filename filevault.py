import os
import argparse
from flask import Flask, render_template_string, request, send_from_directory, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
app.config['EXTENSION_RULE'] = {'type': None, 'extensions': set()}

# Command-line arguments
parser = argparse.ArgumentParser(description='Secure File Server')
parser.add_argument('-p', '--port', type=int, default=5000)
parser.add_argument('-pass', '--password', help='Server access password')
parser.add_argument('-ext', nargs='+', help='File extensions to filter')
parser.add_argument('-type', choices=['whitelist', 'blacklist'])
parser.add_argument('-dir', '--directory', default='uploads')
args = parser.parse_args()

# Server configuration
app.config['UPLOAD_FOLDER'] = os.path.abspath(args.directory)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if args.ext and args.type:
    app.config['EXTENSION_RULE'] = {
        'type': args.type,
        'extensions': set(ext.lower() for ext in args.ext)
    }
    app.config['ALLOW_ALL_EXTENSIONS'] = False
else:
    app.config['ALLOW_ALL_EXTENSIONS'] = True

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Vault</title>
    <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-dark@4/dark.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .file-list { max-width: 800px; margin: 2rem auto; }
        .drag-drop-area {
            border: 2px dashed #666;
            border-radius: 10px;
            padding: 2rem;
            text-align: center;
            margin: 2rem 0;
            cursor: pointer;
        }
    </style>
</head>
<body class="bg-dark text-light">
    <div class="container">
        <h1 class="text-center my-4">🔒 Secure File Vault</h1>
        <div class="drag-drop-area" id="dropZone">
            <h4>Drag & Drop files here</h4>
            <p>or click to select files</p>
            <input type="file" id="fileInput" hidden>
        </div>

        <div class="file-list">
            <h3>Stored Files</h3>
            <div id="fileList" class="list-group">
                {% for file in files %}
                <div class="list-group-item bg-secondary text-light d-flex justify-content-between align-items-center">
                    <span>{{ file }}</span>
                    <button class="btn btn-sm btn-primary download-btn" data-filename="{{ file }}">
                        Download
                    </button>
                </div>
                {% else %}
                <div class="text-center">No files found</div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script>
        let authPassword = sessionStorage.getItem('fileVaultPassword');
        
        async function verifyPassword() {
            if (!authPassword) {
                const { value: password } = await Swal.fire({
                    title: 'Enter Server Password',
                    input: 'password',
                    inputAttributes: { required: true },
                    showCancelButton: false,
                    confirmButtonText: 'Authenticate'
                });
                
                if (password) {
                    const isValid = await validatePassword(password);
                    if (isValid) {
                        authPassword = password;
                        sessionStorage.setItem('fileVaultPassword', password);
                        return true;
                    }
                }
                return false;
            }
            return true;
        }

        async function validatePassword(password) {
            try {
                const response = await fetch('/verify-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                return response.ok;
            } catch (error) {
                return false;
            }
        }

        async function handleFile(file) {
            if (!(await verifyPassword())) return;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/', {
                    method: 'POST',
                    headers: { 'X-Password': authPassword },
                    body: formData
                });

                if (response.status === 401) {
                    sessionStorage.removeItem('fileVaultPassword');
                    authPassword = null;
                    return handleFile(file);
                }

                if (!response.ok) throw new Error(await response.text());
                
                Swal.fire({
                    icon: 'success',
                    title: 'File uploaded!',
                    showConfirmButton: false,
                    timer: 1500
                });
                setTimeout(() => location.reload(), 1500);
            } catch (error) {
                Swal.fire('Error', error.message, 'error');
            }
        }

        // Event listeners
        document.getElementById('dropZone').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });

        document.getElementById('fileInput').addEventListener('change', (e) => {
            Array.from(e.target.files).forEach(handleFile);
        });

        document.addEventListener('dragover', (e) => e.preventDefault());
        document.addEventListener('drop', (e) => {
            e.preventDefault();
            Array.from(e.dataTransfer.files).forEach(handleFile);
        });

        // Download handling
        document.querySelectorAll('.download-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!(await verifyPassword())) return;
                
                const filename = btn.dataset.filename;
                try {
                    const response = await fetch(`/download/${filename}`, {
                        headers: { 'X-Password': authPassword }
                    });
                    
                    if (response.ok) {
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                    }
                } catch (error) {
                    Swal.fire('Error', 'Failed to download file', 'error');
                }
            });
        });
    </script>
</body>
</html>
'''

def allowed_file(filename):
    if app.config['ALLOW_ALL_EXTENSIONS']:
        return True
    
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    rule = app.config['EXTENSION_RULE']
    
    if rule['type'] == 'whitelist':
        return ext in rule['extensions']
    elif rule['type'] == 'blacklist':
        return ext not in rule['extensions']
    return False

@app.route('/verify-password', methods=['POST'])
def verify_password():
    if not args.password:
        return jsonify({'status': 'ok'})
    
    data = request.get_json()
    if data.get('password') == args.password:
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'invalid'}), 401

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if args.password and request.headers.get('X-Password') != args.password:
            return 'Invalid password', 401
        
        if 'file' not in request.files:
            return 'No file part', 400
            
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return '', 204

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string(HTML_TEMPLATE, files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if args.password and request.headers.get('X-Password') != args.password:
        return 'Invalid password', 401
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=args.port, debug=False)
