import os
import argparse
from flask import Flask, render_template_string, request, send_from_directory, redirect, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
app.config['ALLOW_ALL_EXTENSIONS'] = True
app.config['EXTENSION_RULE'] = {'type': None, 'extensions': set()}

# Command-line arguments parsing
parser = argparse.ArgumentParser(description='File Server')
parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run server on')
parser.add_argument('-pass', '--password', help='Password protection')
parser.add_argument('-ext', nargs='+', help='File extensions to allow/block')
parser.add_argument('-type', choices=['whitelist', 'blacklist'], 
                   help='Extension rule type (whitelist/blacklist)')
args = parser.parse_args()

if args.ext and not args.type:
    parser.error("-ext requires -type (whitelist/blacklist)")

if args.ext and args.type:
    app.config['ALLOW_ALL_EXTENSIONS'] = False
    app.config['EXTENSION_RULE'] = {
        'type': args.type,
        'extensions': set(args.ext)
    }

users = {}
if args.password:
    users['admin'] = generate_password_hash(args.password)

@auth.verify_password
def verify_password(username, password):
    if not args.password:
        return True
    return check_password_hash(users.get('admin'), password)

# Create upload directory if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Server</title>
    <link href="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.0.0-beta.25/dist/themes/light.css" relstylesheet>
    <style>
        :root {
            --sl-spacing-medium: 1rem;
            --sl-color-primary-600: #2563eb;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 2rem;
            background-color: #f3f4f6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 2rem;
        }
        
        .upload-section {
            margin-bottom: 2rem;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 2rem;
        }
        
        .file-list {
            display: grid;
            gap: 0.5rem;
        }
        
        .file-card {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            transition: background-color 0.2s;
        }
        
        .file-card:hover {
            background-color: #f8fafc;
        }
        
        .alert {
            padding: 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
        }
        
        .alert-success {
            background-color: #dcfce7;
            color: #166534;
        }
        
        .alert-error {
            background-color: #fee2e2;
            color: #991b1b;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure File Server</h1>
        
        <div class="upload-section">
            <h2>Upload File</h2>
            <form method="post" enctype="multipart/form-data" onsubmit="handleUpload(event)">
                <sl-input type="file" name="file" label="Choose file" required></sl-input>
                <sl-button type="submit" variant="primary" style="margin-top: 1rem">Upload</sl-button>
            </form>
            
            {% if upload_message %}
                <div class="alert alert-{{ upload_message.type }}">
                    {{ upload_message.text }}
                </div>
            {% endif %}
        </div>

        <h2>Available Files</h2>
        <div class="file-list">
            {% for file in files %}
                <div class="file-card">
                    <span>{{ file }}</span>
                    <sl-button href="/download/{{ file }}" variant="default">
                        Download
                    </sl-button>
                </div>
            {% else %}
                <div class="alert">
                    No files available
                </div>
            {% endfor %}
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@shoelace-style/shoelace@2.0.0-beta.25/dist/shoelace.js"></script>
    <script>
        function handleUpload(e) {
            const button = e.target.querySelector('sl-button');
            button.setAttribute('loading', '');
        }
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

@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def index():
    upload_message = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            upload_message = {'type': 'error', 'text': 'No file selected'}
        else:
            file = request.files['file']
            if file.filename == '':
                upload_message = {'type': 'error', 'text': 'No file selected'}
            elif not allowed_file(file.filename):
                upload_message = {'type': 'error', 'text': 'File type not allowed'}
            else:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                upload_message = {'type': 'success', 'text': 'File uploaded successfully'}

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string(HTML_TEMPLATE, files=files, upload_message=upload_message)

@app.route('/download/<filename>')
@auth.login_required
def download_file(filename):
    if not os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        abort(404)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=args.port, debug=False)
