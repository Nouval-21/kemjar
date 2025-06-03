#!/usr/bin/env python3
"""
Advanced Flask Template Debugging Script
Solusi untuk masalah template file terdeteksi 0 bytes
"""

import os
import sys
import stat
import chardet
from pathlib import Path

def check_file_details(file_path):
    """Check detail lengkap file"""
    try:
        # Basic file info
        file_stat = os.stat(file_path)
        
        # File permissions
        permissions = oct(file_stat.st_mode)[-3:]
        
        # Try to read file with different methods
        content = None
        encoding = 'unknown'
        
        # Method 1: Auto-detect encoding
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                if raw_data:
                    detected = chardet.detect(raw_data)
                    encoding = detected.get('encoding', 'unknown')
                    content = raw_data.decode(encoding)
                else:
                    content = ""
        except Exception as e:
            print(f"      ⚠️ Error reading with auto-detect: {e}")
        
        # Method 2: Try UTF-8
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    encoding = 'utf-8'
            except Exception as e:
                print(f"      ⚠️ Error reading with UTF-8: {e}")
        
        # Method 3: Try latin-1 (fallback)
        if content is None:
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
                    encoding = 'latin-1'
            except Exception as e:
                print(f"      ⚠️ Error reading with latin-1: {e}")
        
        return {
            'size': file_stat.st_size,
            'permissions': permissions,
            'encoding': encoding,
            'content_length': len(content) if content else 0,
            'content_preview': content[:100] if content else "No content",
            'readable': content is not None
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'readable': False
        }

def advanced_flask_debug():
    """Advanced debugging untuk Flask templates"""
    
    print("🔍 ADVANCED FLASK TEMPLATE DEBUGGING")
    print("=" * 60)
    
    current_dir = Path.cwd()
    print(f"📁 Current Directory: {current_dir}")
    
    # Check templates directory
    templates_dir = current_dir / 'templates'
    print(f"📁 Templates Directory: {templates_dir}")
    print(f"📁 Templates Directory exists: {templates_dir.exists()}")
    
    if not templates_dir.exists():
        print("❌ Templates directory tidak ditemukan!")
        print("💡 Membuat directory templates...")
        templates_dir.mkdir(exist_ok=True)
        return
    
    # Check directory permissions
    try:
        dir_stat = templates_dir.stat()
        dir_permissions = oct(dir_stat.st_mode)[-3:]
        print(f"📁 Templates Directory permissions: {dir_permissions}")
    except Exception as e:
        print(f"⚠️ Error checking directory permissions: {e}")
    
    # Required templates
    required_templates = [
        'base.html',
        'index.html', 
        'login.html',
        'register.html',
        'dashboard.html'
    ]
    
    print(f"\n📋 DETAILED TEMPLATE ANALYSIS:")
    print("-" * 60)
    
    all_good = True
    
    for template_name in required_templates:
        template_path = templates_dir / template_name
        print(f"\n🔍 Analyzing: {template_name}")
        
        if not template_path.exists():
            print(f"   ❌ File tidak ditemukan!")
            all_good = False
            continue
        
        file_details = check_file_details(template_path)
        
        if 'error' in file_details:
            print(f"   ❌ Error: {file_details['error']}")
            all_good = False
            continue
        
        print(f"   📊 File size: {file_details['size']} bytes")
        print(f"   🔐 Permissions: {file_details['permissions']}")
        print(f"   🈯 Encoding: {file_details['encoding']}")
        print(f"   📝 Content length: {file_details['content_length']} characters")
        print(f"   ✅ Readable: {file_details['readable']}")
        
        if file_details['readable']:
            print(f"   👀 Preview: {file_details['content_preview'][:50]}...")
            
            # Check for common issues
            if file_details['content_length'] == 0:
                print(f"   ⚠️ WARNING: File is empty!")
                all_good = False
            elif file_details['size'] > 0 and file_details['content_length'] == 0:
                print(f"   ⚠️ WARNING: File has size but no readable content!")
                all_good = False
        else:
            print(f"   ❌ File tidak dapat dibaca!")
            all_good = False
    
    # Check for extra files in templates
    print(f"\n📋 ALL FILES IN TEMPLATES DIRECTORY:")
    print("-" * 40)
    
    try:
        for item in templates_dir.iterdir():
            if item.is_file():
                size = item.stat().st_size
                print(f"   📄 {item.name} ({size} bytes)")
            else:
                print(f"   📁 {item.name}/")
    except Exception as e:
        print(f"⚠️ Error listing directory: {e}")
    
    # Recommendations
    print(f"\n🔧 RECOMMENDATIONS:")
    print("-" * 30)
    
    if not all_good:
        print("1. ✍️ Recreate empty/corrupted template files")
        print("2. 🔐 Check file permissions (should be 644)")
        print("3. 💾 Save files with UTF-8 encoding")
        print("4. 🚫 Close any editors that might have files open")
        print("5. 🔄 Restart your development server")
    else:
        print("✅ All templates look good!")
    
    # Flask app check
    print(f"\n🏃 FLASK APP CHECK:")
    print("-" * 20)
    
    app_py = current_dir / 'app.py'
    if app_py.exists():
        print("✅ app.py found")
        # Could add more Flask-specific checks here
    else:
        print("❌ app.py not found")
    
    return all_good

def create_sample_templates():
    """Create sample templates if needed"""
    templates_dir = Path.cwd() / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # Sample base template
    base_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Flask App{% endblock %}</title>
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
</body>
</html>"""
    
    # Sample index template
    index_html = """{% extends "base.html" %}

{% block title %}Home{% endblock %}

{% block content %}
<h1>Welcome to Flask App</h1>
<p>This is the home page.</p>
{% endblock %}"""
    
    # Create files
    templates = {
        'base.html': base_html,
        'index.html': index_html,
        'login.html': '{% extends "base.html" %}\n{% block content %}<h1>Login</h1>{% endblock %}',
        'register.html': '{% extends "base.html" %}\n{% block content %}<h1>Register</h1>{% endblock %}',
        'dashboard.html': '{% extends "base.html" %}\n{% block content %}<h1>Dashboard</h1>{% endblock %}'
    }
    
    for filename, content in templates.items():
        file_path = templates_dir / filename
        if not file_path.exists() or file_path.stat().st_size == 0:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"✅ Created: {filename}")
            except Exception as e:
                print(f"❌ Error creating {filename}: {e}")

if __name__ == "__main__":
    print("🚀 Starting advanced Flask template debugging...\n")
    
    # Run debugging
    success = advanced_flask_debug()
    
    if not success:
        print(f"\n❓ Would you like to create sample templates? (y/n)")
        # In real usage, you could add input() here
        # For now, we'll just show the option
        print("💡 Run create_sample_templates() function to create sample files")
    
    print(f"\n{'='*60}")
    if success:
        print("🎉 All template checks passed!")
    else:
        print("⚠️ Some issues detected - please review recommendations above")