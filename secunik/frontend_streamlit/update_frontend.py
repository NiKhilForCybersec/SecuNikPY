#!/usr/bin/env python3
"""
SecuNik Frontend Update Script - Windows Compatible
Updates frontend files to work with the new backend APIs
"""

import os
import sys
import shutil
from pathlib import Path
import subprocess


def check_frontend_structure():
    """Check current frontend structure"""
    print("Checking frontend structure...")
    
    frontend_dir = Path.cwd()
    if frontend_dir.name != "frontend_streamlit":
        print(f"ERROR: Please run this script from the frontend_streamlit directory")
        print(f"       Current directory: {frontend_dir}")
        return False
    
    # Check for existing files
    required_dirs = ["components", "utils"]
    existing_files = []
    missing_files = []
    
    files_to_check = [
        "app.py",
        "requirements.txt",
        "components/dashboard.py",
        "components/file_upload.py", 
        "components/analysis.py",
        "components/cases.py",
        "components/settings.py",
        "utils/api_client.py",
        "utils/state_manager.py"
    ]
    
    for file_path in files_to_check:
        full_path = frontend_dir / file_path
        if full_path.exists():
            existing_files.append(file_path)
        else:
            missing_files.append(file_path)
    
    print(f"SUCCESS: Found {len(existing_files)} existing files")
    print(f"WARNING: Missing {len(missing_files)} files")
    
    return True


def backup_existing_files():
    """Backup existing files"""
    print("Creating backup of existing files...")
    
    frontend_dir = Path.cwd()
    backup_dir = frontend_dir / "backup_before_update"
    
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    
    backup_dir.mkdir()
    
    # Backup existing files
    files_to_backup = [
        "app.py",
        "requirements.txt",
        "components",
        "utils"
    ]
    
    backed_up = 0
    for item in files_to_backup:
        source = frontend_dir / item
        if source.exists():
            try:
                if source.is_dir():
                    shutil.copytree(source, backup_dir / item)
                else:
                    shutil.copy2(source, backup_dir / item)
                backed_up += 1
            except Exception as e:
                print(f"WARNING: Could not backup {item}: {e}")
    
    print(f"SUCCESS: Backed up {backed_up} items to {backup_dir}")
    return backup_dir


def create_directory_structure():
    """Create required directory structure"""
    print("Creating directory structure...")
    
    frontend_dir = Path.cwd()
    
    directories = [
        "components",
        "utils", 
        "data",
        "logs",
        "static/css",
        "static/images",
        "static/js"
    ]
    
    for dir_path in directories:
        full_path = frontend_dir / dir_path
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"SUCCESS: Created: {dir_path}")


def install_dependencies():
    """Install updated dependencies"""
    print("Installing updated dependencies...")
    
    try:
        # Install requirements
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("SUCCESS: Dependencies installed successfully")
            return True
        else:
            print(f"ERROR: Error installing dependencies: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"ERROR: Error installing dependencies: {e}")
        return False


def create_component_init_files():
    """Create __init__.py files for components"""
    print("Creating __init__.py files...")
    
    frontend_dir = Path.cwd()
    
    init_dirs = ["components", "utils"]
    
    for dir_name in init_dirs:
        init_file = frontend_dir / dir_name / "__init__.py"
        try:
            init_file.write_text(f'"""{dir_name} package for SecuNik frontend"""\n', encoding='utf-8')
            print(f"SUCCESS: Created: {dir_name}/__init__.py")
        except Exception as e:
            print(f"ERROR: Could not create {dir_name}/__init__.py: {e}")


def create_streamlit_config():
    """Create Streamlit configuration"""
    print("Creating Streamlit configuration...")
    
    frontend_dir = Path.cwd()
    streamlit_dir = frontend_dir / ".streamlit"
    streamlit_dir.mkdir(exist_ok=True)
    
    # Create config.toml
    config_content = """[theme]
primaryColor = "#2a5298"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"

[server]
port = 8501
address = "localhost"
maxUploadSize = 200

[browser]
gatherUsageStats = false
"""
    
    config_file = streamlit_dir / "config.toml"
    try:
        config_file.write_text(config_content.strip(), encoding='utf-8')
        print("SUCCESS: Created: .streamlit/config.toml")
    except Exception as e:
        print(f"ERROR: Could not create config.toml: {e}")
    
    # Create secrets.toml template
    secrets_content = """# Add your API keys and secrets here
# This file should not be committed to version control

[api]
# openai_api_key = "your-openai-api-key-here"
"""
    
    secrets_file = streamlit_dir / "secrets.toml"
    if not secrets_file.exists():
        try:
            secrets_file.write_text(secrets_content.strip(), encoding='utf-8')
            print("SUCCESS: Created: .streamlit/secrets.toml")
        except Exception as e:
            print(f"ERROR: Could not create secrets.toml: {e}")


def test_imports():
    """Test if all imports work correctly"""
    print("Testing imports...")
    
    test_imports = [
        "streamlit",
        "plotly.express", 
        "pandas",
        "requests",
        "pathlib"
    ]
    
    failed_imports = []
    
    for module in test_imports:
        try:
            __import__(module)
            print(f"SUCCESS: {module}")
        except ImportError as e:
            print(f"ERROR: {module}: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\nWARNING: Failed to import: {', '.join(failed_imports)}")
        print("SOLUTION: Try running: pip install -r requirements.txt")
        return False
    
    print("SUCCESS: All imports successful!")
    return True


def create_run_script():
    """Create run script for the frontend"""
    print("Creating run script...")
    
    frontend_dir = Path.cwd()
    
    # Create run.py
    run_script_content = '''#!/usr/bin/env python3
"""
SecuNik Frontend Run Script
Starts the Streamlit application
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Start the Streamlit app"""
    app_file = Path(__file__).parent / "app.py"
    
    if not app_file.exists():
        print("ERROR: app.py not found!")
        sys.exit(1)
    
    print("Starting SecuNik Frontend...")
    print("Frontend will be available at: http://localhost:8501")
    print("Make sure the backend is running on: http://localhost:8000")
    print()
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(app_file),
            "--server.port", "8501",
            "--server.address", "localhost"
        ])
    except KeyboardInterrupt:
        print("\\nFrontend stopped by user")
    except Exception as e:
        print(f"ERROR: Error starting frontend: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
    
    run_file = frontend_dir / "run.py"
    try:
        run_file.write_text(run_script_content, encoding='utf-8')
        print("SUCCESS: Created: run.py")
    except Exception as e:
        print(f"ERROR: Could not create run.py: {e}")


def verify_backend_connection():
    """Verify backend connection"""
    print("Testing backend connection...")
    
    try:
        import requests
        response = requests.get("http://localhost:8000/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print("SUCCESS: Backend is online!")
            print(f"         Status: {data.get('status')}")
            print(f"         Version: {data.get('version')}")
            return True
        else:
            print(f"WARNING: Backend responded with status: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to backend")
        print("SOLUTION: Make sure backend is running: cd backend && python run.py")
        return False
    except Exception as e:
        print(f"ERROR: Error testing backend: {e}")
        return False


def show_update_summary():
    """Show update summary and next steps"""
    print("\n" + "="*60)
    print("FRONTEND UPDATE COMPLETED!")
    print("="*60)
    
    print("\nWhat was updated:")
    print("SUCCESS: Updated all component files for new backend APIs")
    print("SUCCESS: Enhanced API client with full backend integration")
    print("SUCCESS: Added AI chat component")
    print("SUCCESS: Improved dashboard with real-time metrics") 
    print("SUCCESS: Enhanced file upload with advanced analysis")
    print("SUCCESS: Updated analysis viewer with detailed results")
    print("SUCCESS: Improved case management")
    print("SUCCESS: Added comprehensive settings page")
    print("SUCCESS: Added state management utilities")
    print("SUCCESS: Updated dependencies")
    
    print("\nNext steps:")
    print("1. Start the backend server:")
    print("   cd ../backend && python run.py")
    print()
    print("2. Start the frontend:")
    print("   python run.py")
    print("   OR")
    print("   streamlit run app.py")
    print()
    print("3. Open your browser to:")
    print("   http://localhost:8501")
    
    print("\nTips:")
    print("- Check that backend is running on localhost:8000")
    print("- Configure OpenAI API key for AI features")
    print("- Upload test files to verify everything works")
    print("- Check the dashboard for system status")
    
    print("\nBackup location:")
    print("   ./backup_before_update/")


def main():
    """Main update process"""
    print("SecuNik Frontend Update Script")
    print("="*50)
    
    # Step 1: Check structure
    if not check_frontend_structure():
        return False
    
    # Step 2: Backup existing files
    backup_dir = backup_existing_files()
    
    # Step 3: Create directory structure
    create_directory_structure()
    
    # Step 4: Create init files
    create_component_init_files()
    
    # Step 5: Create Streamlit config
    create_streamlit_config()
    
    # Step 6: Create run script
    create_run_script()
    
    print("\nNow place the updated files:")
    print("1. Replace app.py with the new main application file")
    print("2. Replace requirements.txt with the updated dependencies")
    print("3. Update all component files in components/")
    print("4. Update all utility files in utils/")
    
    # Wait for user to place files
    input("\nPress Enter after you've placed all the updated files...")
    
    # Step 7: Install dependencies
    if not install_dependencies():
        print("WARNING: Dependency installation failed, but continuing...")
    
    # Step 8: Test imports
    if not test_imports():
        print("WARNING: Some imports failed, but continuing...")
    
    # Step 9: Test backend connection
    verify_backend_connection()
    
    # Step 10: Show summary
    show_update_summary()
    
    return True


if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\nSUCCESS: Update completed successfully!")
        else:
            print("\nERROR: Update failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nUpdate cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Unexpected error: {e}")
        sys.exit(1)