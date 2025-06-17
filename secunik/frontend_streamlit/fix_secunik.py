#!/usr/bin/env python3
"""
SecuNik Auto-Fix Script
Automatically fixes common issues and replaces problematic files
"""

import os
import shutil
import sys
from pathlib import Path

class SecuNikFixer:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.frontend_dir = self.project_root / "frontend_streamlit"
        self.components_dir = self.frontend_dir / "components"
        self.utils_dir = self.frontend_dir / "utils"
        
        self.fixes_applied = []
        self.issues_found = []
    
    def print_banner(self):
        """Print fix banner"""
        print("=" * 60)
        print("🔧 SecuNik Auto-Fix Script")
        print("=" * 60)
        print("🛠️ Scanning for common issues and applying fixes...")
        print(f"📁 Project root: {self.project_root}")
        print("-" * 60)
    
    def check_file_structure(self):
        """Check and fix file structure issues"""
        print("📁 Checking file structure...")
        
        # Check required directories
        required_dirs = [
            self.frontend_dir,
            self.components_dir,
            self.utils_dir,
            self.project_root / "data"
        ]
        
        for directory in required_dirs:
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                self.fixes_applied.append(f"Created missing directory: {directory.name}")
                print(f"✅ Created: {directory.relative_to(self.project_root)}")
    
    def check_dashboard_component(self):
        """Check and fix dashboard component issues"""
        print("🏠 Checking dashboard component...")
        
        dashboard_file = self.components_dir / "dashboard.py"
        
        if not dashboard_file.exists():
            self.issues_found.append("dashboard.py component missing")
            print("❌ dashboard.py component is missing")
            return
        
        # Read the dashboard file to check for issues
        try:
            with open(dashboard_file, 'r') as f:
                content = f.read()
            
            # Check if it contains the wrong content (main app duplicate)
            if "SecuNik - Ultimate Local Cybersecurity Analysis Platform" in content and "Main Streamlit Application" in content:
                self.issues_found.append("dashboard.py contains wrong content (duplicate of main app)")
                print("❌ dashboard.py contains wrong content (duplicate of main app)")
                
                # Back up the problematic file
                backup_file = dashboard_file.with_suffix('.py.backup')
                shutil.copy2(dashboard_file, backup_file)
                print(f"📋 Backed up problematic file to: {backup_file.name}")
                
                return
            
            # Check if it has the correct dashboard functions
            if "show_dashboard" not in content:
                self.issues_found.append("dashboard.py missing show_dashboard function")
                print("❌ dashboard.py missing show_dashboard function")
                return
            
            print("✅ dashboard.py looks correct")
            
        except Exception as e:
            self.issues_found.append(f"Error reading dashboard.py: {e}")
            print(f"❌ Error reading dashboard.py: {e}")
    
    def check_main_app(self):
        """Check main app.py file"""
        print("📱 Checking main app.py...")
        
        app_file = self.frontend_dir / "app.py"
        
        if not app_file.exists():
            self.issues_found.append("app.py missing")
            print("❌ app.py is missing")
            return
        
        try:
            with open(app_file, 'r') as f:
                content = f.read()
            
            # Check for proper imports
            if "COMPONENTS_AVAILABLE" not in content:
                self.issues_found.append("app.py missing proper component handling")
                print("❌ app.py missing proper component handling")
                return
            
            print("✅ app.py structure looks good")
            
        except Exception as e:
            self.issues_found.append(f"Error reading app.py: {e}")
            print(f"❌ Error reading app.py: {e}")
    
    def check_utils(self):
        """Check utils files"""
        print("🛠️ Checking utils files...")
        
        required_utils = [
            "api_client.py",
            "state_manager.py",
            "__init__.py"
        ]
        
        for util_file in required_utils:
            util_path = self.utils_dir / util_file
            
            if not util_path.exists():
                self.issues_found.append(f"Missing utils/{util_file}")
                print(f"❌ Missing: utils/{util_file}")
            else:
                print(f"✅ Found: utils/{util_file}")
    
    def check_requirements(self):
        """Check requirements files"""
        print("📦 Checking requirements files...")
        
        frontend_req = self.frontend_dir / "requirements.txt"
        backend_req = self.project_root / "backend" / "requirements.txt"
        
        if not frontend_req.exists():
            self.issues_found.append("Frontend requirements.txt missing")
            print("❌ Frontend requirements.txt missing")
        else:
            print("✅ Frontend requirements.txt found")
        
        if not backend_req.exists():
            self.issues_found.append("Backend requirements.txt missing")
            print("❌ Backend requirements.txt missing")
        else:
            print("✅ Backend requirements.txt found")
    
    def check_component_imports(self):
        """Check component import issues"""
        print("🧩 Checking component imports...")
        
        components = [
            "dashboard.py",
            "file_upload.py",
            "analysis.py", 
            "cases.py",
            "ai_chat.py",
            "settings.py"
        ]
        
        missing_components = []
        
        for component in components:
            component_path = self.components_dir / component
            if not component_path.exists():
                missing_components.append(component)
                print(f"⚠️ Missing component: {component}")
            else:
                print(f"✅ Found component: {component}")
        
        if missing_components:
            self.issues_found.append(f"Missing components: {', '.join(missing_components)}")
    
    def create_minimal_fixes(self):
        """Create minimal fixes for critical issues"""
        print("\n🔨 Applying minimal fixes...")
        
        # Create __init__.py files if missing
        init_files = [
            self.components_dir / "__init__.py",
            self.utils_dir / "__init__.py"
        ]
        
        for init_file in init_files:
            if not init_file.exists():
                with open(init_file, 'w') as f:
                    f.write(f'"""{init_file.parent.name} package for SecuNik frontend"""\n')
                self.fixes_applied.append(f"Created {init_file.relative_to(self.project_root)}")
                print(f"✅ Created: {init_file.relative_to(self.project_root)}")
        
        # Create basic requirements.txt if missing
        frontend_req = self.frontend_dir / "requirements.txt"
        if not frontend_req.exists():
            basic_requirements = """# Basic SecuNik Frontend Requirements
streamlit>=1.28.0
plotly>=5.17.0
pandas>=2.1.0
numpy>=1.25.0
requests>=2.31.0
"""
            with open(frontend_req, 'w') as f:
                f.write(basic_requirements)
            self.fixes_applied.append("Created basic requirements.txt")
            print("✅ Created basic requirements.txt")
    
    def suggest_manual_fixes(self):
        """Suggest manual fixes for complex issues"""
        print("\n📋 Manual fixes needed:")
        
        if not self.issues_found:
            print("✅ No major issues found!")
            return
        
        print("\n❗ Issues that need manual attention:")
        for i, issue in enumerate(self.issues_found, 1):
            print(f"{i}. {issue}")
        
        print("\n🔧 Suggested actions:")
        
        if any("dashboard.py" in issue for issue in self.issues_found):
            print("• Replace dashboard.py with the correct dashboard component")
            print("  (The current one appears to be a duplicate of the main app)")
        
        if any("app.py" in issue for issue in self.issues_found):
            print("• Replace app.py with the fixed main application file")
            print("  (Should include proper component handling)")
        
        if any("Missing component" in issue for issue in self.issues_found):
            print("• Ensure all component files exist in the components/ directory")
            print("• Check that component files have the required functions")
        
        if any("utils" in issue for issue in self.issues_found):
            print("• Verify utils/api_client.py and utils/state_manager.py exist")
            print("• These files are critical for backend communication")
        
        if any("requirements" in issue for issue in self.issues_found):
            print("• Install missing dependencies:")
            print("  pip install streamlit plotly pandas numpy requests")
    
    def create_diagnostic_info(self):
        """Create diagnostic information file"""
        print("\n📊 Creating diagnostic info...")
        
        diag_file = self.project_root / "secunik_diagnostic.txt"
        
        with open(diag_file, 'w') as f:
            f.write("SecuNik Diagnostic Information\n")
            f.write("=" * 40 + "\n\n")
            
            f.write(f"Project Root: {self.project_root}\n")
            f.write(f"Python Version: {sys.version}\n")
            f.write(f"Platform: {sys.platform}\n\n")
            
            f.write("Issues Found:\n")
            f.write("-" * 20 + "\n")
            for issue in self.issues_found:
                f.write(f"• {issue}\n")
            
            f.write("\nFixes Applied:\n")
            f.write("-" * 20 + "\n")
            for fix in self.fixes_applied:
                f.write(f"• {fix}\n")
            
            f.write("\nFile Structure:\n")
            f.write("-" * 20 + "\n")
            
            # List important files and their existence
            important_files = [
                "frontend_streamlit/app.py",
                "frontend_streamlit/requirements.txt",
                "frontend_streamlit/components/dashboard.py",
                "frontend_streamlit/utils/api_client.py",
                "backend/main.py",
                "backend/requirements.txt"
            ]
            
            for file_path in important_files:
                full_path = self.project_root / file_path
                exists = "✅" if full_path.exists() else "❌"
                f.write(f"{exists} {file_path}\n")
        
        print(f"✅ Diagnostic info saved to: {diag_file.name}")
    
    def run(self):
        """Main fix process"""
        try:
            self.print_banner()
            
            # Run checks
            self.check_file_structure()
            self.check_dashboard_component()
            self.check_main_app()
            self.check_utils()
            self.check_requirements()
            self.check_component_imports()
            
            # Apply basic fixes
            self.create_minimal_fixes()
            
            # Create diagnostic info
            self.create_diagnostic_info()
            
            # Summary
            print("\n" + "=" * 60)
            print("🎯 Fix Summary")
            print("=" * 60)
            
            if self.fixes_applied:
                print("✅ Automatic fixes applied:")
                for fix in self.fixes_applied:
                    print(f"   • {fix}")
            
            if self.issues_found:
                print(f"\n⚠️ {len(self.issues_found)} issues need manual attention")
                self.suggest_manual_fixes()
            else:
                print("🎉 No major issues found!")
            
            print("\n💡 Next steps:")
            print("1. Review the diagnostic file: secunik_diagnostic.txt")
            print("2. Apply any suggested manual fixes")
            print("3. Run: python setup_secunik.py")
            print("4. Test with: python start_secunik.py")
            
            return 0 if not self.issues_found else 1
            
        except Exception as e:
            print(f"\n❌ Fix script failed: {e}")
            import traceback
            traceback.print_exc()
            return 1


def main():
    """Main entry point"""
    fixer = SecuNikFixer()
    return fixer.run()


if __name__ == "__main__":
    sys.exit(main())