# core/framework.py
"""
Main framework orchestrator
Handles module loading, user interaction, and session management
"""

import importlib
import pkgutil
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pathlib import Path
import json
from datetime import datetime

from core.session import Session
from core.output import OutputManager
from core.base_module import BaseModule

class CloudRedTeamFramework:
    def __init__(self):
        self.console = Console()
        self.session = Session()
        self.output_manager = OutputManager()
        self.modules = {}
        self.load_modules()
        
    def load_modules(self):
        """Dynamically load all modules from the modules directory"""
        modules_path = Path(__file__).parent.parent / "modules"
        
        for category in ['discovery', 'exploitation', 'post_exploit']:
            category_path = modules_path / category
            if not category_path.exists():
                continue
                
            for importer, modname, ispkg in pkgutil.iter_modules([str(category_path)]):
                try:
                    module = importlib.import_module(f"modules.{category}.{modname}")
                    
                    # Find all classes that inherit from BaseModule
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if (isinstance(item, type) and 
                            issubclass(item, BaseModule) and 
                            item != BaseModule):
                            instance = item()
                            module_id = f"{category}.{modname}"
                            self.modules[module_id] = instance
                            self.console.print(f"[green][+][/green] Loaded module: {instance.name}")
                except Exception as e:
                    self.console.print(f"[red][!][/red] Failed to load {modname}: {e}")
    
    def show_main_menu(self):
        """Display main menu and get user choice"""
        choices = [
            "1. List All Modules",
            "2. Select and Run Module",
            "3. View Session Info",
            "4. Export Results",
            "5. Exit"
        ]
        
        return questionary.select(
            "Main Menu - Select an option:",
            choices=choices
        ).ask()
    
    def list_modules(self):
        """Display all available modules in a table"""
        table = Table(title="Available Modules", show_header=True, header_style="bold magenta")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Module Name", style="green")
        table.add_column("Category", style="yellow")
        table.add_column("Platform", style="blue")
        table.add_column("Description")
        
        for idx, (module_id, module) in enumerate(self.modules.items(), 1):
            table.add_row(
                str(idx),
                module.name,
                module.category,
                module.platform,
                module.description
            )
        
        self.console.print(table)
    
    def select_module(self):
        """Interactive module selection"""
        if not self.modules:
            self.console.print("[red][!][/red] No modules loaded!")
            return None
        
        # Create choices with module info
        choices = []
        module_map = {}
        
        for idx, (module_id, module) in enumerate(self.modules.items(), 1):
            choice_text = f"{idx}. [{module.platform}] {module.name} - {module.description}"
            choices.append(choice_text)
            module_map[choice_text] = module_id
        
        choices.append("Back to Main Menu")
        
        selection = questionary.select(
            "Select a module to run:",
            choices=choices
        ).ask()
        
        if selection == "Back to Main Menu":
            return None
        
        return self.modules[module_map[selection]]
    
    def run_module(self, module):
        """Execute a selected module"""
        self.console.print(Panel(
            f"[bold green]{module.name}[/bold green]\n"
            f"Platform: {module.platform}\n"
            f"Category: {module.category}\n\n"
            f"{module.description}",
            title="Module Information"
        ))
        
        # Get required inputs from user
        requirements = module.get_requirements()
        inputs = {}
        
        for key, requirement in requirements.items():
            if requirement.get('type') == 'choice':
                inputs[key] = questionary.select(
                    requirement['prompt'],
                    choices=requirement['choices']
                ).ask()
            elif requirement.get('type') == 'confirm':
                inputs[key] = questionary.confirm(
                    requirement['prompt'],
                    default=requirement.get('default', False)
                ).ask()
            elif requirement.get('type') == 'password':
                inputs[key] = questionary.password(
                    requirement['prompt']
                ).ask()
            else:
                inputs[key] = questionary.text(
                    requirement['prompt'],
                    default=requirement.get('default', '')
                ).ask()
        
        # Validate inputs
        if not module.validate_input(inputs):
            self.console.print("[red][!][/red] Input validation failed!")
            return
        
        # Run scan/discovery phase
        self.console.print("\n[yellow][*][/yellow] Starting scan phase...")
        try:
            scan_results = module.scan(inputs)
        except Exception as e:
            self.console.print(f"[red][!][/red] Scan error: {e}")
            import traceback
            traceback.print_exc()
            return
        
        if not scan_results:
            self.console.print("[yellow][!][/yellow] No vulnerabilities found.")
            self.session.add_result(module.name, inputs, scan_results, None)
            return
        
        # Display results
        self.display_scan_results(scan_results)
        
        # Ask if user wants to exploit
        exploit_choice = questionary.confirm(
            "Vulnerabilities found. Do you want to attempt exploitation?",
            default=False
        ).ask()
        
        exploit_results = None
        if exploit_choice:
            self.console.print("\n[red][*][/red] Starting exploitation phase...")
            try:
                exploit_results = module.exploit(scan_results, inputs)
                self.display_exploit_results(exploit_results)
            except Exception as e:
                self.console.print(f"[red][!][/red] Exploitation error: {e}")
                import traceback
                traceback.print_exc()
        
        # Save to session
        self.session.add_result(module.name, inputs, scan_results, exploit_results)
        self.console.print("\n[green][+][/green] Results saved to session")
    
    def display_scan_results(self, results):
        """Display scan results in a formatted table"""
        if isinstance(results, list) and results:
            table = Table(title="Scan Results", show_header=True, header_style="bold yellow")
            
            # Add columns based on first result's keys
            for key in results[0].keys():
                table.add_column(key.replace('_', ' ').title())
            
            for result in results:
                table.add_row(*[str(v) for v in result.values()])
            
            self.console.print(table)
        else:
            self.console.print(f"\n{results}")
    
    def display_exploit_results(self, results):
        """Display exploitation results"""
        if results:
            self.console.print(Panel(
                json.dumps(results, indent=2),
                title="Exploitation Results",
                border_style="red"
            ))
    
    def show_session_info(self):
        """Display current session information"""
        info = self.session.get_info()
        
        panel_content = (
            f"Session ID: {info['session_id']}\n"
            f"Started: {info['start_time']}\n"
            f"Modules Run: {info['modules_run']}\n"
            f"Total Findings: {info['total_findings']}"
        )
        
        self.console.print(Panel(panel_content, title="Session Information", border_style="cyan"))
    
    def export_results(self):
        """Export session results to file"""
        format_choice = questionary.select(
            "Select export format:",
            choices=['JSON', 'HTML', 'TXT']
        ).ask()
        
        filename = questionary.text(
            "Enter output filename (without extension):",
            default=f"cloud_redteam_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ).ask()
        
        success = self.output_manager.export(
            self.session.results,
            filename,
            format_choice.lower()
        )
        
        if success:
            self.console.print(f"[green][+][/green] Results exported to {filename}.{format_choice.lower()}")
        else:
            self.console.print(f"[red][!][/red] Export failed")
    
    def run(self):
        """Main framework loop"""
        while True:
            choice = self.show_main_menu()
            
            if not choice:
                continue
            
            if "List All Modules" in choice:
                self.list_modules()
            elif "Select and Run Module" in choice:
                module = self.select_module()
                if module:
                    self.run_module(module)
            elif "View Session Info" in choice:
                self.show_session_info()
            elif "Export Results" in choice:
                self.export_results()
            elif "Exit" in choice:
                self.console.print("\n[cyan][*][/cyan] Thank you for using Cloud Red Team Framework!")
                break
