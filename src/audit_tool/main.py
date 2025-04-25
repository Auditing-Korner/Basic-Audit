#!/usr/bin/env python3

import argparse
import logging
import sys
from typing import Optional
from pathlib import Path

from .config.config_manager import ConfigManager
from .core.module_loader import ModuleLoader
from .core.report_generator import JSONReportGenerator, HTMLReportGenerator

def setup_logging(config_manager: ConfigManager) -> None:
    """Configure logging based on settings."""
    log_config = config_manager.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_format = log_config.get('format', '%(asctime)s - %(levelname)s - %(message)s')
    log_file = log_config.get('file', 'security_audit.log')
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def save_report(report: str, output_file: str) -> None:
    """Save report to file."""
    with open(output_file, 'w') as f:
        f.write(report)

def list_available_modules(module_loader: ModuleLoader) -> None:
    """Display available security audit modules with descriptions."""
    print("\nAvailable Security Audit Modules:")
    print("-" * 80)
    
    modules = module_loader.get_available_modules()
    categories = {}
    
    # Group modules by category
    for module_name, module_class in modules.items():
        category = module_name.split('.')[2] if len(module_name.split('.')) > 2 else 'Other'
        if category not in categories:
            categories[category] = []
        categories[category].append((module_name, module_class))
    
    # Print modules by category
    for category in sorted(categories.keys()):
        print(f"\n{category.replace('_', ' ').title()} Modules:")
        print("-" * 40)
        for module_name, module_class in sorted(categories[category]):
            description = module_class.__doc__.strip().split('\n')[0] if module_class.__doc__ else "No description available"
            print(f"  • {module_name.split('.')[-1]}:")
            print(f"    {description}")
    
    print("\nTo use specific modules, use the -m/--modules argument followed by module names.")
    print("Example: --modules dns_security oauth_security")

def main():
    parser = argparse.ArgumentParser(description='Security Audit Tool')
    parser.add_argument('--list-modules', '-l', action='store_true',
                       help='List available security audit modules')
    parser.add_argument('target', nargs='?', help='Target to audit (domain, URL, etc.)')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--output', '-o', help='Output file for the report')
    parser.add_argument('--format', '-f', choices=['json', 'html'], 
                       help='Output format (default: json)')
    parser.add_argument('--modules', '-m', nargs='+', 
                       help='Specific modules to run (default: all enabled)')
    args = parser.parse_args()
    
    # Initialize configuration
    config_manager = ConfigManager(args.config)
    
    # Setup logging
    setup_logging(config_manager)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize module loader
        module_loader = ModuleLoader(config_manager)
        module_loader.discover_modules('audit_tool.modules')
        
        # If --list-modules is specified, show available modules and exit
        if args.list_modules:
            list_available_modules(module_loader)
            sys.exit(0)
            
        # Ensure target is provided for audit
        if not args.target:
            parser.error("target is required unless --list-modules is specified")
            
        # Override enabled modules if specified
        if args.modules:
            config_manager.set('modules.enabled', args.modules)
            
        # Run audit
        logger.info(f"Starting audit for target: {args.target}")
        findings = module_loader.run_all_modules(args.target)
        
        # Generate report
        output_format = args.format or config_manager.get('output.default_format', 'json')
        if output_format == 'json':
            report_generator = JSONReportGenerator(findings)
        else:
            report_generator = HTMLReportGenerator(findings)
            
        report = report_generator.generate()
        
        # Save report
        output_file = args.output or f"security_report.{output_format}"
        save_report(report, output_file)
        logger.info(f"Report saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"Error during audit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 