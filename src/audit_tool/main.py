#!/usr/bin/env python3

import argparse
import logging
import sys
import time
from typing import Optional, List, Dict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
from datetime import datetime, timedelta
import threading
from queue import Queue

from .config.config_manager import ConfigManager
from .core.module_loader import ModuleLoader
from .core.report_generator import JSONReportGenerator, HTMLReportGenerator

class RateLimiter:
    """Token bucket rate limiter implementation."""
    def __init__(self, rate: float, burst: int = 1):
        """
        Initialize rate limiter.
        
        Args:
            rate: Number of tokens per second
            burst: Maximum number of tokens that can be accumulated
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = threading.Lock()
        
    def acquire(self) -> float:
        """
        Acquire a token. Returns the time to wait (in seconds) before proceeding.
        """
        with self.lock:
            now = time.time()
            # Add new tokens based on time elapsed
            time_passed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + time_passed * self.rate)
            self.last_update = now
            
            if self.tokens >= 1:
                # Token available
                self.tokens -= 1
                return 0
            else:
                # Calculate wait time for next token
                wait_time = (1 - self.tokens) / self.rate
                return wait_time

class ProgressTracker:
    """Tracks progress and estimates completion time."""
    def __init__(self, total: int, logger: logging.Logger):
        self.total = total
        self.completed = 0
        self.start_time = time.time()
        self.logger = logger
        self.lock = threading.Lock()
        
    def update(self, increment: int = 1) -> None:
        """Update progress and log status with ETA."""
        with self.lock:
            self.completed += increment
            elapsed_time = time.time() - self.start_time
            
            if self.completed > 0:
                # Calculate progress and ETA
                progress = (self.completed / self.total) * 100
                avg_time_per_item = elapsed_time / self.completed
                remaining_items = self.total - self.completed
                eta_seconds = avg_time_per_item * remaining_items
                eta = str(timedelta(seconds=int(eta_seconds)))
                
                # Format the progress message
                msg = (f"Progress: {progress:.1f}% ({self.completed}/{self.total} targets completed) | "
                      f"Elapsed: {str(timedelta(seconds=int(elapsed_time)))} | "
                      f"ETA: {eta}")
                self.logger.info(msg)

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

def read_targets_from_file(file_path: str) -> List[str]:
    """Read targets from a file, one per line."""
    try:
        with open(file_path, 'r') as f:
            # Remove empty lines and whitespace
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        raise ValueError(f"Error reading targets file: {e}")

def run_audit_for_target(target: str, module_loader: ModuleLoader, config_manager: ConfigManager, 
                        output_format: str, output_dir: str, logger: logging.Logger,
                        rate_limiter: Optional[RateLimiter] = None) -> Dict:
    """Run audit for a single target and generate report."""
    try:
        # Apply rate limiting if configured
        if rate_limiter:
            wait_time = rate_limiter.acquire()
            if wait_time > 0:
                logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds before auditing {target}")
                time.sleep(wait_time)
        
        logger.info(f"Starting audit for target: {target}")
        findings = module_loader.run_all_modules(target)
        
        # Generate report
        if output_format == 'json':
            report_generator = JSONReportGenerator(findings)
        else:
            report_generator = HTMLReportGenerator(findings)
            
        report = report_generator.generate()
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Save report with target-specific filename
        output_file = Path(output_dir) / f"{target}_security_report.{output_format}"
        save_report(report, str(output_file))
        logger.info(f"Report saved to: {output_file}")
        
        return {'target': target, 'findings': findings, 'status': 'success'}
    except Exception as e:
        logger.error(f"Error auditing target {target}: {e}")
        return {'target': target, 'findings': None, 'status': 'error', 'error': str(e)}

def run_parallel_audits(targets: List[str], module_loader: ModuleLoader, config_manager: ConfigManager,
                       output_format: str, output_dir: str, logger: logging.Logger, 
                       max_workers: Optional[int] = None, rate_limit: Optional[float] = None) -> Dict:
    """Run audits for multiple targets in parallel with rate limiting."""
    if max_workers is None:
        # Use CPU count + 1 for I/O-bound tasks, but cap at 16 to prevent excessive resource usage
        max_workers = min(multiprocessing.cpu_count() + 1, 16)
    
    # Initialize rate limiter if rate limit is specified
    rate_limiter = RateLimiter(rate_limit) if rate_limit else None
    
    # Initialize progress tracker
    progress = ProgressTracker(len(targets), logger)
    all_findings = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all audit tasks
        future_to_target = {
            executor.submit(
                run_audit_for_target, 
                target, 
                module_loader, 
                config_manager, 
                output_format, 
                output_dir, 
                logger,
                rate_limiter
            ): target for target in targets
        }
        
        # Process completed audits as they finish
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result['status'] == 'success':
                    all_findings[target] = result['findings']
                progress.update()
            except Exception as e:
                logger.error(f"Unexpected error processing target {target}: {e}")
                progress.update()
    
    return all_findings

def main():
    parser = argparse.ArgumentParser(description='Security Audit Tool')
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('target', nargs='?', help='Target to audit (domain, URL, etc.)')
    target_group.add_argument('--targets-file', '-t', help='File containing targets to audit (one per line)')
    parser.add_argument('--list-modules', '-l', action='store_true',
                       help='List available security audit modules')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--output-dir', '-d', default='reports',
                       help='Output directory for reports (default: reports)')
    parser.add_argument('--format', '-f', choices=['json', 'html'], 
                       help='Output format (default: json)')
    parser.add_argument('--modules', '-m', nargs='+', 
                       help='Specific modules to run (default: all enabled)')
    parser.add_argument('--workers', '-w', type=int,
                       help='Maximum number of parallel workers (default: CPU count + 1)')
    parser.add_argument('--rate-limit', '-r', type=float,
                       help='Maximum number of targets to audit per second (default: no limit)')
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
            
        # Get targets
        targets = []
        if args.targets_file:
            targets = read_targets_from_file(args.targets_file)
            if not targets:
                parser.error("Targets file is empty")
        elif args.target:
            targets = [args.target]
        else:
            parser.error("Either target or --targets-file is required unless --list-modules is specified")
            
        # Override enabled modules if specified
        if args.modules:
            config_manager.set('modules.enabled', args.modules)
            
        # Set output format
        output_format = args.format or config_manager.get('output.default_format', 'json')
        
        # Run audits
        if len(targets) == 1:
            # For single target, run directly
            result = run_audit_for_target(
                target=targets[0],
                module_loader=module_loader,
                config_manager=config_manager,
                output_format=output_format,
                output_dir=args.output_dir,
                logger=logger
            )
            all_findings = {targets[0]: result['findings']} if result['status'] == 'success' else {}
        else:
            # For multiple targets, run in parallel
            logger.info(f"Starting parallel audit of {len(targets)} targets")
            all_findings = run_parallel_audits(
                targets=targets,
                module_loader=module_loader,
                config_manager=config_manager,
                output_format=output_format,
                output_dir=args.output_dir,
                logger=logger,
                max_workers=args.workers,
                rate_limit=args.rate_limit
            )
        
        # Generate summary report if multiple targets
        if len(targets) > 1:
            if output_format == 'json':
                summary_generator = JSONReportGenerator(all_findings)
            else:
                summary_generator = HTMLReportGenerator(all_findings)
            
            summary_report = summary_generator.generate()
            summary_file = Path(args.output_dir) / f"summary_report.{output_format}"
            save_report(summary_report, str(summary_file))
            logger.info(f"Summary report saved to: {summary_file}")
        
    except Exception as e:
        logger.error(f"Error during audit: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 