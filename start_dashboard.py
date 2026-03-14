#!/usr/bin/env python3
"""
Pentagon Dashboard Launcher
Command-line interface to start the Pentagon Security Dashboard server.

Usage:
    python start_dashboard.py [options]
    
Options:
    --host HOST     Host to bind (default: 127.0.0.1 for local, use 0.0.0.0 for remote)
    --port PORT     Port number (default: 5000)
    --debug         Enable debug mode (development only)
    --remote        Allow remote connections (binds to 0.0.0.0)
    
Examples:
    # Local development:
    python start_dashboard.py
    
    # Remote access:
    python start_dashboard.py --remote --port 8080
"""

import os
import sys

# Add the project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from pentagon.dashboard.app import run_dashboard


def main():
    """Main entry point for dashboard launcher."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Pentagon Security Dashboard Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python start_dashboard.py                    # Local access only
  python start_dashboard.py --remote           # Allow remote connections
  python start_dashboard.py --port 8080        # Custom port
  python start_dashboard.py --remote --debug   # Development mode
        '''
    )
    
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Host address to bind (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port number (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode (development only, not for production)'
    )
    
    parser.add_argument(
        '--remote',
        action='store_true',
        help='Allow remote connections (binds to 0.0.0.0)'
    )
    
    args = parser.parse_args()
    
    # Determine host based on remote flag
    host = '0.0.0.0' if args.remote else args.host
    
    # Security warning for remote mode
    if args.remote:
        print("\n" + "=" * 60)
        print("⚠️  WARNING: Remote access enabled!")
        print("   Make sure you have proper firewall rules in place.")
        print("   For production, use HTTPS with proper certificates.")
        print("=" * 60 + "\n")
    
    # Launch dashboard
    run_dashboard(host=host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
