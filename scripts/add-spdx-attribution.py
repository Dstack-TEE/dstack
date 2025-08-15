#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""
SPDX Header Attribution Script

This script automatically analyzes git blame data to determine contributors
and adds appropriate SPDX-FileCopyrightText headers using the REUSE tool.

Features:
- Excludes third-party code based on .spdx-exclude patterns
- Maps company email domains to company names
- Uses .mailmap for canonical contributor information
- Integrates with REUSE tool for consistent header formatting
- Supports dry-run mode for safe testing
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional


class SPDXAttributor:
    def __init__(self, repo_root: str, dry_run: bool = False):
        self.repo_root = Path(repo_root).resolve()
        self.dry_run = dry_run
        self.exclude_patterns = self._load_exclude_patterns()
        self.mailmap = self._parse_mailmap()
        self.company_domains = self._build_company_domain_map()
        
    def _load_exclude_patterns(self) -> List[str]:
        """Load exclusion patterns from .spdx-exclude file."""
        exclude_file = self.repo_root / '.spdx-exclude'
        patterns = []
        
        if exclude_file.exists():
            with open(exclude_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        
        return patterns
    
    def _parse_mailmap(self) -> Dict[str, Tuple[str, str]]:
        """Parse .mailmap file to get canonical name/email mappings."""
        mailmap_file = self.repo_root / '.mailmap'
        mailmap = {}
        
        if not mailmap_file.exists():
            print("Warning: .mailmap file not found")
            return mailmap
        
        with open(mailmap_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse mailmap format: "Proper Name <proper@email.com> <commit@email.com>"
                # or "Proper Name <proper@email.com> Commit Name <commit@email.com>"
                if '>' in line:
                    parts = line.split('>')
                    if len(parts) >= 2:
                        proper_part = parts[0].strip()
                        commit_part = parts[1].strip()
                        
                        # Extract proper name and email
                        if '<' in proper_part:
                            proper_name = proper_part.split('<')[0].strip()
                            proper_email = proper_part.split('<')[1].strip()
                        else:
                            continue
                        
                        # Extract commit email (and possibly name)
                        if '<' in commit_part:
                            commit_email = commit_part.split('<')[1].split('>')[0].strip()
                        else:
                            commit_email = commit_part.strip()
                        
                        mailmap[commit_email] = (proper_name, proper_email)
        
        return mailmap
    
    def _build_company_domain_map(self) -> Dict[str, str]:
        """Build mapping from email domains to company names."""
        return {
            'phala.network': 'Phala Network',
            'near.ai': 'Near Foundation',
            'nethermind.io': 'Nethermind',
            'rizelabs.io': 'Rize Labs',
            'testinprod.io': 'Test in Prod',
        }
    
    def _is_excluded(self, file_path: Path) -> bool:
        """Check if a file should be excluded based on patterns."""
        rel_path = file_path.relative_to(self.repo_root)
        rel_path_str = str(rel_path)
        
        for pattern in self.exclude_patterns:
            # Handle directory patterns
            if pattern.endswith('/'):
                if rel_path_str.startswith(pattern) or f"/{pattern}" in f"/{rel_path_str}/":
                    return True
            # Handle glob patterns
            elif fnmatch.fnmatch(rel_path_str, pattern):
                return True
            # Handle wildcard patterns
            elif '*' in pattern and fnmatch.fnmatch(rel_path_str, pattern):
                return True
        
        return False
    
    def _get_canonical_contributor(self, email: str, name: str) -> Tuple[str, str]:
        """Get canonical name and email for a contributor using mailmap."""
        if email in self.mailmap:
            return self.mailmap[email]
        return name.strip(), email.strip()
    
    def _get_company_name(self, email: str) -> Optional[str]:
        """Get company name for an email domain, or None for individual contributors."""
        domain = email.split('@')[-1].lower()
        return self.company_domains.get(domain)
    
    def _get_company_contact_email(self, company: str) -> str:
        """Get the standardized contact email for a company."""
        # Company-specific contact emails
        company_contacts = {
            'Phala Network': 'dstack@phala.network',
            'Near Foundation': 'contact@near.ai',
            'Nethermind': 'contact@nethermind.io',
            'Rize Labs': 'contact@rizelabs.io',
            'Test in Prod': 'contact@testinprod.io',
        }
        
        return company_contacts.get(company, f'contact@{company.lower().replace(" ", "")}.com')
    
    def _analyze_git_blame(self, file_path: Path) -> Dict[str, Set[int]]:
        """Analyze git blame to get contributors and their contribution years."""
        try:
            # Run git blame to get author info and dates
            result = subprocess.run([
                'git', 'blame', '--porcelain', str(file_path)
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            if result.returncode != 0:
                print(f"Warning: Could not run git blame on {file_path}")
                return {}
            
            contributors = defaultdict(set)
            current_commit = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Parse commit hash line
                if re.match(r'^[0-9a-f]{40}', line):
                    current_commit = line.split()[0]
                # Parse author email
                elif line.startswith('author-mail '):
                    email = line[12:].strip('<>')
                    
                    # Skip SPDX-only commits to avoid counting license header changes as contributions
                    if self._is_spdx_only_commit(current_commit):
                        continue
                    
                    # Get the year for this commit
                    year = self._get_commit_year(current_commit)
                    if year and email:
                        contributors[email].add(year)
            
            return contributors
        
        except subprocess.SubprocessError as e:
            print(f"Error running git blame on {file_path}: {e}")
            return {}
    
    def _is_spdx_only_commit(self, commit_hash: str) -> bool:
        """Check if a commit only contains SPDX header changes."""
        try:
            # Get commit message
            result = subprocess.run([
                'git', 'show', '-s', '--format=%s%n%b', commit_hash
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            if result.returncode != 0:
                return False
            
            commit_message = result.stdout.lower()
            
            # Check for SPDX-related keywords in commit message
            spdx_keywords = [
                'spdx', 'license header', 'copyright header', 'add license',
                'update license', 'license annotation', 'reuse annotate',
                'add spdx', 'update spdx', 'copyright attribution'
            ]
            
            if any(keyword in commit_message for keyword in spdx_keywords):
                # Get the diff to see if it's only header changes
                diff_result = subprocess.run([
                    'git', 'show', '--format=', commit_hash
                ], capture_output=True, text=True, cwd=self.repo_root)
                
                if diff_result.returncode == 0:
                    diff_content = diff_result.stdout
                    
                    # Check if the diff only contains SPDX/copyright/license changes
                    # Look for lines that are only adding/removing headers
                    diff_lines = diff_content.split('\n')
                    substantial_changes = 0
                    
                    for line in diff_lines:
                        if line.startswith(('+', '-')) and not line.startswith(('+++', '---')):
                            # Skip lines that are just SPDX/copyright/license related
                            line_content = line[1:].strip()
                            if line_content and not any(marker in line_content.lower() for marker in [
                                'spdx-', 'copyright', 'license-identifier', 
                                'filepyrighttext', '©', '(c)', 'all rights reserved'
                            ]):
                                substantial_changes += 1
                    
                    # If we have very few substantial changes, likely an SPDX-only commit
                    return substantial_changes <= 2
            
            return False
        
        except subprocess.SubprocessError:
            return False
    
    def _get_commit_year(self, commit_hash: str) -> Optional[int]:
        """Get the year of a commit."""
        try:
            result = subprocess.run([
                'git', 'show', '-s', '--format=%ad', '--date=format:%Y', commit_hash
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            if result.returncode == 0:
                return int(result.stdout.strip())
        except (subprocess.SubprocessError, ValueError):
            pass
        
        return None
    
    def _generate_spdx_headers(self, contributors: Dict[str, Set[int]]) -> List[str]:
        """Generate SPDX-FileCopyrightText headers for contributors."""
        headers = []
        company_years = defaultdict(set)  # Track years by company
        individual_contributors = {}  # Track individual contributors
        
        # First pass: group contributors by company vs individual
        for email, years in contributors.items():
            # Get canonical name and email
            name, canonical_email = self._get_canonical_contributor(email, "Unknown")
            
            # Check if this is a company contributor
            company = self._get_company_name(canonical_email)
            
            if company:
                # Accumulate years for this company
                company_years[company].update(years)
            else:
                # Individual contributor
                individual_contributors[canonical_email] = (name, years)
        
        # Generate company headers (one per company)
        for company, years in company_years.items():
            year_list = sorted(years)
            if len(year_list) == 1:
                year_str = str(year_list[0])
            else:
                year_str = f"{year_list[0]}-{year_list[-1]}"
            
            contact_email = self._get_company_contact_email(company)
            header = f"SPDX-FileCopyrightText: © {year_str} {company} <{contact_email}>"
            headers.append(header)
        
        # Generate individual headers
        for canonical_email, (name, years) in individual_contributors.items():
            year_list = sorted(years)
            if len(year_list) == 1:
                year_str = str(year_list[0])
            else:
                year_str = f"{year_list[0]}-{year_list[-1]}"
            
            header = f"SPDX-FileCopyrightText: © {year_str} {name} <{canonical_email}>"
            headers.append(header)
        
        return sorted(headers)
    
    def _remove_existing_spdx_headers(self, file_path: Path) -> bool:
        """Remove existing SPDX headers from a file."""
        if not file_path.exists():
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Find and remove existing SPDX lines
            new_lines = []
            for line in lines:
                if not (line.strip().startswith('// SPDX-') or 
                       line.strip().startswith('# SPDX-') or
                       line.strip().startswith('/* SPDX-') or
                       line.strip().startswith(' * SPDX-')):
                    new_lines.append(line)
            
            # Write back if changes were made
            if len(new_lines) != len(lines):
                if not self.dry_run:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
                return True
        
        except (IOError, UnicodeDecodeError) as e:
            print(f"Warning: Could not process {file_path}: {e}")
        
        return False
    
    def _get_existing_license(self, file_path: Path) -> str:
        """Get the existing SPDX license identifier from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for existing SPDX-License-Identifier
            lines = content.split('\n')[:20]  # Check first 20 lines
            for line in lines:
                if 'SPDX-License-Identifier:' in line:
                    # Extract the license identifier
                    parts = line.split('SPDX-License-Identifier:')
                    if len(parts) > 1:
                        return parts[1].strip().rstrip('*/')
            
            # Default to Apache-2.0 if no existing license found
            return 'Apache-2.0'
        
        except Exception:
            return 'Apache-2.0'
    
    def _apply_reuse_annotation(self, file_path: Path, headers: List[str]) -> bool:
        """Apply SPDX headers using the REUSE tool."""
        if not headers:
            return False
        
        try:
            # Prepare REUSE command - pass full SPDX-FileCopyrightText headers directly
            cmd = ['reuse', 'annotate']
            
            # Add all copyright lines with full SPDX-FileCopyrightText format
            for header in headers:
                cmd.extend(['--copyright', header])  # Keep the full SPDX-FileCopyrightText: format
            
            # Preserve existing license or use Apache-2.0 as default
            existing_license = self._get_existing_license(file_path)
            cmd.extend(['--license', existing_license])
            
            # Handle Solidity files which need explicit style specification
            if file_path.suffix == '.sol':
                cmd.extend(['--style', 'c'])
            
            # Add the file
            cmd.append(str(file_path))
            
            if self.dry_run:
                print(f"Would run: {' '.join(cmd)}")
                return True
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.repo_root)
                if result.returncode != 0:
                    print(f"REUSE command failed for {file_path}: {result.stderr}")
                    return False
                return True
        
        except subprocess.SubprocessError as e:
            print(f"Error running REUSE on {file_path}: {e}")
            return False
    
    def process_file(self, file_path: Path) -> bool:
        """Process a single file to add SPDX attribution."""
        # Convert to absolute path if it's relative
        if not file_path.is_absolute():
            file_path = self.repo_root / file_path
        
        if self._is_excluded(file_path):
            if self.dry_run:
                print(f"Excluded: {file_path}")
            return False
        
        # Analyze git blame
        contributors = self._analyze_git_blame(file_path)
        if not contributors:
            print(f"No contributors found for {file_path}")
            return False
        
        # Generate SPDX headers
        headers = self._generate_spdx_headers(contributors)
        
        if self.dry_run:
            print(f"\nFile: {file_path}")
            print(f"Contributors: {len(contributors)}")
            for header in headers:
                print(f"  {header}")
            return True
        
        # Remove existing SPDX headers
        self._remove_existing_spdx_headers(file_path)
        
        # Apply new headers with REUSE
        success = self._apply_reuse_annotation(file_path, headers)
        
        if success:
            print(f"✓ Updated: {file_path}")
        else:
            print(f"✗ Failed: {file_path}")
        
        return success
    
    def find_source_files(self) -> List[Path]:
        """Find all source files that should be processed."""
        extensions = {'.rs', '.py', '.go', '.ts', '.js', '.c', '.h', '.cpp', '.hpp', '.sol'}
        source_files = []
        
        for ext in extensions:
            for file_path in self.repo_root.rglob(f'*{ext}'):
                if file_path.is_file() and not self._is_excluded(file_path):
                    source_files.append(file_path)
        
        return sorted(source_files)


def main():
    parser = argparse.ArgumentParser(description='Add SPDX attribution headers to source files')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--file', type=str, help='Process a specific file instead of all source files')
    parser.add_argument('--repo-root', type=str, default='.', help='Repository root directory')
    
    args = parser.parse_args()
    
    # Initialize the attributor
    attributor = SPDXAttributor(args.repo_root, dry_run=args.dry_run)
    
    if args.file:
        # Process single file
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: File {file_path} does not exist")
            sys.exit(1)
        
        attributor.process_file(file_path)
    else:
        # Process all source files
        source_files = attributor.find_source_files()
        
        if args.dry_run:
            print(f"Found {len(source_files)} source files to process")
            print("\nDry run - showing what would be done:\n")
        
        success_count = 0
        for file_path in source_files:
            if attributor.process_file(file_path):
                success_count += 1
        
        if not args.dry_run:
            print(f"\nProcessed {success_count}/{len(source_files)} files successfully")


if __name__ == '__main__':
    main()