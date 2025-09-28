#!/usr/bin/env python3

import http.server
import socketserver
import urllib.parse
import json
import re
import os
import tempfile
from datetime import datetime
import cgi
import io

class AristaBGPParser:
    def __init__(self):
        self.reset()

    def reset(self):
        self.bgp_config = {
            'asNumber': '',
            'routerId': '',
            'globalNeighbors': [],
            'vrfs': [],
            'peerGroups': [],
            'routeMaps': [],
            'prefixLists': {},
            'communityLists': [],
            'asPathSets': [],
            'extcommunitySets': [],
            'accessLists': []
        }

    def parse_config(self, content):
        """Parse Arista EOS BGP configuration from content"""
        self.reset()

        # Clean content and split into lines
        content = content.replace('\ufeff', '')  # Remove BOM
        lines = []
        for line in content.split('\n'):
            line = line.rstrip()
            if line and not line.isspace():
                lines.append(line)

        print(f"Total lines to parse: {len(lines)}")

        # Parse in order
        self._parse_prefix_lists(lines)
        self._parse_community_lists(lines)
        self._parse_access_lists(lines)
        self._parse_as_path_sets(lines)
        self._parse_route_maps(lines)
        self._parse_bgp_section(lines)

        return self.bgp_config

    def _parse_prefix_lists(self, lines):
        """Parse ip prefix-list definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('ip prefix-list '):
                parts = line.split()
                if len(parts) >= 3:
                    prefix_name = parts[2]
                    if prefix_name not in self.bgp_config['prefixLists']:
                        self.bgp_config['prefixLists'][prefix_name] = []
                    
                    # Look for subsequent seq lines
                    i += 1
                    while i < len(lines):
                        next_line = lines[i].strip()
                        if next_line.startswith('seq ') and ('permit' in next_line or 'deny' in next_line):
                            # Extract the prefix entry from this seq line
                            seq_parts = next_line.split()
                            if len(seq_parts) >= 4:
                                # Format: seq 10 permit 10.2.0.0/16 le 24
                                seq_entry = ' '.join(seq_parts[2:])  # permit 10.2.0.0/16 le 24
                                self.bgp_config['prefixLists'][prefix_name].append(seq_entry)
                        elif next_line.startswith('ip prefix-list ') or next_line.startswith('!') or not next_line:
                            # End of current prefix-list
                            i -= 1  # Step back one line
                            break
                        i += 1
            i += 1

    def _parse_community_lists(self, lines):
        """Parse ip community-list definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('ip community-list '):
                parts = line.split()
                if len(parts) >= 3:
                    community_name = parts[2]
                    communities = []
                    
                    # Extract community values from this line
                    if 'permit' in line:
                        permit_idx = line.find('permit')
                        community_values = line[permit_idx + 6:].strip().split()
                        communities.extend(community_values)
                    
                    # Check if this community list already exists
                    existing = next((cl for cl in self.bgp_config['communityLists'] if cl['name'] == community_name), None)
                    if existing:
                        existing['communities'].extend(communities)
                    else:
                        self.bgp_config['communityLists'].append({
                            'name': community_name,
                            'communities': communities
                        })
            i += 1

    def _parse_access_lists(self, lines):
        """Parse ip access-list definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('ip access-list '):
                parts = line.split()
                if len(parts) >= 3:
                    access_list_name = parts[2]
                    entries = []
                    i += 1
                    
                    # Look for subsequent access-list entries
                    while i < len(lines):
                        next_line = lines[i].strip()
                        if next_line.startswith('!') or not next_line:
                            # End of current access-list
                            break
                        elif next_line and not next_line.startswith('ip access-list'):
                            # This is an access-list entry
                            entries.append(next_line)
                        elif next_line.startswith('ip access-list') or next_line.startswith('ip routing'):
                            # Start of next access-list or other ip command
                            i -= 1  # Step back one line
                            break
                        i += 1
                    
                    self.bgp_config['accessLists'].append({
                        'name': access_list_name,
                        'entries': entries
                    })
            i += 1

    def _parse_as_path_sets(self, lines):
        """Parse ip as-path access-list definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('ip as-path access-list '):
                parts = line.split()
                if len(parts) >= 6:  # ip as-path access-list NAME permit/deny PATH
                    as_path_name = parts[3]
                    action = parts[4]  # permit or deny
                    path_pattern = ' '.join(parts[5:])  # the AS path pattern
                    
                    # Check if this as-path set already exists
                    existing = next((aps for aps in self.bgp_config['asPathSets'] if aps['name'] == as_path_name), None)
                    if existing:
                        existing['paths'].append(path_pattern)
                    else:
                        self.bgp_config['asPathSets'].append({
                            'name': as_path_name,
                            'paths': [path_pattern]
                        })
            i += 1

    def _parse_route_maps(self, lines):
        """Parse route-map definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('route-map '):
                parts = line.split()
                if len(parts) >= 4:  # route-map NAME permit/deny SEQUENCE
                    route_map_name = parts[1]
                    action = parts[2]  # permit or deny
                    sequence = parts[3]
                    
                    route_map_lines = []
                    prefix_sets = set()
                    community_sets = set()
                    as_path_sets = set()
                    i += 1

                    while i < len(lines):
                        original_line = lines[i].rstrip()
                        line = original_line.strip()
                        
                        # Stop if we hit another route-map or other top-level command
                        if (not original_line.startswith(' ') and not original_line.startswith('!') 
                            and original_line.strip() and not line.startswith('!')):
                            break
                        
                        if line and not line.startswith('!'):
                            route_map_lines.append(original_line)
                            
                            # Find prefix-list references
                            if 'prefix-list' in line:
                                prefix_matches = re.findall(r'prefix-list\s+(\w+)', line)
                                for match in prefix_matches:
                                    prefix_sets.add(match)
                            
                            # Find community-list references
                            if 'community-list' in line:
                                comm_matches = re.findall(r'community-list\s+(\w+)', line)
                                for match in comm_matches:
                                    community_sets.add(match)
                            
                            # Find as-path references
                            if 'as-path' in line:
                                as_path_matches = re.findall(r'as-path\s+(\w+)', line)
                                for match in as_path_matches:
                                    as_path_sets.add(match)
                        
                        i += 1

                    self.bgp_config['routeMaps'].append({
                        'name': route_map_name,
                        'action': action,
                        'sequence': sequence,
                        'lines': route_map_lines,
                        'prefixSets': list(prefix_sets),
                        'communitySets': list(community_sets),
                        'asPathSets': list(as_path_sets)
                    })
                    
                    continue
            i += 1

    def _parse_bgp_section(self, lines):
        """Parse the main BGP configuration section"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('router bgp '):
                self.bgp_config['asNumber'] = line.split()[2]
                i = self._parse_bgp_block(lines, i + 1)
                break
            i += 1

    def _parse_bgp_block(self, lines, start_idx):
        """Parse the BGP configuration block"""
        i = start_idx
        current_vrf = None
        processed_neighbors = set()  # Track processed neighbors to avoid duplicates

        while i < len(lines):
            original_line = lines[i]

            # Check if we've reached the end of BGP block (non-indented line that's not a comment)
            if not original_line.startswith(' ') and not original_line.startswith('!') and original_line.strip():
                # But make sure it's not the router bgp line itself
                if not original_line.strip().startswith('router bgp'):
                    break

            line = original_line.strip()

            if line.startswith('router-id '):
                self.bgp_config['routerId'] = line.split()[-1]

            elif line.startswith('neighbor ') and 'peer group' in line and original_line.startswith('   neighbor '):
                # This is a peer group definition (3 spaces)
                parts = line.split()
                if len(parts) >= 4 and parts[2] == 'peer' and parts[3] == 'group':  # neighbor GROUP_NAME peer group
                    group_name = parts[1]
                    # Make sure this is not an IP address being assigned to a peer group
                    import re
                    if not re.match(r'\d+\.\d+\.\d+\.\d+', group_name):
                        i = self._parse_peer_group(lines, i, group_name)
                        continue

            elif line.startswith('vrf ') and original_line.startswith('   vrf '):
                # VRF definition (3 spaces)
                vrf_name = line.split()[1]
                current_vrf = {'name': vrf_name, 'rd': '', 'neighbors': []}
                i = self._parse_vrf_block(lines, i + 1, current_vrf)
                self.bgp_config['vrfs'].append(current_vrf)
                current_vrf = None
                continue

            elif line.startswith('neighbor ') and original_line.startswith('   neighbor ') and not 'peer group' in line:
                # Global neighbor (3 spaces, not peer group definition)
                parts = line.split()
                if len(parts) >= 2:
                    neighbor_ip = parts[1]
                    # Only process IP addresses, not peer group names
                    import re
                    if re.match(r'\d+\.\d+\.\d+\.\d+', neighbor_ip):
                        # Only create neighbor object once per IP
                        if neighbor_ip not in processed_neighbors:
                            neighbor = {'ip': neighbor_ip, 'remoteAs': '', 'description': '', 'configs': []}
                            i = self._parse_neighbor_block(lines, i, neighbor, is_global=True)
                            if neighbor['remoteAs'] or neighbor['description']:  # Only add if we found actual config
                                self.bgp_config['globalNeighbors'].append(neighbor)
                            processed_neighbors.add(neighbor_ip)
                            continue

            i += 1

        return i

    def _parse_peer_group(self, lines, start_idx, group_name):
        """Parse peer group configuration"""
        i = start_idx
        group = {
            'name': group_name, 
            'remoteAs': '', 
            'description': '', 
            'configs': [], 
            'inRouteMap': None, 
            'outRouteMap': None
        }

        # Only collect lines that belong to this specific peer group
        while i < len(lines):
            original_line = lines[i].rstrip()
            line = original_line.strip()

            # Stop if we hit a different neighbor (not this peer group) or end of BGP section
            if not original_line.startswith('   ') and not original_line.startswith('!') and original_line.strip():
                break
                
            # Only process lines for this specific peer group
            if line.startswith(f'neighbor {group_name} '):
                config_part = line[len(f'neighbor {group_name} '):].strip()
                
                if config_part.startswith('description '):
                    # Handle quoted descriptions
                    if '"' in config_part:
                        group['description'] = config_part.split('"')[1]
                    else:
                        group['description'] = ' '.join(config_part.split()[1:])
                elif 'route-map ' in config_part and ' in' in config_part:
                    group['inRouteMap'] = config_part.split('route-map ')[1].split(' in')[0]
                elif 'route-map ' in config_part and ' out' in config_part:
                    group['outRouteMap'] = config_part.split('route-map ')[1].split(' out')[0]
                elif config_part.startswith('remote-as '):
                    group['remoteAs'] = config_part.split()[-1]

                group['configs'].append(config_part)
                
            # Stop when we encounter another peer group definition or a non-peer-group neighbor
            elif line.startswith('neighbor '):
                if 'peer group' in line and group_name not in line:
                    # This is a different peer group, stop here
                    break
                elif 'peer group' not in line:
                    # This is an actual neighbor (not a peer group), stop here
                    break

            i += 1

        # Only add the group if we found some configuration for it
        if group['description'] or group['configs']:
            self.bgp_config['peerGroups'].append(group)
        
        return i - 1

    def _parse_vrf_block(self, lines, start_idx, vrf):
        """Parse VRF configuration block"""
        i = start_idx
        processed_neighbors = set()  # Track processed neighbors in this VRF

        while i < len(lines):
            original_line = lines[i]
            line = original_line.strip()

            # VRF content should have 6 spaces (BGP VRF style)
            # Stop if we hit another VRF or end of BGP section
            if original_line.startswith('   vrf ') or (not original_line.startswith(' ') and not original_line.startswith('!') and original_line.strip()):
                break

            if line.startswith('rd '):
                vrf['rd'] = line.split()[-1]

            elif line.startswith('neighbor ') and original_line.startswith('      neighbor '):
                parts = line.split()
                if len(parts) >= 2:
                    neighbor_ip = parts[1]
                    # Only process IP addresses, not peer group names
                    import re
                    if re.match(r'\d+\.\d+\.\d+\.\d+', neighbor_ip):
                        # Only create neighbor object once per IP in this VRF
                        if neighbor_ip not in processed_neighbors:
                            neighbor = {'ip': neighbor_ip, 'remoteAs': '', 'description': '', 'configs': [], 'vrf': vrf['name']}
                            old_i = i
                            i = self._parse_neighbor_block(lines, i, neighbor, is_global=False)
                            if neighbor['remoteAs'] or neighbor['description']:  # Only add if we found actual config
                                vrf['neighbors'].append(neighbor)
                            processed_neighbors.add(neighbor_ip)
                            continue

            i += 1

        return i - 1

    def _parse_neighbor_block(self, lines, start_idx, neighbor, is_global=True):
        """Parse individual neighbor configuration"""
        neighbor_ip = neighbor['ip']
        found_configs = 0
        
        if is_global:
            # For global neighbors, scan the entire BGP section
            i = 0
            while i < len(lines) and not lines[i].strip().startswith('router bgp'):
                i += 1
            
            # Scan through all BGP configuration lines to find ALL neighbor configs
            while i < len(lines):
                original_line = lines[i]
                line = original_line.strip()

                # Stop if we've moved beyond BGP configuration section
                if not original_line.startswith(' ') and not original_line.startswith('!') and original_line.strip():
                    if not line.startswith('router bgp'):
                        break
                    
                # Skip VRF sections for global neighbors
                if original_line.startswith('   vrf '):
                    # Skip to end of this VRF
                    while i < len(lines):
                        i += 1
                        if i >= len(lines):
                            break
                        next_line = lines[i]
                        if next_line.startswith('   vrf ') or (not next_line.startswith(' ') and not next_line.startswith('!') and next_line.strip()):
                            i -= 1  # Step back one line
                            break
                    i += 1
                    continue

                # Only process lines that are for this specific neighbor IP
                if line.startswith(f'neighbor {neighbor_ip} '):
                    found_configs += 1
                    config_part = line[len(f'neighbor {neighbor_ip} '):].strip()
                    
                    if config_part.startswith('remote-as '):
                        neighbor['remoteAs'] = config_part.split()[-1]
                    elif config_part.startswith('peer group '):
                        neighbor['peerGroup'] = config_part.split()[-1]
                    elif config_part.startswith('description '):
                        if '"' in config_part:
                            neighbor['description'] = config_part.split('"')[1]
                        else:
                            neighbor['description'] = ' '.join(config_part.split()[1:])
                    elif 'route-map ' in config_part and ' in' in config_part:
                        neighbor['inRouteMap'] = config_part.split('route-map ')[1].split(' in')[0]
                    elif 'route-map ' in config_part and ' out' in config_part:
                        neighbor['outRouteMap'] = config_part.split('route-map ')[1].split(' out')[0]
                    elif config_part.startswith('default-originate'):
                        neighbor['defaultOriginate'] = config_part
                        # Extract route-map from default-originate if present
                        if 'route-map ' in config_part:
                            neighbor['defaultOriginateRouteMap'] = config_part.split('route-map ')[1].strip()

                    neighbor['configs'].append(config_part)

                i += 1
        else:
            # For VRF neighbors, only scan within the current VRF section
            # Find the start of our VRF section
            vrf_name = neighbor.get('vrf', '')
            vrf_start = -1
            in_bgp_section = False
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                # Track if we're in BGP section
                if line.startswith('router bgp'):
                    in_bgp_section = True
                elif not lines[i].startswith(' ') and not lines[i].startswith('!') and line and not line.startswith('router bgp'):
                    in_bgp_section = False
                
                # Look for our VRF within BGP section
                if in_bgp_section and line == f'vrf {vrf_name}':
                    vrf_start = i
                    break
                i += 1
            
            if vrf_start == -1:
                return start_idx
            
            # Scan within this VRF section
            i = vrf_start
            while i < len(lines):
                original_line = lines[i]
                line = original_line.strip()

                # Stop if we hit another VRF or end of BGP section
                if ((original_line.startswith('   vrf ') and line != f'vrf {vrf_name}') or
                    (not original_line.startswith(' ') and not original_line.startswith('!') and original_line.strip() and not line.startswith('router bgp'))):
                    break

                # Only process lines that are for this specific neighbor IP
                if line.startswith(f'neighbor {neighbor_ip} '):
                    found_configs += 1
                    config_part = line[len(f'neighbor {neighbor_ip} '):].strip()
                    
                    if config_part.startswith('remote-as '):
                        neighbor['remoteAs'] = config_part.split()[-1]
                    elif config_part.startswith('peer group '):
                        neighbor['peerGroup'] = config_part.split()[-1]
                    elif config_part.startswith('description '):
                        if '"' in config_part:
                            neighbor['description'] = config_part.split('"')[1]
                        else:
                            neighbor['description'] = ' '.join(config_part.split()[1:])
                    elif 'route-map ' in config_part and ' in' in config_part:
                        neighbor['inRouteMap'] = config_part.split('route-map ')[1].split(' in')[0]
                    elif 'route-map ' in config_part and ' out' in config_part:
                        neighbor['outRouteMap'] = config_part.split('route-map ')[1].split(' out')[0]
                    elif config_part.startswith('default-originate'):
                        neighbor['defaultOriginate'] = config_part
                        # Extract route-map from default-originate if present
                        if 'route-map ' in config_part:
                            neighbor['defaultOriginateRouteMap'] = config_part.split('route-map ')[1].strip()

                    neighbor['configs'].append(config_part)

                i += 1

        return start_idx

class AristaBGPWebHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.parser = AristaBGPParser()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests"""
        # Parse the path to ignore query parameters for root page
        path = self.path.split('?')[0]
        if path == '/' or path == '/index.html':
            self._serve_main_page()
        elif path == '/api/config':
            self._serve_config_api()
        elif path.startswith('/static/'):
            self._serve_static_file()
        else:
            self._send_404()

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/upload':
            self._handle_file_upload()
        elif self.path == '/generate':
            self._handle_config_generation()
        else:
            self._send_404()

    def _serve_main_page(self):
        """Serve the main HTML page for Arista EOS"""
        html_content = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Arista EOS BGP Configuration Viewer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%); color: white; border-radius: 8px; }
        .file-input { margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; border: 2px dashed #dee2e6; }
        .tree { font-family: 'Courier New', monospace; }
        .tree-item { margin: 5px 0; padding: 8px; border-radius: 4px; cursor: pointer; transition: background-color 0.2s; }
        .tree-item:hover { background-color: #e9ecef; }
        .tree-item.selected { background-color: #ff6b35; color: white; }
        .tree-item.bgp-root { background-color: #28a745; color: white; font-weight: bold; font-size: 16px; }
        .tree-item.vrf-item { background-color: #ff6b35; color: white; margin-left: 20px; font-weight: bold; }
        .tree-item.neighbor-item { margin-left: 40px; background-color: #ffc107; border-left: 3px solid #fd7e14; }
        .tree-item.peer-group-item { margin-left: 20px; background-color: #6c757d; color: white; }
        .tree-children { margin-left: 20px; max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }
        .tree-children.expanded { max-height: none; }
        .expand-icon { display: inline-block; width: 20px; margin-right: 5px; font-weight: bold; }
        .controls { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .button { background: #ff6b35; color: white; border: none; padding: 10px 20px; margin: 5px; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .button:hover { background: #e55a2b; }
        .button.success { background: #28a745; }
        .button.success:hover { background: #1e7e34; }
        .details-panel { display: none; margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 5px; border: 1px solid #dee2e6; }
        .route-map { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #dee2e6; }
        .route-map h4 { color: #495057; margin-top: 0; }
        .policy-line { font-family: 'Courier New', monospace; padding: 5px 10px; margin: 2px 0; background: #f8f9fa; border-left: 3px solid #dee2e6; cursor: pointer; transition: all 0.2s; }
        .policy-line:hover { background: #e9ecef; border-left-color: #ff6b35; }
        .policy-line.selected { background: #ffe6d9; border-left-color: #ff6b35; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; padding: 15px; background: #e9ecef; border-radius: 5px; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #495057; }
        .stat-label { font-size: 12px; color: #6c757d; }
        .selected-items { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 5px; border: 1px solid #ffeaa7; display: none; }
        .config-output { background: #2d3748; color: #e2e8f0; padding: 20px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }
        .original-config { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; margin: 5px 0; font-family: 'Courier New', monospace; }
        .config-line { font-family: 'Courier New', monospace; font-size: 12px; margin: 1px 0; padding: 2px; white-space: pre; position: relative; }
        .config-line label { position: absolute; right: 5px; top: 2px; }
        .config-line input[type="checkbox"] { margin: 0; }
        .config-line:hover { background-color: #e9ecef; }
        .prefix-details { background: #fff; border-left: 3px solid #ff6b35; margin: 10px 0; padding: 10px; }
        .hidden { display: none; }
        .loading { text-align: center; padding: 40px; color: #6c757d; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .success { color: #155724; background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍊 Arista EOS BGP Configuration Viewer</h1>
            <p>Arista EOS BGP Configuration Analysis Tool</p>
        </div>

        <div class="file-input">
            <h3>📁 Load Configuration File</h3>
            <div id="uploadForm">
                <input type="file" id="configFile" name="configFile" accept=".log,.txt,.cfg" required />
                <button type="button" class="button" id="uploadBtn">Upload & Parse</button>
            </div>
            <p style="margin: 10px 0 0 0; font-size: 14px; color: #6c757d;">
                Select your Arista EOS configuration file (config.log)
            </p>
            <div id="uploadStatus"></div>
        </div>

        <div id="configContent" class="hidden">
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number" id="bgpAsNumber">-</div>
                    <div class="stat-label">BGP AS</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="totalNeighbors">0</div>
                    <div class="stat-label">Total Neighbors</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="totalVrfs">0</div>
                    <div class="stat-label">VRFs</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="totalRouteMaps">0</div>
                    <div class="stat-label">Route Maps</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number" id="totalCommunityLists">0</div>
                    <div class="stat-label">Community Lists</div>
                </div>
            </div>

            <div class="controls">
                <button class="button" onclick="expandAll()">📂 Expand All</button>
                <button class="button" onclick="collapseAll()">📁 Collapse All</button>
                <button class="button" onclick="clearSelection()">🗑️ Clear Selection</button>
                <button class="button success" onclick="showSelectedDetails()">👁️ View Selected</button>
                <button class="button success" onclick="generateConfig()">💾 Generate Config</button>
            </div>
            <div class="selected-items" id="selectedItems">
                <h4>📋 Selected Items:</h4>
                <div id="selectedItemsList"></div>
            </div>

            <div class="tree" id="bgpTree"></div>

            <div class="details-panel" id="detailsPanel">
                <h3>📊 Selected Neighbors Details</h3>
                <div id="detailsContent"></div>
            </div>

            <div class="details-panel" id="configPanel">
                <h3>⚙️ Generated Configuration</h3>
                <button class="button" onclick="downloadConfig()">💾 Download Config</button>
                <div class="config-output" id="configOutput"></div>
            </div>
        </div>
    </div>

    <script>
        let bgpConfig = {};
        let selectedNeighbors = new Set();
        let selectedRouteMaps = new Set();
        let selectedPrefixLists = new Set();
        let selectedCommunityLists = new Set();

        // Button click handling
        document.addEventListener('DOMContentLoaded', function() {
            const uploadBtn = document.getElementById('uploadBtn');
            if (uploadBtn) {
                uploadBtn.addEventListener('click', function(event) {
                    handleUpload(event);
                });
                uploadBtn.style.cursor = 'pointer';
            }
        });

        async function handleUpload(event) {
            const formData = new FormData();
            const fileInput = document.getElementById('configFile');
            const file = fileInput.files[0];

            if (!file) {
                showStatus('Please select a file', 'error');
                return;
            }

            formData.append('configFile', file);
            showStatus('Uploading and parsing configuration...', 'loading');

            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    const result = await response.json();
                    if (result.success) {
                        bgpConfig = result.config;
                        displayConfig();
                        showStatus('Configuration loaded successfully!', 'success');
                        document.getElementById('configContent').classList.remove('hidden');
                    } else {
                        showStatus('Error: ' + result.error, 'error');
                    }
                } else {
                    showStatus('Upload failed: ' + response.statusText, 'error');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
            }
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('uploadStatus');
            statusDiv.innerHTML = '<div class="' + type + '">' + message + '</div>';
            if (type === 'loading') {
                statusDiv.innerHTML = '<div class="loading">' + message + '</div>';
            }
        }

        function displayConfig() {
            document.getElementById('bgpAsNumber').textContent = bgpConfig.asNumber;
            document.getElementById('totalNeighbors').textContent =
                bgpConfig.globalNeighbors.length + bgpConfig.vrfs.reduce((sum, vrf) => sum + vrf.neighbors.length, 0);
            document.getElementById('totalVrfs').textContent = bgpConfig.vrfs.length;
            document.getElementById('totalRouteMaps').textContent = bgpConfig.routeMaps.length;
            document.getElementById('totalCommunityLists').textContent = bgpConfig.communityLists.length;

            const tree = document.getElementById('bgpTree');
            tree.innerHTML = '';

            // BGP Root
            const bgpRoot = createTreeItem(
                `🍊 BGP AS ${bgpConfig.asNumber} (Router-ID: ${bgpConfig.routerId})`,
                'bgp-root', true
            );
            tree.appendChild(bgpRoot);

            const bgpChildren = document.createElement('div');
            bgpChildren.className = 'tree-children expanded';
            bgpRoot.appendChild(bgpChildren);

            // Global neighbors
            if (bgpConfig.globalNeighbors.length > 0) {
                const globalSection = createTreeItem(
                    `🌍 Global Neighbors (${bgpConfig.globalNeighbors.length})`,
                    'vrf-item', true
                );
                bgpChildren.appendChild(globalSection);

                const globalChildren = document.createElement('div');
                globalChildren.className = 'tree-children expanded';
                globalSection.appendChild(globalChildren);

                bgpConfig.globalNeighbors.forEach(neighbor => {
                    const neighborItem = createTreeItem(
                        `👥 ${neighbor.ip} (AS ${neighbor.remoteAs}) - ${neighbor.description}`,
                        'neighbor-item', false,
                        () => toggleNeighborSelection(neighbor.ip, 'Global')
                    );
                    globalChildren.appendChild(neighborItem);
                });
            }

            // VRF neighbors
            bgpConfig.vrfs.forEach(vrf => {
                const vrfItem = createTreeItem(
                    `📁 VRF ${vrf.name} (${vrf.neighbors.length} neighbors)`,
                    'vrf-item', true
                );
                bgpChildren.appendChild(vrfItem);

                const vrfChildren = document.createElement('div');
                vrfChildren.className = 'tree-children';
                vrfItem.appendChild(vrfChildren);

                vrf.neighbors.forEach(neighbor => {
                    const neighborItem = createTreeItem(
                        `👥 ${neighbor.ip} (AS ${neighbor.remoteAs}) - ${neighbor.description}`,
                        'neighbor-item', false,
                        () => toggleNeighborSelection(neighbor.ip, vrf.name)
                    );
                    vrfChildren.appendChild(neighborItem);
                });
            });
        }

        function createTreeItem(text, className, expandable, clickHandler) {
            const item = document.createElement('div');
            item.className = `tree-item ${className}`;

            const icon = document.createElement('span');
            icon.className = 'expand-icon';

            if (expandable) {
                icon.textContent = '▶';
                item.addEventListener('click', (e) => {
                    e.stopPropagation();
                    toggleExpand(item);
                });
            } else {
                icon.textContent = '•';
                if (clickHandler) {
                    item.addEventListener('click', (e) => {
                        e.stopPropagation();
                        clickHandler();
                        updateSelectedDisplay();
                    });
                }
            }

            const textSpan = document.createElement('span');
            textSpan.textContent = text;

            item.appendChild(icon);
            item.appendChild(textSpan);

            return item;
        }

        function toggleExpand(item) {
            const children = item.querySelector('.tree-children');
            if (children) {
                const icon = item.querySelector('.expand-icon');
                if (children.classList.contains('expanded')) {
                    children.classList.remove('expanded');
                    icon.textContent = '▶';
                } else {
                    children.classList.add('expanded');
                    icon.textContent = '▼';
                }
            }
        }

        function toggleNeighborSelection(neighborIp, context) {
            const key = `${neighborIp}@${context}`;
            const item = event.target.closest('.tree-item');

            if (selectedNeighbors.has(key)) {
                selectedNeighbors.delete(key);
                item.classList.remove('selected');
            } else {
                selectedNeighbors.add(key);
                item.classList.add('selected');
            }
        }

        function updateSelectedDisplay() {
            const selectedDiv = document.getElementById('selectedItems');
            const listDiv = document.getElementById('selectedItemsList');

            if (selectedNeighbors.size === 0 && selectedRouteMaps.size === 0 && selectedCommunityLists.size === 0) {
                selectedDiv.style.display = 'none';
                return;
            }

            selectedDiv.style.display = 'block';
            let html = '';

            if (selectedNeighbors.size > 0) {
                html += '<strong>Neighbors:</strong> ' + Array.from(selectedNeighbors).join(', ') + '<br>';
            }

            if (selectedRouteMaps.size > 0) {
                html += '<strong>Route Maps:</strong> ' + Array.from(selectedRouteMaps).join(', ') + '<br>';
            }

            if (selectedCommunityLists.size > 0) {
                html += '<strong>Community Lists:</strong> ' + Array.from(selectedCommunityLists).join(', ');
            }

            listDiv.innerHTML = html;
        }

        // Control functions
        function expandAll() {
            document.querySelectorAll('.tree-children').forEach(child => {
                child.classList.add('expanded');
            });
            document.querySelectorAll('.expand-icon').forEach(icon => {
                if (icon.textContent === '▶') icon.textContent = '▼';
            });
        }

        function collapseAll() {
            document.querySelectorAll('.tree-children').forEach((child, index) => {
                if (index > 0) child.classList.remove('expanded');
            });
            document.querySelectorAll('.expand-icon').forEach((icon, index) => {
                if (index > 0 && icon.textContent === '▼') icon.textContent = '▶';
            });
        }

        function clearSelection() {
            selectedNeighbors.clear();
            selectedRouteMaps.clear();
            selectedPrefixLists.clear();
            selectedCommunityLists.clear();
            document.querySelectorAll('.tree-item.selected').forEach(item => {
                item.classList.remove('selected');
            });
            updateSelectedDisplay();
            document.getElementById('detailsPanel').style.display = 'none';
            document.getElementById('configPanel').style.display = 'none';
        }

        function showSelectedDetails() {
            if (selectedNeighbors.size === 0) {
                alert('Please select at least one neighbor to view details.');
                return;
            }

            const detailsPanel = document.getElementById('detailsPanel');
            const detailsContent = document.getElementById('detailsContent');

            let html = '<h3>🔍 Detailed Configuration Analysis</h3>';

            selectedNeighbors.forEach(neighborKey => {
                const [neighborIp, context] = neighborKey.split('@');
                let neighbor = null;

                if (context === 'Global') {
                    neighbor = bgpConfig.globalNeighbors.find(n => n.ip === neighborIp);
                } else {
                    const vrf = bgpConfig.vrfs.find(v => v.name === context);
                    if (vrf) neighbor = vrf.neighbors.find(n => n.ip === neighborIp);
                }

                if (neighbor) {
                    const neighborId = `neighbor_${neighborIp}_${context.toLowerCase()}`;
                    html += `<div class="route-map" id="${neighborId}">
                        <h4>🔗 ${neighbor.ip} (${context})</h4>`;

                    html += `<div><strong>📄 Original Configuration:</strong>
                        <div class="original-config">`;

                    // Display original Arista EOS format - all neighbor commands are flat
                    const neighborIndent = context !== 'Global' ? '      ' : '   ';
                    
                    // Show peer group assignment first if exists
                    if (neighbor.peerGroup) {
                        html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} peer group ${neighbor.peerGroup}<label><input type="checkbox" onchange="expandPeerGroup(&quot;${neighbor.peerGroup}&quot;, &quot;${neighborIp}&quot;, &quot;${context}&quot;, this.checked)"></label></div>`;
                    }
                    
                    // Show remote-as
                    html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} remote-as ${neighbor.remoteAs}</div>`;
                    
                    // Show description
                    if (neighbor.description) {
                        html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} description "${neighbor.description}"</div>`;
                    }

                    // Show route-maps if not using peer group (peer group route-maps are shown in peer group expansion)
                    if (neighbor.inRouteMap && !neighbor.peerGroup) {
                        html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} route-map ${neighbor.inRouteMap} in<label><input type="checkbox" onchange="expandRouteMap(&quot;${neighbor.inRouteMap}&quot;, &quot;in&quot;, &quot;${neighborIp}&quot;, this.checked)"></label></div>`;
                    }
                    if (neighbor.outRouteMap && !neighbor.peerGroup) {
                        html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} route-map ${neighbor.outRouteMap} out<label><input type="checkbox" onchange="expandRouteMap(&quot;${neighbor.outRouteMap}&quot;, &quot;out&quot;, &quot;${neighborIp}&quot;, this.checked)"></label></div>`;
                    }
                    
                    // Show default-originate if exists
                    if (neighbor.defaultOriginate) {
                        if (neighbor.defaultOriginateRouteMap) {
                            html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} ${neighbor.defaultOriginate}<label><input type="checkbox" onchange="expandRouteMap(&quot;${neighbor.defaultOriginateRouteMap}&quot;, &quot;default&quot;, &quot;${neighborIp}&quot;, this.checked)"></label></div>`;
                        } else {
                            html += `<div class="config-line">${neighborIndent}neighbor ${neighborIp} ${neighbor.defaultOriginate}</div>`;
                        }
                    }
                    html += `</div></div>`;

                    // Add expansion containers
                    if (neighbor.peerGroup) {
                        html += `<div id="peergroup_${neighbor.peerGroup}_${neighborIp}" style="display: none;"></div>`;
                    }
                    if (neighbor.inRouteMap && !neighbor.peerGroup) {
                        html += `<div id="routemap_${neighbor.inRouteMap}_in_${neighborIp}" style="display: none;"></div>`;
                    }
                    if (neighbor.outRouteMap && !neighbor.peerGroup) {
                        html += `<div id="routemap_${neighbor.outRouteMap}_out_${neighborIp}" style="display: none;"></div>`;
                    }
                    if (neighbor.defaultOriginateRouteMap) {
                        html += `<div id="routemap_${neighbor.defaultOriginateRouteMap}_default_${neighborIp}" style="display: none;"></div>`;
                    }

                    html += '</div>';
                }
            });

            detailsContent.innerHTML = html;
            detailsPanel.style.display = 'block';
            detailsPanel.scrollIntoView({ behavior: 'smooth' });
        }

        function expandPeerGroup(groupName, neighborIp, context, show) {
            const containerId = `peergroup_${groupName}_${neighborIp}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                const peerGroup = bgpConfig.peerGroups.find(pg => pg.name === groupName);
                if (peerGroup) {
                    let html = `<div class="original-config">
                        <div class="config-line">   neighbor ${groupName} peer group</div>`;

                    // Show description if exists
                    if (peerGroup.description) {
                        html += `<div class="config-line">   neighbor ${groupName} description "${peerGroup.description}"</div>`;
                    }

                    // Show all peer group configurations in original Arista format
                    peerGroup.configs.forEach(line => {
                        const trimmedLine = line.trim();
                        if (trimmedLine && trimmedLine !== '!' && !trimmedLine.startsWith('description') && !trimmedLine.startsWith('peer group')) {
                            if (trimmedLine.includes('route-map') && trimmedLine.includes(' in')) {
                                const routeMapName = trimmedLine.split('route-map ')[1].split(' in')[0];
                                html += `<div class="config-line">   neighbor ${groupName} ${trimmedLine}<label><input type="checkbox" onchange="expandRouteMap(&quot;${routeMapName}&quot;, &quot;in&quot;, &quot;${neighborIp}_group&quot;, this.checked)"></label></div>`;
                            } else if (trimmedLine.includes('route-map') && trimmedLine.includes(' out')) {
                                const routeMapName = trimmedLine.split('route-map ')[1].split(' out')[0];
                                html += `<div class="config-line">   neighbor ${groupName} ${trimmedLine}<label><input type="checkbox" onchange="expandRouteMap(&quot;${routeMapName}&quot;, &quot;out&quot;, &quot;${neighborIp}_group&quot;, this.checked)"></label></div>`;
                            } else {
                                html += `<div class="config-line">   neighbor ${groupName} ${trimmedLine}</div>`;
                            }
                        }
                    });

                    html += `</div>`;

                    // Add expansion containers for route maps
                    peerGroup.configs.forEach(line => {
                        const trimmedLine = line.trim();
                        if (trimmedLine.includes('route-map') && trimmedLine.includes(' in')) {
                            const routeMapName = trimmedLine.split('route-map ')[1].split(' in')[0];
                            html += `<div id="routemap_${routeMapName}_in_${neighborIp}_group" style="display: none;"></div>`;
                        } else if (trimmedLine.includes('route-map') && trimmedLine.includes(' out')) {
                            const routeMapName = trimmedLine.split('route-map ')[1].split(' out')[0];
                            html += `<div id="routemap_${routeMapName}_out_${neighborIp}_group" style="display: none;"></div>`;
                        }
                    });

                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function expandRouteMap(routeMapName, direction, neighborId, show) {
            const containerId = `routemap_${routeMapName}_${direction}_${neighborId}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                // Find ALL route-map entries with the same name (all sequences)
                const routeMaps = bgpConfig.routeMaps.filter(rm => rm.name === routeMapName);
                if (routeMaps.length > 0) {
                    let html = `<div class="original-config">`;

                    // Display all sequences for this route-map
                    routeMaps.forEach(routeMap => {
                        html += `<div class="config-line">route-map ${routeMapName} ${routeMap.action} ${routeMap.sequence}</div>`;
                        
                        routeMap.lines.forEach((line, index) => {
                        const originalLine = line;
                        const trimmedLine = line.trim();

                         // Check for all types of expandable references
                         let hasExpandableReference = false;
                         let expandHtml = originalLine;
                         
                         // Check for prefix-list
                         if (trimmedLine.includes('prefix-list')) {
                             const prefixMatch = trimmedLine.match(/prefix-list\\s+(\\w+)/);
                             if (prefixMatch) {
                                 expandHtml += `<label><input type="checkbox" onchange="expandPrefixList(&quot;${prefixMatch[1]}&quot;, &quot;${routeMapName}_${neighborId}_${index}&quot;, this.checked)"></label>`;
                                 hasExpandableReference = true;
                             }
                         }
                         
                         // Check for community-list
                         if (trimmedLine.includes('community-list')) {
                             const commMatch = trimmedLine.match(/community-list\\s+(\\w+)/);
                             if (commMatch) {
                                 if (!hasExpandableReference) expandHtml += `<label>`;
                                 expandHtml += `<input type="checkbox" onchange="expandCommunityList(&quot;${commMatch[1]}&quot;, &quot;${routeMapName}_${neighborId}_${index}&quot;, this.checked)">`;
                                 if (!hasExpandableReference) expandHtml += `</label>`;
                                 hasExpandableReference = true;
                             }
                         }
                         
                         // Check for access-list
                         if (trimmedLine.includes('access-list')) {
                             const accessMatch = trimmedLine.match(/access-list\\s+(\\w+)/);
                             if (accessMatch) {
                                 if (!hasExpandableReference) expandHtml += `<label>`;
                                 expandHtml += `<input type="checkbox" onchange="expandAccessList(&quot;${accessMatch[1]}&quot;, &quot;${routeMapName}_${neighborId}_${index}&quot;, this.checked)">`;
                                 if (!hasExpandableReference) expandHtml += `</label>`;
                                 hasExpandableReference = true;
                             }
                         }
                         
                         // Check for as-path
                         if (trimmedLine.includes('as-path')) {
                             const asPathMatch = trimmedLine.match(/as-path\\s+(\\w+)/);
                             if (asPathMatch) {
                                 if (!hasExpandableReference) expandHtml += `<label>`;
                                 expandHtml += `<input type="checkbox" onchange="expandAsPathSet(&quot;${asPathMatch[1]}&quot;, &quot;${routeMapName}_${neighborId}_${index}&quot;, this.checked)">`;
                                 if (!hasExpandableReference) expandHtml += `</label>`;
                                 hasExpandableReference = true;
                             }
                         }
                         
                         html += `<div class="config-line">${expandHtml}</div>`;
                        });
                    });
                    
                    html += `</div>`;

                    // Add expansion containers
                    const addedSets = new Set();
                    routeMaps.forEach(routeMap => {
                        routeMap.lines.forEach((line, index) => {
                            // Prefix-list containers
                            const prefixMatches = line.match(/prefix-list\\s+(\\w+)/g) || [];
                            prefixMatches.forEach(match => {
                                const prefixName = match.split(' ')[1];
                                const setId = `prefixlist_${prefixName}_${routeMapName}_${neighborId}_${index}`;
                                if (!addedSets.has(setId)) {
                                    addedSets.add(setId);
                                    html += `<div id="${setId}" style="display: none;"></div>`;
                                }
                            });

                            // Community-list containers
                            const commMatches = line.match(/community-list\\s+(\\w+)/g) || [];
                            commMatches.forEach(match => {
                                const commName = match.split(' ')[1];
                                const setId = `communitylist_${commName}_${routeMapName}_${neighborId}_${index}`;
                                if (!addedSets.has(setId)) {
                                    addedSets.add(setId);
                                    html += `<div id="${setId}" style="display: none;"></div>`;
                                }
                            });

                            // Access-list containers
                            const accessMatches = line.match(/access-list\\s+(\\w+)/g) || [];
                            accessMatches.forEach(match => {
                                const accessName = match.split(' ')[1];
                                const setId = `accesslist_${accessName}_${routeMapName}_${neighborId}_${index}`;
                                if (!addedSets.has(setId)) {
                                    addedSets.add(setId);
                                    html += `<div id="${setId}" style="display: none;"></div>`;
                                }
                            });

                            // AS-path containers
                            const asPathMatches = line.match(/as-path\\s+(\\w+)/g) || [];
                            asPathMatches.forEach(match => {
                                const asPathName = match.split(' ')[1];
                                const setId = `aspathset_${asPathName}_${routeMapName}_${neighborId}_${index}`;
                                if (!addedSets.has(setId)) {
                                    addedSets.add(setId);
                                    html += `<div id="${setId}" style="display: none;"></div>`;
                                }
                            });
                        });
                    });

                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function expandPrefixList(prefixName, uniqueId, show) {
            const containerId = `prefixlist_${prefixName}_${uniqueId}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                const prefixList = bgpConfig.prefixLists[prefixName];
                if (prefixList) {
                    let html = `<div class="original-config">
                        <div class="config-line">ip prefix-list ${prefixName}</div>`;

                    prefixList.forEach(prefix => {
                        html += `<div class="config-line"> seq 10 ${prefix}</div>`;
                    });

                    html += `</div>`;
                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function expandCommunityList(commName, uniqueId, show) {
            const containerId = `communitylist_${commName}_${uniqueId}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                const commList = bgpConfig.communityLists.find(cl => cl.name === commName);
                if (commList) {
                    let html = `<div class="original-config">
                        <div class="config-line">ip community-list ${commName}</div>`;

                    commList.communities.forEach(community => {
                        html += `<div class="config-line"> permit ${community}</div>`;
                    });

                    html += `</div>`;
                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function expandAccessList(accessName, uniqueId, show) {
            const containerId = `accesslist_${accessName}_${uniqueId}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                const accessList = bgpConfig.accessLists.find(al => al.name === accessName);
                if (accessList) {
                    let html = `<div class="original-config">
                        <div class="config-line">ip access-list ${accessName}</div>`;

                    accessList.entries.forEach(entry => {
                        html += `<div class="config-line">   ${entry}</div>`;
                    });

                    html += `</div>`;
                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function expandAsPathSet(asPathName, uniqueId, show) {
            const containerId = `aspathset_${asPathName}_${uniqueId}`;
            const container = document.getElementById(containerId);
            if (!container) return;

            if (show) {
                const asPathSet = bgpConfig.asPathSets.find(aps => aps.name === asPathName);
                if (asPathSet) {
                    let html = `<div class="original-config">
                        <div class="config-line">ip as-path access-list ${asPathName}</div>`;

                    asPathSet.paths.forEach(path => {
                        html += `<div class="config-line">   permit ${path}</div>`;
                    });

                    html += `</div>`;
                    container.innerHTML = html;
                }
                container.style.display = 'block';
            } else {
                container.style.display = 'none';
            }
        }

        function formatConfigLines(lines) {
            if (lines.length === 0) return '';
            
            const formattedLines = [];
            let lastConfigBlockType = null;
            
            lines.forEach((line, index) => {
                const trimmedLine = line.trim();
                const originalLine = line;
                let currentConfigBlockType = null;
                
                // Identify config block types based on line content
                if (trimmedLine.startsWith('route-map ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 4) {
                        // Different route-maps are different blocks
                        currentConfigBlockType = `route-map_${parts[1]}`;
                    }
                } else if (trimmedLine.startsWith('ip prefix-list ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 3) {
                        currentConfigBlockType = `prefix-list_${parts[2]}`;
                    }
                } else if (trimmedLine.startsWith('ip community-list ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 3) {
                        currentConfigBlockType = `community-list_${parts[2]}`;
                    }
                } else if (trimmedLine.startsWith('ip access-list ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 3) {
                        currentConfigBlockType = `access-list_${parts[2]}`;
                    }
                } else if (trimmedLine.startsWith('ip as-path access-list ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 4) {
                        currentConfigBlockType = `as-path-list_${parts[3]}`;
                    }
                } else if (trimmedLine.startsWith('neighbor ')) {
                    const parts = trimmedLine.split(' ');
                    if (parts.length >= 2) {
                        const neighborTarget = parts[1];
                        // Check if it's an IP address or peer group name
                        if (neighborTarget.match(/^\\d+\\.\\d+\\.\\d+\\.\\d+$/)) {
                            // IP address neighbor block
                            currentConfigBlockType = `neighbor-ip_${neighborTarget}`;
                        } else {
                            // Peer group neighbor block
                            currentConfigBlockType = `neighbor-group_${neighborTarget}`;
                        }
                    }
                }
                
                // Add blank line before new config block (except for first line)
                if (currentConfigBlockType && 
                    lastConfigBlockType && 
                    currentConfigBlockType !== lastConfigBlockType && 
                    formattedLines.length > 0) {
                    formattedLines.push(''); // Add blank line
                }
                
                formattedLines.push(line);
                
                // Update last config block type
                if (currentConfigBlockType) {
                    lastConfigBlockType = currentConfigBlockType;
                }
            });
            
            return formattedLines.join('\\n');
        }

        function generateConfig() {
            let configText = '';
            const configLines = document.querySelectorAll('.config-line');
            const visibleConfigSections = [];
            let currentNeighborInfo = null;
            let currentSectionLines = [];

            configLines.forEach(line => {
                let element = line;
                let isVisible = true;

                // Check if line is visible
                while (element && element !== document.body) {
                    if (element.style && element.style.display === 'none') {
                        isVisible = false;
                        break;
                    }
                    element = element.parentElement;
                }

                if (isVisible) {
                    const textContent = line.textContent || line.innerText || '';
                    if (textContent.trim()) {
                        // Try to determine neighbor context from DOM hierarchy
                        let neighborContext = null;
                        let parentElement = line.parentElement;
                        
                        // Look for neighbor context in parent hierarchy
                        while (parentElement && parentElement !== document.body) {
                            if (parentElement.id && parentElement.id.startsWith('neighbor_')) {
                                const parts = parentElement.id.split('_');
                                if (parts.length >= 3) {
                                    const neighborIp = parts[1];
                                    const vrfType = parts.slice(2).join('_'); // Handle VRF names with underscores like vrf_a
                                    neighborContext = {
                                        ip: neighborIp,
                                        vrf: vrfType === 'global' ? 'Global' : vrfType.toUpperCase().replace('VRF_', 'VRF_')
                                    };
                                    break;
                                }
                            }
                            parentElement = parentElement.parentElement;
                        }

                        // If we found a new neighbor context, save previous section and start new one
                        if (neighborContext && 
                            (!currentNeighborInfo || 
                             currentNeighborInfo.ip !== neighborContext.ip || 
                             currentNeighborInfo.vrf !== neighborContext.vrf)) {
                            
                            // Save previous section if exists
                            if (currentNeighborInfo && currentSectionLines.length > 0) {
                                visibleConfigSections.push({
                                    neighbor: currentNeighborInfo,
                                    lines: [...currentSectionLines]
                                });
                                currentSectionLines = [];
                            }
                            
                            currentNeighborInfo = neighborContext;
                        }

                        // Add line to current section (skip header lines)
                        if (!textContent.startsWith('🔗') && !textContent.includes('Original Configuration:')) {
                            currentSectionLines.push(textContent);
                        }
                    }
                }
            });

            // Add the last section if exists
            if (currentNeighborInfo && currentSectionLines.length > 0) {
                visibleConfigSections.push({
                    neighbor: currentNeighborInfo,
                    lines: [...currentSectionLines]
                });
            }

            // If no neighbor-specific sections found, fall back to original behavior
            if (visibleConfigSections.length === 0) {
                const allVisibleLines = [];
                configLines.forEach(line => {
                    let element = line;
                    let isVisible = true;

                    while (element && element !== document.body) {
                        if (element.style && element.style.display === 'none') {
                            isVisible = false;
                            break;
                        }
                        element = element.parentElement;
                    }

                    if (isVisible) {
                        const textContent = line.textContent || line.innerText || '';
                        if (textContent.trim() && !textContent.startsWith('🔗') && !textContent.includes('Original Configuration:')) {
                            allVisibleLines.push(textContent);
                        }
                    }
                });

                if (allVisibleLines.length === 0) {
                    alert('No configuration visible to generate. Please expand some neighbors or policies first.');
                    return;
                }

                configText = formatConfigLines(allVisibleLines);
            } else {
                // Generate config with neighbor separators
                const configParts = [];
                visibleConfigSections.forEach((section, index) => {
                    const separator = `!\\n! ******** ${section.neighbor.ip} (${section.neighbor.vrf}) ********\\n!`;
                    configParts.push(separator);
                    
                    // Format section lines with spacing between different config blocks
                    const formattedLines = formatConfigLines(section.lines);
                    configParts.push(formattedLines);
                    
                    if (index < visibleConfigSections.length - 1) {
                        configParts.push('!'); // Add blank line between sections (except after last)
                    }
                });
                configText = configParts.join('\\n');
            }

            const configPanel = document.getElementById('configPanel');
            const configOutput = document.getElementById('configOutput');
            configOutput.textContent = configText;
            configPanel.style.display = 'block';
            configPanel.scrollIntoView({ behavior: 'smooth' });
        }

        function downloadConfig() {
            const configOutput = document.getElementById('configOutput');
            if (!configOutput.textContent) {
                alert('No configuration generated yet. Please generate configuration first.');
                return;
            }

            const blob = new Blob([configOutput.textContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `arista_bgp_config_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>'''

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())

    def _handle_file_upload(self):
        """Handle file upload and parsing"""
        try:
            # Parse multipart form data
            content_type = self.headers['Content-Type']
            if 'multipart/form-data' not in content_type:
                self._send_json_response(400, {'success': False, 'error': 'Invalid content type'})
                return

            # Get boundary
            boundary = content_type.split('boundary=')[1].encode()

            # Read the entire request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Parse multipart data manually
            parts = post_data.split(b'--' + boundary)

            file_content = None
            for part in parts:
                if b'filename=' in part and b'Content-Type:' in part:
                    # Extract file content
                    content_start = part.find(b'\r\n\r\n') + 4
                    if content_start > 3:
                        file_content = part[content_start:].rstrip(b'\r\n').decode('utf-8', errors='ignore')
                        break

            if not file_content:
                self._send_json_response(400, {'success': False, 'error': 'No file content found'})
                return

            # Parse the configuration
            config = self.parser.parse_config(file_content)

            self._send_json_response(200, {
                'success': True,
                'config': config
            })

        except Exception as e:
            print(f"Upload error: {e}")
            self._send_json_response(500, {'success': False, 'error': str(e)})

    def _handle_config_generation(self):
        """Handle configuration generation for Arista EOS"""
        try:
            # Read JSON data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)

            neighbors = data.get('neighbors', [])
            route_maps = data.get('routeMaps', [])
            prefix_lists = data.get('prefixLists', [])
            community_lists = data.get('communityLists', [])

            # Generate configuration
            config_lines = []
            config_lines.append('! Generated Arista EOS BGP Configuration')
            config_lines.append(f'! Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            config_lines.append('!')

            # Add selected prefix-lists
            for prefix_name in prefix_lists:
                if prefix_name in self.parser.bgp_config['prefixLists']:
                    for prefix in self.parser.bgp_config['prefixLists'][prefix_name]:
                        config_lines.append(f'ip prefix-list {prefix_name} {prefix}')
                    config_lines.append('!')

            # Add selected community-lists
            for community_name in community_lists:
                community_list = next((cl for cl in self.parser.bgp_config['communityLists'] if cl['name'] == community_name), None)
                if community_list:
                    for community in community_list['communities']:
                        config_lines.append(f'ip community-list {community_name} permit {community}')
                    config_lines.append('!')

            # Add selected route maps
            for route_map_name in route_maps:
                route_map = next((rm for rm in self.parser.bgp_config['routeMaps'] if rm['name'] == route_map_name), None)
                if route_map:
                    config_lines.append(f'route-map {route_map_name} {route_map["action"]} {route_map["sequence"]}')
                    for line in route_map['lines']:
                        config_lines.append(line)
                    config_lines.append('!')

            # Add BGP configuration for selected neighbors
            if neighbors:
                config_lines.append(f'router bgp {self.parser.bgp_config["asNumber"]}')
                config_lines.append(f' router-id {self.parser.bgp_config["routerId"]}')

                # Process neighbors
                global_neighbors = []
                vrf_neighbors = {}

                for neighbor_key in neighbors:
                    neighbor_ip, context = neighbor_key.split('@')

                    if context == 'Global':
                        neighbor = next((n for n in self.parser.bgp_config['globalNeighbors'] if n['ip'] == neighbor_ip), None)
                        if neighbor:
                            global_neighbors.append(neighbor)
                    else:
                        vrf = next((v for v in self.parser.bgp_config['vrfs'] if v['name'] == context), None)
                        if vrf:
                            neighbor = next((n for n in vrf['neighbors'] if n['ip'] == neighbor_ip), None)
                            if neighbor:
                                if context not in vrf_neighbors:
                                    vrf_neighbors[context] = {'vrf': vrf, 'neighbors': []}
                                vrf_neighbors[context]['neighbors'].append(neighbor)

                # Add global neighbors
                for neighbor in global_neighbors:
                    config_lines.append(f' neighbor {neighbor["ip"]}')
                    for config_line in neighbor['configs']:
                        if config_line.strip():
                            config_lines.append(f'  {config_line}')
                    config_lines.append(' !')

                # Add VRF neighbors
                for context, vrf_data in vrf_neighbors.items():
                    config_lines.append(f' vrf {context}')
                    if vrf_data["vrf"]["rd"]:
                        config_lines.append(f'  rd {vrf_data["vrf"]["rd"]}')
                    for neighbor in vrf_data['neighbors']:
                        config_lines.append(f'  neighbor {neighbor["ip"]}')
                        for config_line in neighbor['configs']:
                            if config_line.strip():
                                config_lines.append(f'   {config_line}')
                        config_lines.append('  !')
                    config_lines.append(' !')

                config_lines.append('!')

            generated_config = '\n'.join(config_lines)

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(generated_config.encode())

        except Exception as e:
            print(f"Config generation error: {e}")
            self._send_json_response(500, {'error': str(e)})

    def _send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_404(self):
        """Send 404 response"""
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'404 Not Found')

def main():
    PORT = 8082

    # Test parsing with the actual Arista config file first
    if os.path.exists("/Users/qiaoshu/Documents/playground/arista config.log"):
        print("Testing parser with actual config file...")
        parser = AristaBGPParser()
        with open("/Users/qiaoshu/Documents/playground/arista config.log", 'r', encoding='utf-8-sig') as f:
            content = f.read()
        config = parser.parse_config(content)
        print(f"Test parse results: AS {config['asNumber']}, Router ID {config['routerId']}")
        print(f"Global neighbors: {len(config['globalNeighbors'])}")
        print(f"VRFs: {len(config['vrfs'])}")
        print(f"Route maps: {len(config['routeMaps'])}")
        print(f"Prefix lists: {len(config['prefixLists'])}")
        print(f"Peer groups: {len(config['peerGroups'])}")
        print()

    with socketserver.TCPServer(("", PORT), AristaBGPWebHandler) as httpd:
        print(f"🍊 Arista EOS BGP Configuration Viewer starting...")
        print(f"📡 Server running at http://localhost:{PORT}")
        print(f"🔗 Open your browser and navigate to the URL above")
        print(f"📁 Upload your 'arista config.log' file to get started")
        print(f"⏹️  Press Ctrl+C to stop the server")
        print()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped by user")
            httpd.shutdown()

if __name__ == "__main__":
    main()
