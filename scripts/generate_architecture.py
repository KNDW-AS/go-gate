#!/usr/bin/env python3
"""
GO-GATE Architecture Diagram Generator (SVG)
Generates a clean SVG architecture diagram.
100% owned - no external dependencies.
"""

import os

def generate_svg():
    # SVG dimensions
    width = 1280
    height = 720
    
    # Colors
    bg_color = "#1a1a2e"
    box_dark = "#16213e"
    box_engine = "#0f3460"
    box_accent = "#e94560"
    text_color = "#ffffff"
    accent_blue = "#4a9eff"
    
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
  <!-- Background -->
  <rect width="{width}" height="{height}" fill="{bg_color}"/>
  
  <!-- Title -->
  <text x="{width//2}" y="60" font-family="Arial, sans-serif" font-size="48" 
        font-weight="bold" fill="{accent_blue}" text-anchor="middle">GO-GATE™</text>
  <text x="{width//2}" y="100" font-family="Arial, sans-serif" font-size="24" 
        fill="{text_color}" text-anchor="middle">AI Agent Security Kernel</text>
  
  <!-- Top Row Boxes -->
  <!-- Agent Request -->
  <rect x="120" y="160" width="200" height="80" rx="15" fill="{box_dark}" stroke="{text_color}" stroke-width="2"/>
  <text x="220" y="195" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Agent</text>
  <text x="220" y="220" font-family="Arial, sans-serif" font-size="16" 
        fill="{text_color}" text-anchor="middle">Request</text>
  
  <!-- GO-GATE 2PC Engine -->
  <rect x="480" y="150" width="320" height="100" rx="15" fill="{box_engine}" stroke="{accent_blue}" stroke-width="3"/>
  <text x="640" y="190" font-family="Arial, sans-serif" font-size="22" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">GO-GATE</text>
  <text x="640" y="220" font-family="Arial, sans-serif" font-size="20" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">2PC Engine</text>
  
  <!-- Human Approval -->
  <rect x="960" y="160" width="200" height="80" rx="15" fill="{box_dark}" stroke="{text_color}" stroke-width="2"/>
  <text x="1060" y="195" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Human</text>
  <text x="1060" y="220" font-family="Arial, sans-serif" font-size="16" 
        fill="{text_color}" text-anchor="middle">Approval</text>
  
  <!-- Arrows (Top Row) -->
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="{accent_blue}"/>
    </marker>
  </defs>
  <line x1="320" y1="200" x2="480" y2="200" stroke="{accent_blue}" stroke-width="4" marker-end="url(#arrowhead)"/>
  <line x1="800" y1="200" x2="960" y2="200" stroke="{accent_blue}" stroke-width="4" marker-end="url(#arrowhead)"/>
  
  <!-- Arrow Labels -->
  <text x="400" y="190" font-family="Arial, sans-serif" font-size="14" 
        font-weight="bold" fill="{accent_blue}" text-anchor="middle">PREPARE</text>
  <text x="880" y="190" font-family="Arial, sans-serif" font-size="14" 
        font-weight="bold" fill="{accent_blue}" text-anchor="middle">PENDING</text>
  
  <!-- Bottom Row Boxes -->
  <!-- Policy Engine -->
  <rect x="140" y="380" width="200" height="80" rx="15" fill="{box_accent}" stroke="{text_color}" stroke-width="2"/>
  <text x="240" y="415" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Policy</text>
  <text x="240" y="440" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Engine</text>
  
  <!-- Sandbox Executor -->
  <rect x="540" y="380" width="200" height="80" rx="15" fill="{box_accent}" stroke="{text_color}" stroke-width="2"/>
  <text x="640" y="415" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Sandbox</text>
  <text x="640" y="440" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Executor</text>
  
  <!-- Audit Trail -->
  <rect x="940" y="380" width="200" height="80" rx="15" fill="{box_accent}" stroke="{text_color}" stroke-width="2"/>
  <text x="1040" y="415" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Audit</text>
  <text x="1040" y="440" font-family="Arial, sans-serif" font-size="18" 
        font-weight="bold" fill="{text_color}" text-anchor="middle">Trail</text>
  
  <!-- Arrows (Engine to Components) -->
  <line x1="560" y1="250" x2="280" y2="380" stroke="{accent_blue}" stroke-width="3" marker-end="url(#arrowhead)"/>
  <line x1="640" y1="250" x2="640" y2="380" stroke="{accent_blue}" stroke-width="3" marker-end="url(#arrowhead)"/>
  <line x1="720" y1="250" x2="1000" y2="380" stroke="{accent_blue}" stroke-width="3" marker-end="url(#arrowhead)"/>
  
  <!-- Risk Level Indicators -->
  <rect x="160" y="530" width="180" height="50" rx="10" fill="none" stroke="#00d9ff" stroke-width="2"/>
  <text x="250" y="560" font-family="Arial, sans-serif" font-size="16" 
        font-weight="bold" fill="#00d9ff" text-anchor="middle">LOW → COMMIT</text>
  
  <rect x="550" y="530" width="180" height="50" rx="10" fill="none" stroke="#ffd700" stroke-width="2"/>
  <text x="640" y="560" font-family="Arial, sans-serif" font-size="16" 
        font-weight="bold" fill="#ffd700" text-anchor="middle">MEDIUM → VERIFY</text>
  
  <rect x="940" y="530" width="180" height="50" rx="10" fill="none" stroke="#ff6b6b" stroke-width="2"/>
  <text x="1030" y="560" font-family="Arial, sans-serif" font-size="16" 
        font-weight="bold" fill="#ff6b6b" text-anchor="middle">HIGH → HUMAN</text>
  
  <!-- Tagline -->
  <text x="{width//2}" y="640" font-family="Arial, sans-serif" font-size="16" 
        fill="{accent_blue}" text-anchor="middle" opacity="0.9">
    Fail-Closed Security · Immutable Audit · Sandboxed Execution
  </text>
  
  <!-- Footer -->
  <text x="{width//2}" y="690" font-family="Arial, sans-serif" font-size="18" 
        fill="{text_color}" text-anchor="middle" opacity="0.8">
    Designed in Norway 🇳🇴
  </text>
</svg>'''
    
    # Save SVG
    os.makedirs('docs/assets', exist_ok=True)
    svg_path = 'docs/assets/go-gate-architecture.svg'
    with open(svg_path, 'w') as f:
        f.write(svg)
    print(f'✅ SVG saved to {svg_path}')
    print(f'   Dimensions: {width}x{height}')
    
    return svg_path

if __name__ == '__main__':
    generate_svg()
    print('\nNote: Convert SVG to PNG for best GitHub rendering:')
    print('  inkscape go-gate-architecture.svg --export-filename=go-gate-architecture.png')
    print('  or use: cairosvg go-gate-architecture.svg -o go-gate-architecture.png')
