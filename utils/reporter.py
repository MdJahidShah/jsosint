#!/usr/bin/env python3
"""
Report generator for jsosint
"""

import json
import csv
import os
from datetime import datetime
from jinja2 import Template

class ReportGenerator:
    """Generate reports in different formats"""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def save_results(self, results, filename=None, format='json'):
        """Save results to file"""
        
        if not filename:
            filename = f"jsosint_report_{self.timestamp}.{format}"
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        full_path = os.path.join('results', filename)
        
        if format == 'json':
            with open(full_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        elif format == 'txt':
            with open(full_path, 'w') as f:
                self._generate_text_report(results, f)
        
        elif format == 'csv':
            with open(full_path, 'w', newline='') as f:
                self._generate_csv_report(results, f)
        
        elif format == 'html':
            with open(full_path, 'w') as f:
                self._generate_html_report(results, f)
        
        return full_path
    
    def _generate_text_report(self, results, file):
        """Generate text report"""
        file.write(f"jsosint Report\n")
        file.write(f"Generated: {datetime.now()}\n")
        file.write("=" * 60 + "\n\n")
        
        if 'metadata' in results:
            file.write("METADATA:\n")
            for key, value in results['metadata'].items():
                file.write(f"  {key}: {value}\n")
            file.write("\n")
        
        # Process different result sections
        for section, data in results.items():
            if section == 'metadata':
                continue
            
            file.write(f"{section.upper()}:\n")
            file.write("-" * 40 + "\n")
            
            if isinstance(data, dict):
                for key, value in data.items():
                    file.write(f"  {key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    file.write(f"  {item}\n")
            else:
                file.write(f"  {data}\n")
            file.write("\n")
    
    def _generate_csv_report(self, results, file):
        """Generate CSV report"""
        writer = csv.writer(file)
        
        # Write metadata
        writer.writerow(['Section', 'Key', 'Value'])
        if 'metadata' in results:
            for key, value in results['metadata'].items():
                writer.writerow(['metadata', key, value])
        
        # Write other sections
        for section, data in results.items():
            if section == 'metadata':
                continue
            
            if isinstance(data, dict):
                for key, value in data.items():
                    writer.writerow([section, key, value])
    
    def _generate_html_report(self, results, file):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>jsosint Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .section { margin: 20px 0; border: 1px solid #ddd; padding: 15px; }
                .section-title { background: #ecf0f1; padding: 10px; font-weight: bold; }
                .data { margin: 10px 0; }
                .key { font-weight: bold; color: #2c3e50; }
                .value { margin-left: 10px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>jsosint Report</h1>
                <p>Generated: {{ timestamp }}</p>
            </div>
            
            {% for section, data in results.items() %}
            <div class="section">
                <div class="section-title">{{ section }}</div>
                <div class="data">
                    {% if data is mapping %}
                        {% for key, value in data.items() %}
                            <div><span class="key">{{ key }}:</span> <span class="value">{{ value }}</span></div>
                        {% endfor %}
                    {% else %}
                        <div>{{ data }}</div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            timestamp=datetime.now(),
            results=results
        )
        file.write(html_content)