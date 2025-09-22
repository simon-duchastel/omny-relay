#!/usr/bin/env python3
"""
Data visualization tools for NFC transit card analysis.
Creates charts, graphs, and visual reports from captured data.
"""

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import base64
from io import BytesIO

logger = logging.getLogger(__name__)

# Set style for better-looking plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")


class NFCDataVisualizer:
    """Creates visualizations for NFC data analysis."""
    
    def __init__(self, output_dir: str = "visualizations"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Configure matplotlib for better output
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['figure.dpi'] = 100
        plt.rcParams['savefig.dpi'] = 300
        plt.rcParams['savefig.bbox'] = 'tight'
        
    def create_session_overview(self, session_data: Dict) -> str:
        """Create overview visualization of a session."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f"Session Overview: {session_data.get('session_id', 'Unknown')}", fontsize=16)
        
        # 1. Packet count over time
        if 'packet_analysis' in session_data:
            timestamps = [p['timestamp'] for p in session_data['packet_analysis']]
            timestamps_dt = [datetime.fromtimestamp(ts) for ts in timestamps]
            
            ax1.hist(timestamps_dt, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            ax1.set_title('Packet Distribution Over Time')
            ax1.set_xlabel('Time')
            ax1.set_ylabel('Packet Count')
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
            
        # 2. Protocol distribution
        protocols = {}
        if 'packet_analysis' in session_data:
            for packet in session_data['packet_analysis']:
                protocol = packet.get('protocol', 'Unknown')
                protocols[protocol] = protocols.get(protocol, 0) + 1
                
        if protocols:
            ax2.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
            ax2.set_title('Protocol Distribution')
        
        # 3. Packet size distribution
        if 'packet_analysis' in session_data:
            sizes = [p['length'] for p in session_data['packet_analysis']]
            ax3.hist(sizes, bins=15, alpha=0.7, color='lightgreen', edgecolor='black')
            ax3.set_title('Packet Size Distribution')
            ax3.set_xlabel('Packet Size (bytes)')
            ax3.set_ylabel('Frequency')
        
        # 4. Transit insights summary
        insights = session_data.get('transit_insights', {})
        if insights:
            insight_text = []
            if 'possible_card_ids' in insights:
                insight_text.append(f"Card IDs: {len(insights['possible_card_ids'])}")
            if 'possible_balances' in insights:
                insight_text.append(f"Balances: {len(insights['possible_balances'])}")
            if 'timestamps' in insights:
                insight_text.append(f"Timestamps: {len(insights['timestamps'])}")
                
            ax4.text(0.1, 0.5, '\n'.join(insight_text), fontsize=12, 
                    verticalalignment='center', transform=ax4.transAxes)
            ax4.set_title('Transit Insights Summary')
            ax4.axis('off')
        
        plt.tight_layout()
        
        # Save plot
        filename = self.output_dir / f"session_overview_{session_data.get('session_id', 'unknown')}.png"
        plt.savefig(filename)
        plt.close()
        
        logger.info(f"Session overview saved: {filename}")
        return str(filename)
        
    def create_balance_analysis(self, sessions_data: List[Dict]) -> str:
        """Create balance analysis across multiple sessions."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        fig.suptitle('Transit Card Balance Analysis', fontsize=16)
        
        all_balances = []
        balance_changes = []
        
        for session in sessions_data:
            insights = session.get('transit_insights', {})
            if 'possible_balances' in insights:
                all_balances.extend(insights['possible_balances'])
            if 'balance_changes' in insights:
                for change in insights['balance_changes']:
                    balance_changes.append(change['change'])
        
        # Balance distribution
        if all_balances:
            ax1.hist(all_balances, bins=20, alpha=0.7, color='gold', edgecolor='black')
            ax1.set_title('Balance Distribution')
            ax1.set_xlabel('Balance ($)')
            ax1.set_ylabel('Frequency')
            ax1.axvline(np.mean(all_balances), color='red', linestyle='--', 
                       label=f'Mean: ${np.mean(all_balances):.2f}')
            ax1.legend()
        
        # Balance changes
        if balance_changes:
            ax2.hist(balance_changes, bins=15, alpha=0.7, color='coral', edgecolor='black')
            ax2.set_title('Transaction Amount Distribution')
            ax2.set_xlabel('Amount Change ($)')
            ax2.set_ylabel('Frequency')
            ax2.axvline(0, color='black', linestyle='-', alpha=0.5)
        
        plt.tight_layout()
        
        filename = self.output_dir / "balance_analysis.png"
        plt.savefig(filename)
        plt.close()
        
        logger.info(f"Balance analysis saved: {filename}")
        return str(filename)
        
    def create_protocol_timeline(self, session_data: Dict) -> str:
        """Create timeline of protocol communications."""
        if 'packet_analysis' not in session_data:
            return None
            
        # Prepare data
        packets = session_data['packet_analysis']
        df = pd.DataFrame([
            {
                'timestamp': datetime.fromtimestamp(p['timestamp']),
                'protocol': p.get('protocol', 'Unknown'),
                'direction': p.get('direction', 'Unknown'),
                'length': p['length']
            }
            for p in packets
        ])
        
        if df.empty:
            return None
        
        # Create timeline plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 10), sharex=True)
        fig.suptitle(f"Protocol Timeline: {session_data.get('session_id', 'Unknown')}", fontsize=16)
        
        # Protocol timeline
        protocols = df['protocol'].unique()
        colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
        
        for i, protocol in enumerate(protocols):
            protocol_data = df[df['protocol'] == protocol]
            ax1.scatter(protocol_data['timestamp'], [i] * len(protocol_data),
                       c=[colors[i]], label=protocol, alpha=0.7, s=50)
        
        ax1.set_ylabel('Protocol')
        ax1.set_yticks(range(len(protocols)))
        ax1.set_yticklabels(protocols)
        ax1.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        ax1.set_title('Protocol Communication Timeline')
        ax1.grid(True, alpha=0.3)
        
        # Packet size over time
        ax2.plot(df['timestamp'], df['length'], marker='o', linestyle='-', 
                alpha=0.7, markersize=4)
        ax2.set_ylabel('Packet Size (bytes)')
        ax2.set_xlabel('Time')
        ax2.set_title('Packet Size Over Time')
        ax2.grid(True, alpha=0.3)
        
        # Format x-axis
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
        
        plt.tight_layout()
        
        filename = self.output_dir / f"protocol_timeline_{session_data.get('session_id', 'unknown')}.png"
        plt.savefig(filename)
        plt.close()
        
        logger.info(f"Protocol timeline saved: {filename}")
        return str(filename)
        
    def create_security_dashboard(self, sessions_data: List[Dict]) -> str:
        """Create security analysis dashboard."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Security Analysis Dashboard', fontsize=16)
        
        # Collect security data
        security_issues = []
        protocols_by_session = []
        unencrypted_sessions = 0
        total_sessions = len(sessions_data)
        
        for session in sessions_data:
            security_notes = session.get('security_notes', [])
            security_issues.extend(security_notes)
            
            protocols = session.get('protocols_detected', [])
            protocols_by_session.append(len(protocols))
            
            # Check for encryption indicators
            if any('unencrypted' in note.lower() for note in security_notes):
                unencrypted_sessions += 1
        
        # 1. Security issues frequency
        if security_issues:
            issue_types = {}
            for issue in security_issues:
                # Categorize issues
                if 'unencrypted' in issue.lower():
                    category = 'Unencrypted Data'
                elif 'authentication' in issue.lower():
                    category = 'Authentication'
                elif 'replay' in issue.lower():
                    category = 'Replay Attack'
                else:
                    category = 'Other'
                    
                issue_types[category] = issue_types.get(category, 0) + 1
            
            ax1.bar(issue_types.keys(), issue_types.values(), color='red', alpha=0.7)
            ax1.set_title('Security Issues by Type')
            ax1.set_ylabel('Count')
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
        
        # 2. Encryption status
        encrypted_sessions = total_sessions - unencrypted_sessions
        if total_sessions > 0:
            ax2.pie([encrypted_sessions, unencrypted_sessions], 
                   labels=['Encrypted', 'Unencrypted'],
                   colors=['green', 'red'],
                   autopct='%1.1f%%')
            ax2.set_title('Session Encryption Status')
        
        # 3. Protocol diversity per session
        if protocols_by_session:
            ax3.hist(protocols_by_session, bins=max(protocols_by_session) + 1, 
                    alpha=0.7, color='blue', edgecolor='black')
            ax3.set_title('Protocol Diversity per Session')
            ax3.set_xlabel('Number of Protocols')
            ax3.set_ylabel('Session Count')
        
        # 4. Security score
        if total_sessions > 0:
            # Calculate simple security score
            encryption_score = (encrypted_sessions / total_sessions) * 40
            issue_score = max(0, 30 - len(security_issues))
            protocol_score = min(30, np.mean(protocols_by_session) * 10) if protocols_by_session else 0
            
            total_score = encryption_score + issue_score + protocol_score
            
            # Create gauge-like visualization
            theta = np.linspace(0, 2 * np.pi, 100)
            r = np.ones_like(theta)
            
            # Color based on score
            if total_score >= 80:
                color = 'green'
            elif total_score >= 60:
                color = 'orange'
            else:
                color = 'red'
            
            ax4.fill_between(theta, 0, r, alpha=0.3, color=color)
            ax4.text(0, 0, f'{total_score:.1f}', ha='center', va='center', 
                    fontsize=24, fontweight='bold')
            ax4.set_title('Security Score (0-100)')
            ax4.set_xlim(-1.5, 1.5)
            ax4.set_ylim(-1.5, 1.5)
            ax4.axis('off')
        
        plt.tight_layout()
        
        filename = self.output_dir / "security_dashboard.png"
        plt.savefig(filename)
        plt.close()
        
        logger.info(f"Security dashboard saved: {filename}")
        return str(filename)


class InteractiveVisualizer:
    """Creates interactive visualizations using Plotly."""
    
    def __init__(self, output_dir: str = "interactive_viz"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def create_interactive_timeline(self, session_data: Dict) -> str:
        """Create interactive timeline with Plotly."""
        if 'packet_analysis' not in session_data:
            return None
            
        packets = session_data['packet_analysis']
        
        # Prepare data
        timestamps = [datetime.fromtimestamp(p['timestamp']) for p in packets]
        protocols = [p.get('protocol', 'Unknown') for p in packets]
        lengths = [p['length'] for p in packets]
        directions = [p.get('direction', 'Unknown') for p in packets]
        
        # Create subplot figure
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=['Protocol Timeline', 'Packet Size Over Time'],
            vertical_spacing=0.1
        )
        
        # Protocol timeline (scatter plot)
        unique_protocols = list(set(protocols))
        colors = px.colors.qualitative.Set3[:len(unique_protocols)]
        
        for i, protocol in enumerate(unique_protocols):
            protocol_indices = [j for j, p in enumerate(protocols) if p == protocol]
            protocol_timestamps = [timestamps[j] for j in protocol_indices]
            protocol_lengths = [lengths[j] for j in protocol_indices]
            protocol_directions = [directions[j] for j in protocol_indices]
            
            fig.add_trace(
                go.Scatter(
                    x=protocol_timestamps,
                    y=[i] * len(protocol_timestamps),
                    mode='markers',
                    name=protocol,
                    marker=dict(color=colors[i % len(colors)], size=8),
                    hovertemplate=f'<b>{protocol}</b><br>' +
                                'Time: %{x}<br>' +
                                'Direction: %{customdata[0]}<br>' +
                                'Size: %{customdata[1]} bytes<extra></extra>',
                    customdata=list(zip(protocol_directions, protocol_lengths))
                ),
                row=1, col=1
            )
        
        # Packet size timeline
        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=lengths,
                mode='lines+markers',
                name='Packet Size',
                line=dict(color='blue'),
                marker=dict(size=4),
                hovertemplate='Time: %{x}<br>Size: %{y} bytes<br>Protocol: %{customdata}<extra></extra>',
                customdata=protocols
            ),
            row=2, col=1
        )
        
        # Update layout
        fig.update_layout(
            title=f"Interactive Analysis: {session_data.get('session_id', 'Unknown')}",
            height=800,
            showlegend=True
        )
        
        fig.update_yaxes(title_text="Protocol", row=1, col=1)
        fig.update_yaxes(title_text="Packet Size (bytes)", row=2, col=1)
        fig.update_xaxes(title_text="Time", row=2, col=1)
        
        # Save as HTML
        filename = self.output_dir / f"interactive_timeline_{session_data.get('session_id', 'unknown')}.html"
        fig.write_html(str(filename))
        
        logger.info(f"Interactive timeline saved: {filename}")
        return str(filename)
        
    def create_balance_flow(self, sessions_data: List[Dict]) -> str:
        """Create interactive balance flow visualization."""
        # Collect balance change data
        balance_data = []
        
        for session in sessions_data:
            session_id = session.get('session_id', 'Unknown')
            insights = session.get('transit_insights', {})
            
            if 'balance_changes' in insights:
                for i, change in enumerate(insights['balance_changes']):
                    balance_data.append({
                        'session': session_id,
                        'transaction': i,
                        'from_balance': change['from_balance'],
                        'to_balance': change['to_balance'],
                        'change': change['change'],
                        'type': change['type']
                    })
        
        if not balance_data:
            return None
            
        df = pd.DataFrame(balance_data)
        
        # Create sankey diagram for balance flows
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=["Initial Balance", "Final Balance"],
                color="blue"
            ),
            link=dict(
                source=[0] * len(df),  # All from initial
                target=[1] * len(df),  # All to final
                value=df['change'].abs().tolist(),
                color=["red" if x < 0 else "green" for x in df['change']]
            )
        )])
        
        fig.update_layout(
            title_text="Balance Flow Analysis",
            font_size=10
        )
        
        filename = self.output_dir / "balance_flow.html"
        fig.write_html(str(filename))
        
        logger.info(f"Balance flow visualization saved: {filename}")
        return str(filename)


class ReportGenerator:
    """Generates comprehensive HTML reports with embedded visualizations."""
    
    def __init__(self, visualizer: NFCDataVisualizer, interactive_viz: InteractiveVisualizer):
        self.visualizer = visualizer
        self.interactive_viz = interactive_viz
        
    def generate_html_report(self, sessions_data: List[Dict], output_file: str = None) -> str:
        """Generate comprehensive HTML report."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"nfc_analysis_report_{timestamp}.html"
            
        # Generate visualizations
        overview_plots = []
        timeline_plots = []
        
        for session in sessions_data[:5]:  # Limit to first 5 sessions for performance
            overview_plot = self.visualizer.create_session_overview(session)
            timeline_plot = self.visualizer.create_protocol_timeline(session)
            interactive_timeline = self.interactive_viz.create_interactive_timeline(session)
            
            if overview_plot:
                overview_plots.append(overview_plot)
            if timeline_plot:
                timeline_plots.append(timeline_plot)
        
        balance_plot = self.visualizer.create_balance_analysis(sessions_data)
        security_plot = self.visualizer.create_security_dashboard(sessions_data)
        
        # Convert images to base64 for embedding
        def image_to_base64(image_path):
            with open(image_path, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode()
        
        # Generate HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NFC Transit Card Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #2c3e50; text-align: center; }}
                h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 10px; margin: 20px 0; }}
                .chart {{ text-align: center; margin: 30px 0; }}
                .chart img {{ max-width: 100%; height: auto; border: 1px solid #bdc3c7; border-radius: 5px; }}
                .section {{ margin: 40px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #bdc3c7; padding: 12px; text-align: left; }}
                th {{ background-color: #3498db; color: white; }}
                .alert {{ background-color: #e74c3c; color: white; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .info {{ background-color: #3498db; color: white; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <h1>NFC Transit Card Analysis Report</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Sessions Analyzed:</strong> {len(sessions_data)}</p>
                <p><strong>Total Cards Detected:</strong> {sum(len(s.get('cards_detected', [])) for s in sessions_data)}</p>
                <p><strong>Total Transactions:</strong> {sum(len(s.get('transactions', [])) for s in sessions_data)}</p>
                <p><strong>Security Issues:</strong> {sum(len(s.get('security_notes', [])) for s in sessions_data)}</p>
            </div>
        """
        
        # Add security dashboard
        if security_plot and Path(security_plot).exists():
            html_content += f"""
            <div class="section">
                <h2>Security Analysis</h2>
                <div class="chart">
                    <img src="data:image/png;base64,{image_to_base64(security_plot)}" alt="Security Dashboard">
                </div>
            </div>
            """
        
        # Add balance analysis
        if balance_plot and Path(balance_plot).exists():
            html_content += f"""
            <div class="section">
                <h2>Balance Analysis</h2>
                <div class="chart">
                    <img src="data:image/png;base64,{image_to_base64(balance_plot)}" alt="Balance Analysis">
                </div>
            </div>
            """
        
        # Add session overviews
        if overview_plots:
            html_content += """
            <div class="section">
                <h2>Session Overviews</h2>
            """
            for plot in overview_plots:
                if Path(plot).exists():
                    html_content += f"""
                    <div class="chart">
                        <img src="data:image/png;base64,{image_to_base64(plot)}" alt="Session Overview">
                    </div>
                    """
            html_content += "</div>"
        
        # Add detailed session data
        html_content += """
        <div class="section">
            <h2>Detailed Session Data</h2>
            <table>
                <tr>
                    <th>Session ID</th>
                    <th>Duration</th>
                    <th>Packets</th>
                    <th>Cards</th>
                    <th>Protocols</th>
                    <th>Security Issues</th>
                </tr>
        """
        
        for session in sessions_data:
            session_id = session.get('session_id', 'Unknown')
            duration = session.get('session_duration', 0)
            packets = session.get('total_packets', 0)
            cards = len(session.get('cards_detected', []))
            protocols = ', '.join(session.get('protocols_detected', []))
            security_issues = len(session.get('security_notes', []))
            
            html_content += f"""
                <tr>
                    <td>{session_id}</td>
                    <td>{duration:.1f}s</td>
                    <td>{packets}</td>
                    <td>{cards}</td>
                    <td>{protocols}</td>
                    <td>{security_issues}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </div>
        </body>
        </html>
        """
        
        # Write report
        report_path = Path(output_file)
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)


# CLI interface
def main():
    """CLI interface for visualization tools."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="NFC Data Visualization Tools")
    parser.add_argument("--session-file", help="JSON file with session data")
    parser.add_argument("--sessions-dir", help="Directory with multiple session files")
    parser.add_argument("--output-dir", default="visualizations", help="Output directory")
    parser.add_argument("--interactive", action="store_true", help="Generate interactive visualizations")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    
    args = parser.parse_args()
    
    visualizer = NFCDataVisualizer(args.output_dir)
    interactive_viz = InteractiveVisualizer(args.output_dir)
    
    sessions_data = []
    
    # Load session data
    if args.session_file:
        with open(args.session_file, 'r') as f:
            sessions_data.append(json.load(f))
    elif args.sessions_dir:
        sessions_dir = Path(args.sessions_dir)
        for session_file in sessions_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    sessions_data.append(json.load(f))
            except Exception as e:
                logger.error(f"Failed to load {session_file}: {e}")
    
    if not sessions_data:
        print("No session data found. Use --session-file or --sessions-dir")
        return
    
    print(f"Loaded {len(sessions_data)} sessions")
    
    # Generate visualizations
    for session in sessions_data:
        visualizer.create_session_overview(session)
        visualizer.create_protocol_timeline(session)
        
        if args.interactive:
            interactive_viz.create_interactive_timeline(session)
    
    # Generate aggregate analyses
    visualizer.create_balance_analysis(sessions_data)
    visualizer.create_security_dashboard(sessions_data)
    
    if args.interactive:
        interactive_viz.create_balance_flow(sessions_data)
    
    # Generate report
    if args.report:
        report_gen = ReportGenerator(visualizer, interactive_viz)
        report_file = report_gen.generate_html_report(sessions_data)
        print(f"Report generated: {report_file}")
    
    print(f"Visualizations saved to: {args.output_dir}")


if __name__ == "__main__":
    main()