"""
Visualization Components for SecuNik Frontend
Professional security data visualizations using Plotly
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json

# Color scheme for consistency
COLORS = {
    'primary': '#1f77b4',
    'secondary': '#ff7f0e',
    'success': '#2ca02c',
    'danger': '#d62728',
    'warning': '#ff9800',
    'info': '#17a2b8',
    'dark': '#343a40',
    'light': '#f8f9fa',
    'critical': '#8b0000',
    'high': '#dc3545',
    'medium': '#ffc107',
    'low': '#28a745'
}

def render_threat_overview_chart(threat_data: List[Dict]):
    """Render threat overview donut chart"""
    if not threat_data:
        st.info("No threat data available")
        return
    
    # Aggregate threats by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for threat in threat_data:
        severity = threat.get('severity', 'LOW').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Create donut chart
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=.6,
        marker_colors=[COLORS['critical'], COLORS['high'], COLORS['medium'], COLORS['low']],
        textinfo='label+value',
        textposition='outside'
    )])
    
    fig.update_layout(
        title="Threat Severity Distribution",
        showlegend=True,
        height=400,
        annotations=[dict(
            text=f'{sum(severity_counts.values())}<br>Total Threats',
            x=0.5, y=0.5,
            font_size=20,
            showarrow=False
        )]
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_timeline_visualization(events: List[Dict]):
    """Render interactive timeline of security events"""
    if not events:
        st.info("No timeline data available")
        return
    
    # Prepare data
    timeline_data = []
    for event in events:
        timestamp = event.get('timestamp')
        if timestamp:
            try:
                # Parse timestamp
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                
                timeline_data.append({
                    'timestamp': dt,
                    'event': event.get('event', 'Unknown'),
                    'description': event.get('description', ''),
                    'severity': event.get('severity', 'LOW'),
                    'source': event.get('source', 'Unknown')
                })
            except:
                continue
    
    if not timeline_data:
        st.warning("No valid timeline data")
        return
    
    # Sort by timestamp
    timeline_data.sort(key=lambda x: x['timestamp'])
    
    # Create timeline figure
    fig = go.Figure()
    
    # Group events by severity
    severity_groups = {}
    for event in timeline_data:
        severity = event['severity']
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(event)
    
    # Add traces for each severity
    y_position = 0
    for severity, events in severity_groups.items():
        timestamps = [e['timestamp'] for e in events]
        descriptions = [f"{e['event']}: {e['description'][:50]}..." for e in events]
        
        color = COLORS.get(severity.lower(), COLORS['info'])
        
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=[y_position] * len(events),
            mode='markers+text',
            name=severity,
            marker=dict(
                size=12,
                color=color,
                symbol='circle'
            ),
            text=descriptions,
            textposition="top center",
            hovertemplate='<b>%{text}</b><br>Time: %{x}<extra></extra>'
        ))
        
        y_position += 1
    
    # Update layout
    fig.update_layout(
        title="Security Event Timeline",
        xaxis_title="Time",
        yaxis=dict(
            showticklabels=False,
            showgrid=False,
            zeroline=False
        ),
        height=400,
        hovermode='x unified',
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_ioc_distribution(iocs: List[Dict]):
    """Render IOC type distribution chart"""
    if not iocs:
        st.info("No IOCs found")
        return
    
    # Count IOCs by type
    ioc_types = {}
    for ioc in iocs:
        ioc_type = ioc.get('type', 'unknown')
        ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
    
    # Create horizontal bar chart
    fig = go.Figure(data=[
        go.Bar(
            y=list(ioc_types.keys()),
            x=list(ioc_types.values()),
            orientation='h',
            marker_color=COLORS['primary'],
            text=list(ioc_types.values()),
            textposition='outside'
        )
    ])
    
    fig.update_layout(
        title="Indicators of Compromise by Type",
        xaxis_title="Count",
        yaxis_title="IOC Type",
        height=400,
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_risk_gauge(risk_score: float):
    """Render risk score gauge chart"""
    # Determine color based on risk score
    if risk_score >= 0.8:
        color = COLORS['critical']
        risk_level = "CRITICAL"
    elif risk_score >= 0.6:
        color = COLORS['high']
        risk_level = "HIGH"
    elif risk_score >= 0.4:
        color = COLORS['medium']
        risk_level = "MEDIUM"
    else:
        color = COLORS['low']
        risk_level = "LOW"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=risk_score * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Overall Risk Score<br><span style='font-size:0.8em;color:gray'>{risk_level}</span>"},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 25], 'color': "lightgray"},
                {'range': [25, 50], 'color': "lightgray"},
                {'range': [50, 75], 'color': "lightgray"},
                {'range': [75, 100], 'color': "lightgray"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)


def render_file_analysis_summary(analysis_results: List[Dict]):
    """Render summary of file analysis results"""
    if not analysis_results:
        st.info("No analysis results available")
        return
    
    # Prepare data for visualization
    file_data = []
    for result in analysis_results:
        file_data.append({
            'filename': result.get('filename', 'Unknown')[:20] + '...',
            'risk_score': result.get('risk_score', 0),
            'threats': len(result.get('threats', [])),
            'iocs': len(result.get('iocs', [])),
            'status': result.get('status', 'unknown')
        })
    
    df = pd.DataFrame(file_data)
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Risk Scores by File', 'Threats per File', 'IOCs per File', 'Analysis Status'),
        specs=[[{'type': 'bar'}, {'type': 'bar'}],
               [{'type': 'bar'}, {'type': 'pie'}]]
    )
    
    # Risk scores
    fig.add_trace(
        go.Bar(x=df['filename'], y=df['risk_score'], name='Risk Score', marker_color=COLORS['danger']),
        row=1, col=1
    )
    
    # Threats count
    fig.add_trace(
        go.Bar(x=df['filename'], y=df['threats'], name='Threats', marker_color=COLORS['warning']),
        row=1, col=2
    )
    
    # IOCs count
    fig.add_trace(
        go.Bar(x=df['filename'], y=df['iocs'], name='IOCs', marker_color=COLORS['info']),
        row=2, col=1
    )
    
    # Status distribution
    status_counts = df['status'].value_counts()
    fig.add_trace(
        go.Pie(labels=status_counts.index, values=status_counts.values, name='Status'),
        row=2, col=2
    )
    
    fig.update_layout(height=800, showlegend=False)
    st.plotly_chart(fig, use_container_width=True)


def render_network_graph(connections: List[Dict]):
    """Render network connections graph"""
    if not connections:
        st.info("No network data available")
        return
    
    # Create nodes and edges
    nodes = set()
    edges = []
    
    for conn in connections:
        src = conn.get('src_ip', '')
        dst = conn.get('dst_ip', '')
        if src and dst:
            nodes.add(src)
            nodes.add(dst)
            edges.append((src, dst))
    
    if not nodes:
        st.warning("No valid network connections")
        return
    
    # Create network graph using plotly
    import networkx as nx
    
    G = nx.Graph()
    G.add_nodes_from(nodes)
    G.add_edges_from(edges)
    
    pos = nx.spring_layout(G)
    
    # Create edge trace
    edge_trace = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_trace.append(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode='lines',
            line=dict(width=0.5, color='#888'),
            hoverinfo='none'
        ))
    
    # Create node trace
    node_trace = go.Scatter(
        x=[pos[node][0] for node in G.nodes()],
        y=[pos[node][1] for node in G.nodes()],
        mode='markers+text',
        text=[node for node in G.nodes()],
        textposition="top center",
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            color=[G.degree(node) for node in G.nodes()],
            colorbar=dict(
                thickness=15,
                title='Connections',
                xanchor='left',
                titleside='right'
            )
        )
    )
    
    # Create figure
    fig = go.Figure(data=edge_trace + [node_trace])
    
    fig.update_layout(
        title='Network Connection Graph',
        showlegend=False,
        hovermode='closest',
        height=600,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_heatmap(data: Dict[str, List[float]], title: str = "Activity Heatmap"):
    """Render a heatmap visualization"""
    if not data:
        st.info("No data available for heatmap")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=df.values,
        x=df.columns,
        y=df.index,
        colorscale='RdYlBu_r',
        showscale=True
    ))
    
    fig.update_layout(
        title=title,
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_metrics_dashboard(metrics: Dict[str, Any]):
    """Render a metrics dashboard with KPIs"""
    st.markdown("### 📊 Security Metrics Dashboard")
    
    # Create columns for metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Files Analyzed",
            value=metrics.get('total_files', 0),
            delta=metrics.get('files_delta', 0),
            delta_color="normal"
        )
    
    with col2:
        threats = metrics.get('total_threats', 0)
        st.metric(
            label="Threats Detected",
            value=threats,
            delta=metrics.get('threats_delta', 0),
            delta_color="inverse"
        )
    
    with col3:
        iocs = metrics.get('total_iocs', 0)
        st.metric(
            label="IOCs Extracted",
            value=iocs,
            delta=metrics.get('iocs_delta', 0),
            delta_color="inverse"
        )
    
    with col4:
        risk = metrics.get('avg_risk_score', 0)
        st.metric(
            label="Avg Risk Score",
            value=f"{risk:.1%}",
            delta=f"{metrics.get('risk_delta', 0):.1%}",
            delta_color="inverse"
        )
    
    # Trend charts
    if metrics.get('trends'):
        st.markdown("### 📈 Trends")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Threat trend
            if 'threat_trend' in metrics['trends']:
                fig = px.line(
                    metrics['trends']['threat_trend'],
                    x='date',
                    y='count',
                    title='Threat Detection Trend',
                    markers=True
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk trend
            if 'risk_trend' in metrics['trends']:
                fig = px.area(
                    metrics['trends']['risk_trend'],
                    x='date',
                    y='risk',
                    title='Risk Score Trend',
                    color_discrete_sequence=[COLORS['warning']]
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)


def render_advanced_analysis_view(analysis_data: Dict):
    """Render advanced analysis visualizations"""
    st.markdown("### 🔬 Advanced Analysis")
    
    tabs = st.tabs(["🕸️ Attack Graph", "🔄 Correlation Matrix", "📊 Statistical Analysis", "🎯 Threat Intel"])
    
    with tabs[0]:
        # Attack graph visualization
        if 'attack_chain' in analysis_data:
            render_attack_chain(analysis_data['attack_chain'])
        else:
            st.info("No attack chain data available")
    
    with tabs[1]:
        # Correlation matrix
        if 'correlations' in analysis_data:
            render_correlation_matrix(analysis_data['correlations'])
        else:
            st.info("No correlation data available")
    
    with tabs[2]:
        # Statistical analysis
        if 'statistics' in analysis_data:
            render_statistical_analysis(analysis_data['statistics'])
        else:
            st.info("No statistical data available")
    
    with tabs[3]:
        # Threat intelligence
        if 'threat_intel' in analysis_data:
            render_threat_intelligence(analysis_data['threat_intel'])
        else:
            st.info("No threat intelligence data available")


def render_attack_chain(attack_chain: List[Dict]):
    """Render attack chain visualization"""
    if not attack_chain:
        st.info("No attack chain detected")
        return
    
    # Create Sankey diagram for attack flow
    labels = []
    sources = []
    targets = []
    values = []
    
    for i, step in enumerate(attack_chain):
        if i < len(attack_chain) - 1:
            labels.extend([step['stage'], attack_chain[i+1]['stage']])
            sources.append(len(labels) - 2)
            targets.append(len(labels) - 1)
            values.append(step.get('confidence', 1))
    
    # Remove duplicates from labels
    unique_labels = list(dict.fromkeys(labels))
    
    # Update indices
    label_indices = {label: i for i, label in enumerate(unique_labels)}
    sources = [label_indices[labels[s]] for s in sources]
    targets = [label_indices[labels[t]] for t in targets]
    
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=unique_labels,
            color=[COLORS['danger'] if 'compromise' in l.lower() else COLORS['warning'] for l in unique_labels]
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values
        )
    )])
    
    fig.update_layout(
        title="Attack Chain Flow",
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_correlation_matrix(correlations: Dict):
    """Render correlation matrix heatmap"""
    # Convert to correlation matrix format
    items = list(correlations.keys())
    matrix = []
    
    for item1 in items:
        row = []
        for item2 in items:
            if item1 == item2:
                row.append(1.0)
            else:
                # Get correlation value
                corr = correlations.get(item1, {}).get(item2, 0)
                row.append(corr)
        matrix.append(row)
    
    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=items,
        y=items,
        colorscale='RdBu',
        zmid=0,
        text=[[f'{val:.2f}' for val in row] for row in matrix],
        texttemplate='%{text}',
        textfont={"size": 10}
    ))
    
    fig.update_layout(
        title="Event Correlation Matrix",
        height=600
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_statistical_analysis(stats: Dict):
    """Render statistical analysis charts"""
    col1, col2 = st.columns(2)
    
    with col1:
        # Distribution chart
        if 'distribution' in stats:
            fig = go.Figure(data=[
                go.Histogram(
                    x=stats['distribution'],
                    nbinsx=30,
                    marker_color=COLORS['primary']
                )
            ])
            fig.update_layout(
                title="Event Distribution",
                xaxis_title="Value",
                yaxis_title="Frequency",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Box plot for outliers
        if 'categories' in stats:
            fig = go.Figure()
            for category, values in stats['categories'].items():
                fig.add_trace(go.Box(
                    y=values,
                    name=category,
                    boxpoints='outliers'
                ))
            
            fig.update_layout(
                title="Category Analysis with Outliers",
                yaxis_title="Value",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)


def render_threat_intelligence(threat_intel: Dict):
    """Render threat intelligence visualization"""
    # Threat actor information
    if 'threat_actors' in threat_intel:
        st.markdown("#### 🎭 Threat Actors")
        
        actors_df = pd.DataFrame(threat_intel['threat_actors'])
        
        fig = px.treemap(
            actors_df,
            path=['group', 'technique'],
            values='count',
            title='Threat Actor Techniques'
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    # MITRE ATT&CK mapping
    if 'mitre_attack' in threat_intel:
        st.markdown("#### 🗺️ MITRE ATT&CK Mapping")
        
        tactics = threat_intel['mitre_attack']
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(tactics.keys()),
                y=list(tactics.values()),
                marker_color=COLORS['danger']
            )
        ])
        
        fig.update_layout(
            title="MITRE ATT&CK Tactics Coverage",
            xaxis_title="Tactic",
            yaxis_title="Technique Count",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)


# Export all visualization functions
__all__ = [
    'render_threat_overview_chart',
    'render_timeline_visualization',
    'render_ioc_distribution',
    'render_risk_gauge',
    'render_file_analysis_summary',
    'render_network_graph',
    'render_heatmap',
    'render_metrics_dashboard',
    'render_advanced_analysis_view',
    'COLORS'
]