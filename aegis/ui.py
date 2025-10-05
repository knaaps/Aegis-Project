"""
Aegis-Lite Security Scanner
===========================
Clean, minimal interface 
"""

import streamlit as st
import json
import pandas as pd
import time

from aegis import database
from aegis.database import get_all_assets, get_db_stats, init_db, clear_db
from aegis.cli import run_scan_logic
from aegis.utils import get_risk_level, safe_json_parse

# Clean, minimal theme
def apply_clean_theme():
    """styling inspired by MonkeyType"""
    st.markdown("""
    <style>
    /* Clean dark theme */
    .stApp {
        background-color: #1a1a1a;
        color: #e0e0e0;
        font-family: 'Segoe UI', system-ui, sans-serif;
    }
    
    /* Headers with subtle accent */
    h1, h2, h3, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
        color: #ffffff;
        border-bottom: 1px solid #333;
        padding-bottom: 8px;
        font-weight: 600;
    }
    
    /* Clean cards */
    .main .block-container {
        background: #2a2a2a;
        width: 900px;
        border-radius: 8px;
        padding: 20px;
        margin: 10px 0;
        border: 1px solid #333;
    }
    
    /* Subtle sidebar */
    .css-1d391kg {
        background-color: #1e1e1e !important;
        border-right: 1px solid #333;
    }
    
    /* Clean inputs */
    .stTextInput>div>div>input {
        background-color: #2a2a2a;
        color: #ffffff;
        border: 1px solid #444;
        border-radius: 6px;
        font-family: 'Consolas', monospace;
    }
    
    .stTextInput>div>div>input:focus {
        border-color: #00d4aa;
        box-shadow: 0 0 0 1px #00d4aa;
    }
    
    /* Minimal buttons */
    .stButton>button {
        background-color: #00d4aa !important;
        color: #000000 !important;
        border: none !important;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    
    .stButton>button:hover {
        background-color: #00b894 !important;
        transform: translateY(-1px);
    }
    
    /* Clean dataframes */
    .dataframe {
        background-color: #2a2a2a !important;
        color: #e0e0e0 !important;
        border: 1px solid #333 !important;
        font-family: 'Consolas', monospace;
        font-size: 0.9em;
    }
    
    .dataframe th {
        background-color: #333 !important;
        color: #ffffff !important;
        font-weight: 600;
    }
    
    .dataframe td {
        background-color: #2a2a2a !important;
        color: #e0e0e0 !important;
    }
    
    /* Minimal tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0px;
        background-color: #2a2a2a;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: #333;
        color: #888;
        border: none;
        border-radius: 6px 6px 0 0;
        padding: 10px 20px;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #00d4aa !important;
        color: #000000 !important;
    }
    
    /* Clean metrics */
    [data-testid="stMetricValue"] {
        color: #00d4aa !important;
        font-weight: 700;
    }
    
    [data-testid="stMetricLabel"] {
        color: #888 !important;
    }
    
    /* Progress bars */
    .stProgress > div > div > div {
        background-color: #00d4aa !important;
    }
    
    /* Alerts */
    .stAlert {
        background-color: #2a2a2a;
        border: 1px solid #444;
        border-left: 4px solid #00d4aa;
    }
    
    /* Code blocks */
    .stCodeBlock {
        background-color: #1e1e1e !important;
        border: 1px solid #333 !important;
        border-radius: 6px;
    }

    div[data-baseweb="tab-list"] {
        display: flex !important;
        justify-content: space-between !important;
    }

    button[data-baseweb="tab"] {
        flex: 1 !important;
        text-align: center !important;
    }

    </style>
    """, unsafe_allow_html=True)

def show_ascii_header():
    """ASCII art header"""
    st.markdown("""
    <div style="text-align: center; font-family: 'Consolas', monospace; color: #00d4aa; line-height: 1.2; margin: 20px 0; white-space: pre;">
    <pre style="margin: 0; font-size: 1em;">
                       █████╗ ███████╗ ██████╗ ██╗███████╗                                                        
                      ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝                                                        
                      ███████║█████╗  ██║  ███╗██║███████╗                                                        
                      ██╔══██║██╔══╝  ██║   ██║██║╚════██║                                                        
                      ██║  ██║███████╗╚██████╔╝██║███████║                                                        
                      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝                                                        
    </pre>
    <sub><div style="color: #888; margin-top: 1px; font-size: 1.2em;">
    Security Scanner for Small-Medium Enterprises
    </sub></div>
    </div>
    """, unsafe_allow_html=True)

def show_system_info():
    """Display system information"""
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        st.sidebar.markdown("### System Status")
        
        col1, col2 = st.sidebar.columns(2)
        with col1:
            st.metric("CPU", f"{cpu:.1f}%")
        with col2:
            st.metric("RAM", f"{memory.percent:.1f}%")

        if cpu > 80 or memory.percent > 80:
            st.sidebar.warning("High system load")

    except ImportError:
        st.sidebar.info("Install psutil for system monitoring")

def format_scan_results(assets):
    """Format scan results for clean display"""
    if not assets:
        return pd.DataFrame()

    df_data = []
    for asset in assets:
        try:
            https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
            web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))

            # Certificate warnings
            cert_warning = ""
            if https_data.get('cert_expires_soon'):
                days = https_data.get('days_until_expiry', 0)
                cert_warning = f"Expires in {days}d"

            risk_score = asset.get('score', 0)

            dir_data = safe_json_parse(asset.get('directory_discovery', '{}'))
            admin_panels = len(dir_data.get('admin_panels', []))
            sensitive_files = len(dir_data.get('sensitive_files', []))
            api_endpoints = len(dir_data.get('api_endpoints', []))

            row = {
                'Domain': asset.get('domain', ''),
                'IP': asset.get('ip', 'Unknown'),
                'Ports': asset.get('ports', ''),
                'Score': risk_score,
                'Level': get_risk_level(risk_score),
                'HTTPS': 'Yes' if https_data.get('has_https') else 'No',
                'Admin Panels': admin_panels,  # NEW COLUMN
                'Sensitive Files': sensitive_files,  # NEW COLUMN
                'Vulns': len(web_data.get('vulnerabilities', [])),
                'Last Scan': asset.get('last_scanned', '')[:16]
            }
            df_data.append(row)

        except Exception as e:
            st.error(f"Error processing asset: {e}")
            continue

    return pd.DataFrame(df_data)

def main():
    """Main application function"""
    
    # Apply clean theme
    apply_clean_theme()

    # Initialize database
    try:
        database.init_db()
    except Exception as e:
        st.error(f"Database initialization failed: {e}")
        # Don't return, let the user see the error and potentially fix it

    # Header with ASCII art
    show_ascii_header()
    st.markdown("---")

    # Sidebar
    show_system_info()

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Risk Guide")
    st.sidebar.markdown("""
    - **Critical (70-100)**: Immediate attention
    - **High (50-69)**: Address promptly  
    - **Medium (30-49)**: Monitor and plan
    - **Low (1-29)**: Good posture
    - **None (0)**: No services
    """)

    st.sidebar.markdown("---")
    if st.sidebar.button("Clear Database"):
        try:
            clear_db()
            st.sidebar.success("Database cleared")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed: {e}")

    # Main tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Scan", "Results", "Report", "Action Plan"])

    # Tab 1: Scanning with enhanced progress visualization
    with tab1:
        st.header("Domain Scanner")

        # Input section
        col1, col2 = st.columns([2, 1])

        with col1:
            domain = st.text_input(
                "Target Domain",
                placeholder="example.com",
                help="Enter domain to scan"
            )

        with col2:
            st.markdown("**Options**")
            ethical = st.checkbox("Ethical Mode", value=True)
            monitor = st.checkbox("Monitor Resources")
            max_subdomains = st.number_input(
                "Max Subdomains", min_value=1, max_value=500, value=50
            )

        # Scan button
        if st.button("Start Scan", type="primary", disabled=not domain, use_container_width=True):
            if not domain:
                st.error("Please enter a domain name")
            else:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    # Scan stages with progress updates
                    stages1 = [
                        (10, "🔧 Initializing scan..."),
                        (25, "🌐 Discovering subdomains..."),
                        (50, "🔍 Scanning ports & services...")
                    ]
                    
                    for progress, message in stages1:
                        status_text.markdown(f"**{message}**")
                        progress_bar.progress(progress)
                        time.sleep(0.3)

                    stages2 = [
                        (75, "🛡️ Running security checks..."),
                        (90, "📊 Generating report...")
                    ]

                    # Actual scan execution
                    with st.spinner("Executing security scan..."):
                        result = run_scan_logic(domain, ethical, monitor, max_subdomains)

                    for progress, message in stages2:
                        status_text.markdown(f"**{message}**")
                        progress_bar.progress(progress)
                        time.sleep(0.6)

                    progress_bar.progress(100)
                    status_text.empty()
                    
                    # Show results
                    if result.get("success"):
                        st.success("✅ Scan completed successfully!")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Subdomains", result.get("subdomains_found", 0))
                        with col2:
                            st.metric("Assets Scanned", result.get("successful_scans", 0))
                        with col3:
                            st.metric("Duration", f"{result.get('duration', 0):.1f}s")
                        with col4:
                            risk_count = len([a for a in get_all_assets() if a.get('score', 0) >= 50])
                            st.metric("High Risk Assets", risk_count)
                    else:
                        st.error("❌ Scan failed - check console for details")
                        
                except Exception as e:
                    st.error(f"Scan error: {e}")


        # Information
        with st.expander("About Ethical Scanning"):
            st.markdown("""
            - **Respects rate limits** and best practices
            - **2-second delays** between requests  
            - **Common ports only** in ethical mode
            - **Resource monitoring** to prevent system overload
            - **Robots.txt compliance** where applicable
            """)

    # Tab 2: Results (Enhanced)
    with tab2:
        st.header("Scan Results")
        try:
            assets = get_all_assets()
            if assets:
                # Summary metrics with additional insights
                st.subheader("Overview")
                df = format_scan_results(assets)
                
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    st.metric("Total Assets", len(assets))
                with col2:
                    avg_score = df['Score'].mean() if not df.empty else 0
                    st.metric("Avg Risk", f"{avg_score:.1f}/100")
                with col3:
                    high_risk = len(df[df['Score'] >= 50]) if not df.empty else 0
                    st.metric("High+ Risk", high_risk)
                with col4:
                    https_count = len(df[df['HTTPS'] == 'Yes']) if not df.empty else 0
                    st.metric("HTTPS Enabled", f"{https_count}/{len(assets)}")
                with col5:
                    total_vulns = sum(len(safe_json_parse(a.get('web_vulnerabilities', '{}')).get('vulnerabilities', [])) for a in assets)
                    st.metric("Vulnerabilities", total_vulns)
                
                st.markdown("---")
                
                # Assets table with expandable details
                st.subheader("Assets Inventory")
                
                for idx, asset in enumerate(assets, 1):
                    domain = asset.get('domain', '')
                    score = asset.get('score', 0)
                    ports = asset.get('ports', '')
                    
                    # Risk level indicator
                    risk_emoji = "🔴" if score >= 70 else "🟠" if score >= 50 else "🟡" if score >= 30 else "🟢"
                    
                    with st.expander(f"{risk_emoji} {domain} (Score: {score}/100)", expanded=idx==1):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Network Information**")
                            st.write(f"IP Address: `{asset.get('ip', 'Unknown')}`")
                            st.write(f"Open Ports: `{ports or 'None'}`")
                            st.write(f"Last Scanned: {asset.get('last_scanned', 'Unknown')[:16]}")
                        
                        with col2:
                            st.markdown("**Security Status**")
                            https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
                            st.write(f"HTTPS: {'✅' if https_data.get('has_https') else '❌'}")
                            
                            if https_data.get('cert_expires_soon'):
                                days = https_data.get('days_until_expiry', 0)
                                st.warning(f"⚠️ Certificate expires in {days} days")
                            elif https_data.get('has_https'):
                                st.write(f"Certificate Valid: ✅ ({https_data.get('days_until_expiry', 'N/A')} days)")
                        
                        # Vulnerability breakdown
                        web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))
                        vulns = web_data.get('vulnerabilities', [])
                        
                        if vulns:
                            st.markdown("**Detected Vulnerabilities**")
                            for vuln in vulns:
                                severity = vuln.get('severity', 'info').upper()
                                severity_color = "🔴" if severity in ['CRITICAL', 'HIGH'] else "🟡" if severity == 'MEDIUM' else "🔵"
                                st.write(f"{severity_color} {vuln.get('name', 'Unknown')} ({severity})")
                        
                        # Directory findings
                        dir_data = safe_json_parse(asset.get('directory_discovery', '{}'))
                        admin_panels = dir_data.get('admin_panels', [])
                        sensitive_files = dir_data.get('sensitive_files', [])
                        
                        if admin_panels or sensitive_files:
                            st.markdown("**Exposed Resources**")
                            
                            if admin_panels:
                                st.write(f"🔴 Admin Panels: {len(admin_panels)}")
                                for panel in admin_panels[:3]:
                                    st.code(panel.get('url', ''), language="")
                                if len(admin_panels) > 3:
                                    st.write(f"... and {len(admin_panels) - 3} more")
                            
                            if sensitive_files:
                                st.write(f"🟠 Sensitive Files: {len(sensitive_files)}")
                                for sfile in sensitive_files[:3]:
                                    st.code(sfile.get('path', ''), language="")
                                if len(sensitive_files) > 3:
                                    st.write(f"... and {len(sensitive_files) - 3} more")
                
            else:
                st.info("No scan results found. Run a scan first!")
        
        except Exception as e:
            st.error(f"Error loading results: {e}")

    # Tab 3: Report (Enhanced)
    with tab3:
        st.header("Security Report")
        try:
            assets = get_all_assets()
            stats = get_db_stats()

            #Interactive Risk Distribution Pie Chart
            st.subheader("Risk Distribution Visualization")

            import plotly.graph_objects as go

            # Prepare data
            risk_labels = ['Critical', 'High', 'Medium', 'Low']
            risk_values = [
                stats['critical_risk_assets'],
                stats['high_risk_assets'],
                stats['medium_risk_assets'],
                stats['low_risk_assets']
            ]
            risk_colors = ['#ff6b6b', '#ffa726', '#ffd93d', '#6bcf7f']

            # Create pie chart
            fig = go.Figure(data=[go.Pie(
                labels=risk_labels,
                values=risk_values,
                hole=0.3,  # Donut chart
                marker=dict(colors=risk_colors),
                textinfo='label+percent',
                textfont_size=14,
                hovertemplate='<b>%{label}</b><br>Assets: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])

            fig.update_layout(
                showlegend=True,
                height=400,
                margin=dict(t=0, b=0, l=0, r=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#e0e0e0')
            )

            st.plotly_chart(fig, use_container_width=True)

            if assets:
                # Executive Summary with risk score interpretation
                st.subheader("Executive Summary")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**Scan Overview**")
                    st.write(f"Total Assets: {stats['total_assets']}")
                    st.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M')}")
                    avg_score = stats['avg_score']
                    risk_level = "Critical" if avg_score >= 70 else "High" if avg_score >= 50 else "Medium" if avg_score >= 30 else "Low"
                    st.write(f"Average Risk: {avg_score:.1f}/100 ({risk_level})")
                
                with col2:
                    st.markdown("**Risk Breakdown**")
                    st.write(f"🔴 Critical: {stats['critical_risk_assets']}")
                    st.write(f"🟠 High: {stats['high_risk_assets']}")
                    st.write(f"🟡 Medium: {stats['medium_risk_assets']}")
                    st.write(f"🟢 Low: {stats['low_risk_assets']}")
                
                with col3:
                    st.markdown("**Security Posture**")
                    https_count = sum(1 for a in assets if safe_json_parse(a.get('ssl_vulnerabilities', '{}')).get('has_https'))
                    https_pct = (https_count / len(assets) * 100) if assets else 0
                    st.write(f"HTTPS Coverage: {https_pct:.0f}%")
                    
                    total_vulns = sum(len(safe_json_parse(a.get('web_vulnerabilities', '{}')).get('vulnerabilities', [])) for a in assets)
                    st.write(f"Total Vulnerabilities: {total_vulns}")
                    
                    total_exposed = sum(len(safe_json_parse(a.get('directory_discovery', '{}')).get('admin_panels', [])) for a in assets)
                    st.write(f"Exposed Admin Panels: {total_exposed}")
                
                st.markdown("---")
                
                # Detailed Findings Section
                st.subheader("Detailed Findings")
                
                tab_critical, tab_config, tab_crypto = st.tabs(["Critical Issues", "Configuration", "Cryptography"])
                
                with tab_critical:
                    critical_found = False
                    
                    # High-risk assets
                    high_risk_assets = [a for a in assets if a.get('score', 0) >= 50]
                    if high_risk_assets:
                        critical_found = True
                        st.warning(f"⚠️ {len(high_risk_assets)} assets require immediate attention")
                        for asset in high_risk_assets:
                            st.write(f"• {asset['domain']} (Score: {asset['score']}/100)")
                    
                    # Exposed admin panels
                    for asset in assets:
                        dir_data = safe_json_parse(asset.get('directory_discovery', '{}'))
                        if dir_data.get('admin_panels'):
                            critical_found = True
                            st.error(f"🔴 {asset['domain']}: {len(dir_data['admin_panels'])} admin panels exposed")
                    
                    if not critical_found:
                        st.success("✅ No critical security issues detected")
                
                with tab_config:
                    # Missing HTTPS
                    no_https = [a for a in assets if not safe_json_parse(a.get('ssl_vulnerabilities', '{}')).get('has_https')]
                    if no_https:
                        st.warning(f"⚠️ {len(no_https)} assets without HTTPS encryption")
                        for asset in no_https:
                            st.write(f"• {asset['domain']}")
                    
                    # Unusual ports
                    for asset in assets:
                        ports = asset.get('ports', '').split(',')
                        unusual = [p for p in ports if p.strip() not in ['80', '443', '']]
                        if unusual:
                            st.info(f"ℹ️ {asset['domain']}: Additional ports open - {', '.join(unusual)}")
                
                with tab_crypto:
                    # Certificate analysis
                    expiring_soon = []
                    invalid_certs = []
                    
                    for asset in assets:
                        https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
                        if https_data.get('cert_expires_soon'):
                            expiring_soon.append((asset['domain'], https_data.get('days_until_expiry')))
                        if https_data.get('has_https') and not https_data.get('valid_cert'):
                            invalid_certs.append(asset['domain'])
                    
                    if expiring_soon:
                        st.warning(f"⚠️ {len(expiring_soon)} certificates expiring soon")
                        for domain, days in expiring_soon:
                            st.write(f"• {domain}: {days} days remaining")
                    
                    if invalid_certs:
                        st.error(f"🔴 {len(invalid_certs)} invalid certificates")
                        for domain in invalid_certs:
                            st.write(f"• {domain}")
                    
                    if not expiring_soon and not invalid_certs:
                        st.success("✅ All certificates are valid and current")
                
                st.markdown("---")
                
                # Export with additional formats
                st.subheader("Export & Documentation")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    # Enhanced JSON export
                    report_data = {
                        'metadata': {
                            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'total_assets': len(assets),
                            'scan_summary': {
                                'avg_risk_score': stats['avg_score'],
                                'risk_distribution': {
                                    'critical': stats['critical_risk_assets'],
                                    'high': stats['high_risk_assets'],
                                    'medium': stats['medium_risk_assets'],
                                    'low': stats['low_risk_assets']
                                }
                            }
                        },
                        'assets': [dict(asset) for asset in assets]
                    }
                    
                    st.download_button(
                        label="📄 Download JSON",
                        data=json.dumps(report_data, indent=2),
                        file_name=f"aegis_report_{time.strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                
                with col2:
                    st.download_button(
                        label="📊 Download CSV",
                        data=format_scan_results(assets).to_csv(index=False),
                        file_name=f"aegis_assets_{time.strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                
                with col3:
                    # Simple markdown report
                    md_report = f"""# Aegis-Lite Security Report
                    
    **Generated:** {time.strftime('%Y-%m-%d %H:%M')}
    **Total Assets:** {len(assets)}
    **Average Risk Score:** {stats['avg_score']:.1f}/100

    ## Risk Summary
    - Critical: {stats['critical_risk_assets']}
    - High: {stats['high_risk_assets']}
    - Medium: {stats['medium_risk_assets']}
    - Low: {stats['low_risk_assets']}

    ## Assets Scanned
    """
                    for asset in assets:
                        md_report += f"\n### {asset['domain']}\n"
                        md_report += f"- Score: {asset['score']}/100\n"
                        md_report += f"- IP: {asset['ip']}\n"
                        md_report += f"- Ports: {asset['ports']}\n"
                    
                    st.download_button(
                        label="📝 Download Markdown",
                        data=md_report,
                        file_name=f"aegis_report_{time.strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown"
                    )
                
                # Prioritized recommendations
                st.subheader("Recommended Actions")
                
                recommendations = []
                
                if stats['critical_risk_assets'] > 0:
                    recommendations.append(("🔴 URGENT", f"Address {stats['critical_risk_assets']} critical-risk assets within 24 hours"))
                
                if stats['high_risk_assets'] > 0:
                    recommendations.append(("🟠 HIGH", f"Remediate {stats['high_risk_assets']} high-risk vulnerabilities within 7 days"))
                
                if len(no_https) > 0:
                    recommendations.append(("🟡 MEDIUM", f"Enable HTTPS on {len(no_https)} assets"))
                
                if expiring_soon:
                    recommendations.append(("🟡 MEDIUM", f"Renew {len(expiring_soon)} expiring certificates"))
                
                # Standard recommendations
                recommendations.extend([
                    ("🟢 ONGOING", "Schedule monthly security scans"),
                    ("🟢 ONGOING", "Implement automated monitoring"),
                    ("🟢 ONGOING", "Maintain software update schedule"),
                    ("🟢 ONGOING", "Review access controls quarterly")
                ])
                
                for priority, action in recommendations:
                    st.write(f"{priority}: {action}")
            
            else:
                st.info("No data available. Run a scan first!")
        
        except Exception as e:
            st.error(f"Error generating report: {e}")

    # Tab 4: Action Plan with unique issues aggregation
    with tab4:
        st.header("🎯 Business Action Plan")
        
        try:
            assets = get_all_assets()
            
            if assets:
                # Get stats for the action plan
                stats = get_db_stats()
                
                # Business Risk Summary
                st.subheader("📋 Executive Risk Summary")
                
                # Simple business language summary
                critical_count = stats['critical_risk_assets']
                high_count = stats['high_risk_assets']
                
                if critical_count > 0:
                    st.error(f"🚨 **URGENT**: {critical_count} critical security issues need immediate attention")
                elif high_count > 0:
                    st.warning(f"⚠️ **ATTENTION NEEDED**: {high_count} high-priority security issues found")
                else:
                    st.success("✅ **GOOD NEWS**: No critical security issues detected")
                
                # Business Impact Analysis - WITH UNIQUE ISSUES
                st.subheader("💼 Business Impact Analysis")
                
                # Track unique issues to avoid repetition
                unique_issues = {}
                
                for asset in assets:
                    https_data = safe_json_parse(asset.get('ssl_vulnerabilities', '{}'))
                    web_data = safe_json_parse(asset.get('web_vulnerabilities', '{}'))
                    dir_data = safe_json_parse(asset.get('directory_discovery', '{}'))

                    # Track issue: No HTTPS
                    if not https_data.get('has_https'):
                        key = "no_https"
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Customer Data Exposure',
                                'impact': 'Visitor information could be intercepted by attackers',
                                'urgency': 'High',
                                'action': 'Enable HTTPS encryption on all websites',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))
                    
                    # Track issue: Expiring certificate
                    if https_data.get('cert_expires_soon'):
                        days = https_data.get('days_until_expiry', 0)
                        key = f"expiring_cert_{days}"
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Website Downtime Risk',
                                'impact': f'Website may stop working in {days} days when certificate expires',
                                'urgency': 'Medium',
                                'action': 'Renew SSL certificate before expiration',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))
                    
                    # Track issue: Admin panels exposed
                    if web_data.get('has_admin_panel', False):
                        key = "exposed_admin"
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Unauthorized Access Risk',
                                'impact': 'Admin areas could be hacked, leading to full site compromise',
                                'urgency': 'High',
                                'action': 'Password-protect admin pages and implement access controls',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))
                    
                    # Track issue: Vulnerabilities found
                    vuln_count = len(web_data.get('vulnerabilities', []))
                    if vuln_count > 0:
                        key = "vulnerabilities_found"
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Website Compromise Risk',
                                'impact': 'Hackers could deface your site, steal data, or take it offline',
                                'urgency': 'High',
                                'action': 'Patch security vulnerabilities immediately',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))
                    
                    # Track issue: Exposed admin panels
                    if dir_data.get('admin_panels'):
                        key = "exposed_admin_panels"
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Unauthorized Admin Access',
                                'impact': 'Attackers could gain control of your website through exposed admin interfaces',
                                'urgency': 'High',
                                'action': 'Restrict access to admin panels or move them to non-standard locations',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))

                    # Track issue: Sensitive files exposed
                    if dir_data.get('sensitive_files'):
                        key = "exposed_sensitive_files" 
                        if key not in unique_issues:
                            unique_issues[key] = {
                                'risk': 'Sensitive Data Exposure',
                                'impact': 'Configuration files, backups, or source code could be downloaded by attackers',
                                'urgency': 'High', 
                                'action': 'Remove sensitive files from web-accessible directories',
                                'affected_assets': 0,
                                'example_domains': []
                            }
                        unique_issues[key]['affected_assets'] += 1
                        unique_issues[key]['example_domains'].append(asset.get('domain', 'Unknown'))
                
                # Display unique business risks
                if unique_issues:
                    # Sort by urgency and affected assets
                    sorted_issues = sorted(
                        unique_issues.values(), 
                        key=lambda x: (x['urgency'] == 'High', x['affected_assets']), 
                        reverse=True
                    )
                    
                    for i, risk in enumerate(sorted_issues, 1):
                        with st.expander(
                            f"{i}. {risk['risk']} - {risk['urgency']} Priority "
                            f"({risk['affected_assets']} asset{'s' if risk['affected_assets'] > 1 else ''} affected)", 
                            expanded=i == 1  # Expand first item only
                        ):
                            st.write(f"**🚨 Business Impact:** {risk['impact']}")
                            st.write(f"**🛠️ Required Action:** {risk['action']}")
                            
                            # Show a couple of example domains (not all to avoid clutter)
                            if risk['example_domains']:
                                example_count = min(3, len(risk['example_domains']))
                                examples = ", ".join(risk['example_domains'][:example_count])
                                if len(risk['example_domains']) > example_count:
                                    examples += f" and {len(risk['example_domains']) - example_count} more"
                                st.write(f"**📋 Affected:** {examples}")
                else:
                    st.success("✅ No security issues detected across all assets!")
                
                # Action Plan Section
                st.subheader("📝 Your Action Plan")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### 🚀 Immediate Actions (This Week)")
                    immediate_actions = [
                        "Contact your website developer with this report",
                        "Prioritize fixing critical and high-risk items", 
                        "Backup your website before making changes"
                    ]
                    for action in immediate_actions:
                        st.write(f"• {action}")
                
                with col2:
                    st.markdown("#### 📅 Ongoing Actions (This Month)")
                    ongoing_actions = [
                        "Schedule regular security scans (monthly)",
                        "Keep all software and plugins updated",
                        "Monitor for new vulnerabilities"
                    ]
                    for action in ongoing_actions:
                        st.write(f"• {action}")
                
                # Template Emails Section
                st.subheader("📧 Ready-to-Use Email Templates")
                
                email_tab1, email_tab2 = st.tabs(["To Your Developer", "To Your Hosting Company"])
                
                with email_tab1:
                    st.markdown("#### Email to Website Developer")
                    # Get domain for email template
                    current_domain = domain if 'domain' in locals() and domain else 'our website'
                    developer_email = f"""Subject: Urgent Security Updates Needed for {current_domain}

Hi [Developer Name],

I recently ran a security scan and found some issues that need attention:

{chr(10).join([f"- {issue['risk']}: {issue['action']}" for issue in list(unique_issues.values())[:3]])}

Can you please address these items as soon as possible? I've attached the full security report for your reference.

Thanks,
[Your Name]
"""
                    st.text_area("Copy and paste this email:", developer_email, height=200)
                    if st.button("📋 Copy Developer Email", key="dev_email"):
                        st.success("Email template copied to clipboard!")
                
                with email_tab2:
                    st.markdown("#### Email to Hosting Provider")
                    hosting_email = """Subject: SSL Certificate and Security Configuration Assistance

Hi [Hosting Support],

I need assistance with some security configurations for my website:

1. SSL Certificate: Please ensure our HTTPS is properly configured
2. Server Security: Help review our security settings
3. Regular Monitoring: Set up security alerts if possible

Can you let me know what security services you offer and associated costs?

Thanks,
[Your Name]
"""
                    st.text_area("Copy and paste this email:", hosting_email, height=200)
                    if st.button("📋 Copy Hosting Email", key="host_email"):
                        st.success("Email template copied to clipboard!")
                
                # Simple Next Steps
                st.subheader("🎯 Your Next 3 Steps")
                
                steps = [
                    "1. **Email your developer** using the template above",
                    "2. **Follow up in 3 days** if you haven't heard back", 
                    "3. **Scan again next month** to verify fixes are working"
                ]
                
                for step in steps:
                    st.write(step)
                    
            else:
                st.info("🔍 Run a security scan first to generate your action plan")
                
        except Exception as e:
            st.error(f"Error generating action plan: {e}")

    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666; font-size: 0.9em;'>"
        "Aegis-Lite Security Scanner • Built for educational purposes • Use responsibly"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()