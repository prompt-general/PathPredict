# cli/realtime.py
import click
import asyncio
import json
import websockets
from typing import Dict, Any
import logging
from tabulate import tabulate
from datetime import datetime

logger = logging.getLogger(__name__)

@click.group()
def realtime():
    """Real-time event processing and monitoring commands"""
    pass

@realtime.command()
@click.option("--profile", default="default", help="AWS profile name")
@click.option("--lookback", default=60, help="Lookback minutes for events")
def monitor(profile, lookback):
    """Monitor real-time security events"""
    click.echo(f"🔍 Monitoring AWS events (profile: {profile}, lookback: {lookback}m)")
    click.echo("Press Ctrl+C to stop\n")
    
    try:
        from events.collectors.aws_event_collector import AWSCloudTrailCollector
        from events.processors.event_processor import EventProcessor
        
        collector = AWSCloudTrailCollector(aws_profile=profile)
        processor = EventProcessor()
        
        # For now, simulate streaming
        import time
        from random import choice
        
        event_types = [
            "CreateRole", "AttachRolePolicy", "RunInstances",
            "AuthorizeSecurityGroupIngress", "AssumeRole"
        ]
        
        while True:
            # Simulate event
            simulated_event = {
                "event_id": f"event_{int(time.time())}",
                "event_name": choice(event_types),
                "event_time": datetime.utcnow().isoformat(),
                "request_parameters": {"roleName": "SimulatedRole"},
                "response_elements": {"role": {"arn": "arn:aws:iam::123456789012:role/SimulatedRole"}}
            }
            
            # Process event
            result = processor.process_aws_event(simulated_event)
            
            # Display
            click.echo(f"[{datetime.now().strftime('%H:%M:%S')}] {simulated_event['event_name']}")
            click.echo(f"  Result: {result.get('status', 'unknown')}")
            if result.get('risk_level') in ['HIGH', 'CRITICAL']:
                click.echo(f"  ⚠️  Risk: {click.style(result['risk_level'], fg='red', bold=True)}")
                if result.get('message'):
                    click.echo(f"  Message: {result['message']}")
            click.echo()
            
            time.sleep(10)  # Simulate every 10 seconds
            
    except KeyboardInterrupt:
        click.echo("\n⏹️  Monitoring stopped")
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)

@realtime.command()
@click.option("--url", default="ws://localhost:8000/api/v1/realtime/events", 
              help="WebSocket URL")
def websocket(url):
    """Connect to WebSocket for real-time updates"""
    click.echo(f"🔗 Connecting to WebSocket: {url}")
    
    async def connect_and_listen():
        try:
            async with websockets.connect(url) as websocket:
                click.echo("✅ Connected to Path Predict real-time events")
                click.echo("Waiting for events...\n")
                
                while True:
                    message = await websocket.recv()
                    data = json.loads(message)
                    
                    if data.get('type') == 'connection_established':
                        click.echo(f"📡 {data['message']}")
                    elif data.get('type') == 'security_event':
                        event = data['data']
                        click.echo(f"[{event['event_time'][11:19]}] {event['event_name']}")
                        click.echo(f"  Resource: {event['resource']}")
                        click.echo(f"  Risk: {click.style(event['risk_level'], fg='red' if event['risk_level'] in ['HIGH', 'CRITICAL'] else 'yellow')}")
                        if event.get('message'):
                            click.echo(f"  Note: {event['message']}")
                        click.echo()
                    
        except websockets.exceptions.ConnectionClosed:
            click.echo("❌ Connection closed")
        except Exception as e:
            click.echo(f"❌ Error: {e}")
    
    asyncio.run(connect_and_listen())

@realtime.command()
@click.option("--plan-file", type=click.Path(exists=True), help="Terraform plan JSON file")
@click.option("--hcl-file", type=click.Path(exists=True), help="Terraform HCL file")
@click.option("--block-on-high-risk", is_flag=True, help="Exit with error on high risk")
def analyze(plan_file, hcl_file, block_on_high_risk):
    """Analyze Terraform for attack path risks"""
    try:
        from cicd.terraform_analyzer import TerraformPlanAnalyzer
        
        analyzer = TerraformPlanAnalyzer()
        
        if plan_file:
            with open(plan_file, 'r') as f:
                plan_data = json.load(f)
            result = analyzer.analyze_plan(plan_data)
            click.echo("📋 Terraform Plan Analysis Results:")
        
        elif hcl_file:
            with open(hcl_file, 'r') as f:
                hcl_content = f.read()
            result = analyzer.analyze_hcl(hcl_content)
            click.echo("📋 Terraform HCL Analysis Results:")
        
        else:
            click.echo("❌ Must specify either --plan-file or --hcl-file")
            return
        
        # Display summary
        summary = result.get('summary', {})
        click.echo(f"Total Changes: {summary.get('total_changes', 0)}")
        click.echo(f"High Risk Changes: {click.style(str(summary.get('high_risk_changes', 0)), fg='red' if summary.get('high_risk_changes', 0) > 0 else 'green')}")
        click.echo(f"Potential Attack Paths: {summary.get('potential_attack_paths', 0)}")
        
        # Display high risk resources
        high_risk = result.get('high_risk_resources', [])
        if high_risk:
            click.echo("\n⚠️  High Risk Resources:")
            for resource in high_risk:
                click.echo(f"  • {resource['resource']}")
                for issue in resource.get('issues', []):
                    click.echo(f"    - {issue['title']} ({issue['severity']})")
        
        # Display recommendations
        recommendations = result.get('recommendations', [])
        if recommendations:
            click.echo("\n💡 Recommendations:")
            for rec in recommendations[:5]:  # Show top 5
                click.echo(f"  • {rec['resource']}: {rec['recommendation']}")
        
        # Exit with error if high risk and blocking
        if block_on_high_risk and summary.get('high_risk_changes', 0) > 0:
            click.echo("\n❌ High risk changes detected - exiting with error")
            raise click.Abort()
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)

@realtime.command()
@click.option("--changes-file", type=click.Path(exists=True), 
              help="JSON file with proposed changes")
@click.option("--horizon", default=7, help="Prediction horizon in days")
def predict(changes_file, horizon):
    """Predict future attack paths from proposed changes"""
    click.echo(f"🔮 Predicting attack paths ({horizon} day horizon)")
    
    try:
        from prediction.engine import AttackPathPredictor
        
        predictor = AttackPathPredictor()
        
        # Load changes
        changes = []
        if changes_file:
            with open(changes_file, 'r') as f:
                changes = json.load(f)
        else:
            # Sample changes
            changes = [
                {
                    "type": "role_created",
                    "node_id": "aws::iam::role/NewAdminRole",
                    "assume_role_policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
                }
            ]
        
        # Create sample graph
        import networkx as nx
        graph = nx.DiGraph()
        
        # Make predictions
        predictions = predictor.predict_attack_paths(graph, changes, horizon)
        
        if not predictions:
            click.echo("✅ No high-confidence predictions")
            return
        
        # Display predictions
        click.echo(f"\n📊 Found {len(predictions)} predictions:")
        
        table_data = []
        for pred in predictions[:10]:  # Show top 10
            table_data.append([
                pred.get('prediction_id', '')[:15],
                pred.get('type', '')[:20],
                pred.get('node', '')[:30],
                f"{pred.get('confidence', 0):.1%}",
                pred.get('risk_level', 'LOW')
            ])
        
        headers = ['ID', 'Type', 'Node', 'Confidence', 'Risk']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
        
        # Show high confidence predictions
        high_conf = [p for p in predictions if p.get('confidence', 0) > 0.7]
        if high_conf:
            click.echo(f"\n⚠️  {len(high_conf)} High Confidence Predictions:")
            for pred in high_conf[:3]:
                click.echo(f"  • {pred.get('type')} on {pred.get('node', '')[:50]}")
                if pred.get('reason'):
                    click.echo(f"    Reason: {pred['reason']}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)

@realtime.command()
def dashboard():
    """Show real-time dashboard"""
    import requests
    import time
    
    click.echo("📈 Path Predict Real-time Dashboard")
    click.echo("Updating every 10 seconds...\n")
    
    try:
        while True:
            try:
                response = requests.get("http://localhost:8000/api/v1/realtime/dashboard", timeout=5)
                if response.status_code == 200:
                    data = response.json().get('dashboard', {})
                    stats = data.get('stats', {})
                    
                    # Clear screen (Unix/Windows compatible)
                    click.clear()
                    
                    click.echo("=" * 60)
                    click.echo("PATH PREDICT DASHBOARD".center(60))
                    click.echo("=" * 60)
                    click.echo(f"Time: {data.get('timestamp', '')}")
                    click.echo(f"Active Connections: {stats.get('active_connections', 0)}")
                    click.echo("\n" + "-" * 60)
                    
                    # Stats
                    click.echo("📊 Graph Statistics:")
                    click.echo(f"  Total Nodes: {stats.get('total_nodes', 0)}")
                    click.echo(f"  Cloud Providers: {stats.get('providers', 0)}")
                    click.echo(f"  Critical Resources: {stats.get('critical_resources', 0)}")
                    click.echo(f"  Current Attack Paths: {data.get('current_attack_paths', 0)}")
                    
                    # Recent events
                    events = data.get('recent_events', [])
                    if events:
                        click.echo("\n📅 Recent Events:")
                        for event in events[:3]:
                            click.echo(f"  • {event.get('node', '')[:40]}...")
                    
                    # Top risks
                    risks = data.get('top_risks', [])
                    if risks:
                        click.echo("\n⚠️  Top Risks:")
                        for risk in risks[:3]:
                            click.echo(f"  • {risk.get('source', '')[:30]} → {risk.get('target', '')[:30]}")
                            click.echo(f"    Score: {risk.get('risk_score', 0):.1f}")
                    
                    click.echo("\n" + "=" * 60)
                    click.echo("Press Ctrl+C to exit")
                    
                else:
                    click.echo(f"❌ API error: {response.status_code}")
                    
            except requests.exceptions.RequestException:
                click.echo("❌ Cannot connect to API server")
            
            time.sleep(10)
            
    except KeyboardInterrupt:
        click.echo("\n⏹️  Dashboard stopped")

# Update main CLI to include realtime commands
def add_realtime_commands(cli):
    """Add real-time commands to main CLI"""
    cli.add_command(realtime)
