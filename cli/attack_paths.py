import click
import json
from typing import List, Dict, Any
from tabulate import tabulate
from attack_paths.traversal import AttackPathTraversal
from attack_paths.scoring import RiskScoringEngine
from graph.connection import get_connection
import sys
from datetime import datetime

@click.group()
def paths():
    """Attack path detection and analysis commands"""
    pass

@paths.command()
@click.option("--type", "-t", 
              type=click.Choice(['all', 'privilege', 'public', 'cross-account', 'identity']),
              default='all',
              help="Type of attack paths to detect")
@click.option("--limit", "-l", default=10, help="Number of paths to show")
@click.option("--min-score", default=30, help="Minimum risk score to show")
@click.option("--format", "-f", 
              type=click.Choice(['table', 'json', 'csv']),
              default='table',
              help="Output format")
def detect(type, limit, min_score, format):
    """Detect and display attack paths"""
    click.echo(f"🔍 Detecting {type} attack paths...")
    
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        # Get paths based on type
        if type == 'privilege':
            raw_paths = traversal.detect_privilege_escalation(limit=limit*2)
        elif type == 'public':
            raw_paths = traversal.detect_public_exposure()
        elif type == 'cross-account':
            raw_paths = traversal.detect_cross_account_paths()
        elif type == 'identity':
            raw_paths = traversal.detect_identity_chains()
        else:  # all
            all_paths = traversal.detect_all_paths()
            raw_paths = []
            for path_list in all_paths.values():
                raw_paths.extend(path_list)
        
        # Score and filter paths
        scored_paths = scoring.batch_score_paths(raw_paths)
        filtered_paths = [
            p for p in scored_paths 
            if p['risk_assessment']['raw_score'] >= min_score
        ][:limit]
        
        if not filtered_paths:
            click.echo("✅ No attack paths found above threshold.")
            return
        
        # Display based on format
        if format == 'json':
            click.echo(json.dumps(filtered_paths, indent=2))
        elif format == 'csv':
            # Generate CSV
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'Path ID', 'Type', 'Source', 'Target', 
                'Hops', 'Risk Score', 'Risk Level', 'Providers'
            ])
            
            # Data
            for path in filtered_paths:
                writer.writerow([
                    path['path_id'],
                    path.get('type', 'unknown'),
                    path['source'][:50] + '...' if len(path['source']) > 50 else path['source'],
                    path['target'][:50] + '...' if len(path['target']) > 50 else path['target'],
                    path.get('hop_count', 1),
                    f"{path['risk_assessment']['raw_score']:.1f}",
                    path['risk_assessment']['risk_level'],
                    ','.join(path.get('providers', []))
                ])
            
            click.echo(output.getvalue())
        else:  # table format
            table_data = []
            for path in filtered_paths:
                risk = path['risk_assessment']
                
                # Color code risk level
                risk_level = risk['risk_level']
                if risk_level == 'CRITICAL':
                    risk_level = click.style('CRITICAL', fg='red', bold=True)
                elif risk_level == 'HIGH':
                    risk_level = click.style('HIGH', fg='yellow', bold=True)
                elif risk_level == 'MEDIUM':
                    risk_level = click.style('MEDIUM', fg='blue')
                else:
                    risk_level = click.style(risk_level, fg='green')
                
                table_data.append([
                    path['path_id'][:20] + '...',
                    path.get('type', 'unknown')[:15],
                    path['source'][:30] + '...',
                    path['target'][:30] + '...',
                    path.get('hop_count', 1),
                    f"{risk['raw_score']:.1f}",
                    risk_level,
                    ','.join(path.get('providers', []))[:20]
                ])
            
            headers = ['ID', 'Type', 'Source', 'Target', 'Hops', 'Score', 'Risk', 'Providers']
            click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
            
            # Summary
            click.echo(f"\n📊 Summary: Found {len(filtered_paths)} attack paths")
            
            risk_counts = {}
            for path in filtered_paths:
                level = path['risk_assessment']['risk_level']
                risk_counts[level] = risk_counts.get(level, 0) + 1
            
            for level, count in risk_counts.items():
                click.echo(f"  {level}: {count}")
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@paths.command()
@click.option("--source", "-s", required=True, help="Source node ID")
@click.option("--target", "-t", required=True, help="Target node ID")
@click.option("--max-hops", default=5, help="Maximum hops to search")
def find(source, target, max_hops):
    """Find paths between two specific nodes"""
    click.echo(f"🔗 Finding paths from {source[:50]}... to {target[:50]}...")
    
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        paths = traversal.find_paths_between(
            source_id=source,
            target_id=target,
            max_hops=max_hops
        )
        
        scored_paths = scoring.batch_score_paths(paths)
        
        if not scored_paths:
            click.echo("❌ No paths found between specified nodes.")
            return
        
        click.echo(f"✅ Found {len(scored_paths)} path(s)")
        
        for i, path in enumerate(scored_paths, 1):
            risk = path['risk_assessment']
            click.echo(f"\n--- Path {i} ---")
            click.echo(f"Score: {risk['raw_score']:.1f} ({risk['risk_level']})")
            click.echo(f"Hops: {path.get('hop_count', 1)}")
            click.echo(f"Confidence: {risk['confidence']:.1%}")
            click.echo(f"Priority: {risk['remediation_priority']}/5")
            
            click.echo("\nPath steps:")
            for j, node_id in enumerate(path.get('nodes', [])):
                rel = path.get('relationships', [])[j] if j < len(path.get('relationships', [])) else ''
                click.echo(f"  {node_id[:80]} {rel}")
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@paths.command()
def summary():
    """Show attack path summary"""
    click.echo("📊 Generating attack path summary...")
    
    try:
        from api.attack_paths import attack_paths_summary
        
        # Use API function
        summary_data = attack_paths_summary()
        
        # Display summary
        click.echo(f"\n📈 Attack Path Summary")
        click.echo(f"Timestamp: {summary_data['timestamp']}")
        click.echo(f"Total Paths: {summary_data['total_paths']}")
        
        click.echo(f"\n🔢 By Type:")
        for path_type, count in summary_data['by_type'].items():
            click.echo(f"  {path_type}: {count}")
        
        click.echo(f"\n⚠️  By Risk Level:")
        for level, count in summary_data['by_risk_level'].items():
            if count > 0:
                if level == 'CRITICAL':
                    level_display = click.style(level, fg='red', bold=True)
                elif level == 'HIGH':
                    level_display = click.style(level, fg='yellow')
                else:
                    level_display = level
                click.echo(f"  {level_display}: {count}")
        
        click.echo(f"\n☁️  By Cloud Providers:")
        for providers, count in summary_data['by_provider'].items():
            click.echo(f"  {providers}: {count}")
        
        if summary_data['top_critical']:
            click.echo(f"\n🔥 Top Critical Paths:")
            for i, path in enumerate(summary_data['top_critical'][:3], 1):
                click.echo(f"  {i}. {path['path_id']}")
                click.echo(f"     Score: {path['risk_assessment']['raw_score']:.1f}")
                click.echo(f"     Source → Target: {path['source'][:50]}... → {path['target'][:50]}...")
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@paths.command()
@click.argument("path_id")
@click.option("--action", "-a", 
              type=click.Choice(['remove_edge', 'add_mfa', 'restrict_access']),
              default='remove_edge',
              help="Remediation action to simulate")
def simulate(path_id, action):
    """Simulate remediation on an attack path"""
    click.echo(f"🔄 Simulating {action} on path: {path_id}")
    
    try:
        from api.attack_paths import simulate_remediation
        
        result = simulate_remediation(path_id=path_id, action=action)
        
        if result.get('success', True):
            click.echo(f"✅ Simulation completed: {result['simulation_id']}")
            click.echo(f"\n📋 Results:")
            for key, value in result['results'].items():
                click.echo(f"  {key}: {value}")
            click.echo(f"\n💡 Assumptions: {result['assumptions']}")
        else:
            click.echo(f"❌ Simulation failed: {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@paths.command()
@click.option("--export-format", 
              type=click.Choice(['cypher', 'json', 'graphml']),
              default='cypher',
              help="Export format")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def export(export_format, output):
    """Export attack paths for external analysis"""
    click.echo(f"📤 Exporting attack paths in {export_format} format...")
    
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        # Get all paths
        all_paths = traversal.detect_all_paths()
        all_paths_list = []
        for paths in all_paths.values():
            all_paths_list.extend(paths)
        
        scored_paths = scoring.batch_score_paths(all_paths_list)
        
        if export_format == 'json':
            data = {
                "export_timestamp": datetime.utcnow().isoformat(),
                "total_paths": len(scored_paths),
                "attack_paths": scored_paths
            }
            
            export_data = json.dumps(data, indent=2)
            
        elif export_format == 'cypher':
            # Generate Cypher queries to recreate paths
            export_data = "-- Path Predict Attack Path Export\n"
            export_data += f"-- Generated: {datetime.utcnow().isoformat()}\n"
            export_data += f"-- Total Paths: {len(scored_paths)}\n\n"
            
            for path in scored_paths[:50]:  # Limit to 50 paths
                export_data += f"// Path: {path['path_id']}\n"
                export_data += f"// Risk Score: {path['risk_assessment']['raw_score']:.1f}\n"
                export_data += f"// Risk Level: {path['risk_assessment']['risk_level']}\n\n"
                
        elif export_format == 'graphml':
            # Create NetworkX graph for GraphML export
            import networkx as nx
            G = nx.MultiDiGraph()
            
            for path in scored_paths:
                nodes = path.get('nodes', [])
                relationships = path.get('relationships', [])
                
                # Add nodes
                for node_id in nodes:
                    G.add_node(node_id, 
                              type=node_id.split('::')[1] if '::' in node_id else 'unknown')
                
                # Add edges
                for i in range(len(nodes) - 1):
                    if i < len(relationships):
                        G.add_edge(nodes[i], nodes[i+1], 
                                  relationship=relationships[i],
                                  path_id=path['path_id'])
            
            # Export to GraphML
            from io import StringIO
            output_buffer = StringIO()
            nx.write_graphml(G, output_buffer)
            export_data = output_buffer.getvalue()
        
        # Write to file or stdout
        if output:
            with open(output, 'w') as f:
                f.write(export_data)
            click.echo(f"✅ Exported to {output}")
        else:
            click.echo(export_data[:5000])  # Limit output to first 5000 chars
            if len(export_data) > 5000:
                click.echo(f"\n... (truncated, use --output to export full data)")
                
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

# Update main CLI to include paths commands
def add_paths_commands(cli):
    """Add attack path commands to main CLI"""
    cli.add_command(paths)
