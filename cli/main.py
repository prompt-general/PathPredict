import click
import sys
from pathlib import Path
from ingestion.aws.ingestor import AWSIngestor
from graph.connection import get_connection

@click.group()
def cli():
    """Path Predict CLI - Multi-Cloud Attack Path Prediction"""
    pass

@cli.command()
def init():
    """Initialize the Neo4j database schema"""
    click.echo("Initializing Neo4j database schema...")
    try:
        conn = get_connection()
        click.echo("✅ Schema initialized successfully!")
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option("--profile", default="default", help="AWS profile name")
@click.option("--account-id", help="AWS account ID (optional)")
def ingest_aws(profile, account_id):
    """Ingest AWS IAM and EC2 data"""
    click.echo(f"Ingesting AWS data using profile: {profile}")
    
    try:
        ingestor = AWSIngestor(aws_profile=profile, account_id=account_id)
        
        with click.progressbar(
            label="Ingesting IAM roles",
            length=1  # We'll update this dynamically
        ) as bar:
            roles = ingestor.ingest_iam_roles()
            bar.update(1)
            click.echo(f"✅ Ingested {len(roles)} IAM roles")
        
        with click.progressbar(
            label="Ingesting EC2 instances",
            length=1
        ) as bar:
            instances = ingestor.ingest_ec2_instances()
            bar.update(1)
            click.echo(f"✅ Ingested {len(instances)} EC2 instances")
        
        click.echo("🎉 AWS ingestion completed!")
        
    except Exception as e:
        click.echo(f"❌ Error during ingestion: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option("--limit", default=10, help="Number of paths to show")
def list_paths(limit):
    """List current attack paths"""
    conn = get_connection()
    
    query = """
    MATCH (i:Identity)
    WHERE i.node_id CONTAINS 'aws'
    RETURN i.node_id, i.subtype, count(*) as count
    ORDER BY count DESC
    LIMIT $limit
    """
    
    results = conn.execute_query(query, {"limit": limit})
    
    click.echo("Current Identity Nodes:")
    click.echo("-" * 80)
    for result in results:
        click.echo(f"{result['i.node_id']} ({result['i.subtype']})")

@cli.command()
def server():
    """Start the API server"""
    import uvicorn
    click.echo("Starting Path Predict API server...")
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

from cli.attack_paths import add_paths_commands
add_paths_commands(cli)

if __name__ == "__main__":
    # Import attack paths commands
    from cli.attack_paths import paths, add_paths_commands
    from cli.main import cli
    
    # Add attack paths commands to main CLI
    add_paths_commands(cli)
    
    cli()
