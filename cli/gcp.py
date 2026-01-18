# cli/gcp.py
import click
from ingestion.gcp.ingestor import GCPIngestor

@click.group()
def gcp():
    """GCP-specific commands"""
    pass

@gcp.command()
@click.option("--credentials", type=click.Path(exists=True), 
              help="Path to GCP service account credentials JSON")
@click.option("--project-id", required=True, help="GCP Project ID")
def ingest(credentials, project_id):
    """Ingest GCP resources into the graph"""
    click.echo(f"Ingesting GCP project: {project_id}")
    
    ingestor = GCPIngestor(credentials_path=credentials, project_id=project_id)
    ingestor.ingest_all(project_id)
    
    click.echo("✅ GCP ingestion completed")

# Update main CLI to include GCP commands
def add_gcp_commands(cli):
    cli.add_command(gcp)
