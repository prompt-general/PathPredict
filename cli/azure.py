# cli/azure.py
import click
from typing import Optional
from ingestion.azure.azure_ad_ingestor import AzureADIngestor

@click.group()
def azure():
    """Azure AD ingestion commands"""
    pass

@azure.command()
@click.option("--tenant-id", required=True, help="Azure AD tenant ID")
@click.option("--client-id", required=True, help="Azure AD client ID")
@click.option("--client-secret", required=True, help="Azure AD client secret")
def ingest(tenant_id, client_id, client_secret):
    """Ingest Azure Active Directory data"""
    click.echo("🔍 Ingesting Azure Active Directory data...")
    
    try:
        ingestor = AzureADIngestor(tenant_id, client_id, client_secret)
        
        with click.progressbar(
            label="Ingesting users",
            length=1
        ) as bar:
            users = ingestor.ingest_users()
            bar.update(1)
            click.echo(f"✅ Ingested {len(users)} users")
        
        with click.progressbar(
            label="Ingesting groups",
            length=1
        ) as bar:
            groups = ingestor.ingest_groups()
            bar.update(1)
            click.echo(f"✅ Ingested {len(groups)} groups")
        
        with click.progressbar(
            label="Ingesting service principals",
            length=1
        ) as bar:
            service_principals = ingestor.ingest_service_principals()
            bar.update(1)
            click.echo(f"✅ Ingested {len(service_principals)} service principals")
        
        click.echo("🎉 Azure AD ingestion completed!")
        
    except Exception as e:
        click.echo(f"❌ Error during Azure AD ingestion: {e}", err=True)
        raise

# Update main CLI to include Azure commands
def add_azure_commands(cli):
    """Add Azure commands to main CLI"""
    cli.add_command(azure)
