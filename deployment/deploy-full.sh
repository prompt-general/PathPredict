#!/bin/bash
# deployment/deploy-full.sh

set -e

echo "🚀 Deploying Full Path Predict Stack..."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed${NC}"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not installed${NC}"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed${NC}"
        exit 1
    fi
    
    # Check required environment variables
    required_vars=("SECRET_KEY")
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            echo -e "${YELLOW}⚠️  Warning: $var is not set${NC}"
        fi
    done
    
    echo -e "${GREEN}✅ Prerequisites satisfied${NC}"
}

# Generate configuration
generate_config() {
    echo -e "${BLUE}📝 Generating configuration...${NC}"
    
    # Create config directory
    mkdir -p config credentials models monitoring
    
    # Generate JWT secret if not set
    if [ -z "$SECRET_KEY" ]; then
        export SECRET_KEY=$(openssl rand -hex 32)
        echo -e "${YELLOW}⚠️  Generated SECRET_KEY: $SECRET_KEY${NC}"
        echo "Please save this key for future use!"
    fi
    
    # Generate admin password
    if [ -z "$ADMIN_PASSWORD" ]; then
        export ADMIN_PASSWORD=$(openssl rand -hex 16)
        echo -e "${YELLOW}⚠️  Generated ADMIN_PASSWORD: $ADMIN_PASSWORD${NC}"
    fi
    
    # Generate password hash using Python
    ADMIN_PASSWORD_HASH=$(python3 -c "
import bcrypt
password = '$ADMIN_PASSWORD'.encode('utf-8')
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)
print(hashed.decode('utf-8'))
")
    
    # Create environment file
    cat > .env << EOF
# Path Predict Environment Variables
# Database
NEO4J_AUTH=neo4j/pathpredict123
REDIS_PASSWORD=redis123

# Security
SECRET_KEY=$SECRET_KEY
ADMIN_PASSWORD_HASH=$ADMIN_PASSWORD_HASH
JWT_SECRET_KEY=$SECRET_KEY

# Cloud Providers (set these as needed)
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=
# AZURE_CLIENT_ID=
# AZURE_CLIENT_SECRET=
# AZURE_TENANT_ID=
# GCP_PROJECT_ID=
# GCP_CREDENTIALS=

# Alerting (set these as needed)
# SLACK_WEBHOOK_URL=
# TEAMS_WEBHOOK_URL=
# SMTP_SERVER=
# SMTP_USERNAME=
# SMTP_PASSWORD=
# FROM_EMAIL=
# TO_EMAILS=

# SIEM (set these as needed)
# SPLUNK_HOST=
# SPLUNK_TOKEN=
# SENTINEL_DCE=
# SENTINEL_DCR_ID=
EOF
    
    echo -e "${GREEN}✅ Configuration generated${NC}"
}

# Build images
build_images() {
    echo -e "${BLUE}🐳 Building Docker images...${NC}"
    
    # Build base images
    docker-compose -f docker-compose.full.yml build
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Docker images built successfully${NC}"
    else
        echo -e "${RED}❌ Failed to build Docker images${NC}"
        exit 1
    fi
}

# Start services
start_services() {
    echo -e "${BLUE}🚀 Starting services...${NC}"
    
    # Pull latest images
    docker-compose -f docker-compose.full.yml pull
    
    # Start services
    docker-compose -f docker-compose.full.yml up -d
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Services started${NC}"
    else
        echo -e "${RED}❌ Failed to start services${NC}"
        exit 1
    fi
}

# Wait for services
wait_for_services() {
    echo -e "${BLUE}⏳ Waiting for services to be ready...${NC}"
    
    services=("neo4j" "redis" "api" "prometheus" "grafana")
    
    for service in "${services[@]}"; do
        echo -n "Waiting for $service..."
        
        max_attempts=30
        attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if docker-compose -f docker-compose.full.yml ps $service | grep -q "Up"; then
                # Additional health check for some services
                case $service in
                    "neo4j")
                        if docker-compose -f docker-compose.full.yml exec neo4j cypher-shell -u neo4j -p pathpredict123 "RETURN 1" &> /dev/null; then
                            echo -e "${GREEN} ✅${NC}"
                            break
                        fi
                        ;;
                    "api")
                        if curl -s http://localhost:8000/health > /dev/null; then
                            echo -e "${GREEN} ✅${NC}"
                            break
                        fi
                        ;;
                    "redis")
                        if docker-compose -f docker-compose.full.yml exec redis redis-cli ping | grep -q "PONG"; then
                            echo -e "${GREEN} ✅${NC}"
                            break
                        fi
                        ;;
                    *)
                        echo -e "${GREEN} ✅${NC}"
                        break
                        ;;
                esac
            fi
            
            echo -n "."
            sleep 2
            attempt=$((attempt + 1))
        done
        
        if [ $attempt -gt $max_attempts ]; then
            echo -e "${RED} ❌${NC}"
            echo -e "${RED}❌ Service $service failed to start${NC}"
            exit 1
        fi
    done
}

# Initialize system
initialize_system() {
    echo -e "${BLUE}🔧 Initializing system...${NC}"
    
    # Initialize Neo4j schema
    echo -n "Initializing database schema..."
    docker-compose -f docker-compose.full.yml exec api python -m cli.main init
    echo -e "${GREEN} ✅${NC}"
    
    # Create admin user
    echo -n "Creating admin user..."
    docker-compose -f docker-compose.full.yml exec api python -c "
from auth.rbac import RBACManager
rbac = RBACManager('$SECRET_KEY')
rbac.create_user('admin', 'admin@company.com', '$ADMIN_PASSWORD', ['admin'])
print('Admin user created')
"
    echo -e "${GREEN} ✅${NC}"
    
    # Create sample data
    echo -n "Creating sample data..."
    docker-compose -f docker-compose.full.yml exec api python tests/sample_data.py
    echo -e "${GREEN} ✅${NC}"
    
    echo -e "${GREEN}✅ System initialized${NC}"
}

# Show deployment info
show_info() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        PATH PREDICT DEPLOYED!         ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    echo -e "${BLUE}📊 Services:${NC}"
    echo "  • Neo4j Browser:      http://localhost:7474"
    echo "      Username: neo4j"
    echo "      Password: pathpredict123"
    echo ""
    echo "  • API Documentation:  http://localhost:8000/docs"
    echo "  • GraphQL Playground: http://localhost:8000/graphql"
    echo "  • Grafana Dashboard:  http://localhost:3000"
    echo "      Username: admin"
    echo "      Password: admin123"
    echo "  • Prometheus:         http://localhost:9090"
    echo ""
    
    echo -e "${BLUE}🔐 Admin Credentials:${NC}"
    echo "  Username: admin"
    echo "  Password: $ADMIN_PASSWORD"
    echo ""
    
    echo -e "${BLUE}🛠️  Useful Commands:${NC}"
    echo "  • View logs:          docker-compose -f docker-compose.full.yml logs -f"
    echo "  • Stop services:      docker-compose -f docker-compose.full.yml down"
    echo "  • Restart services:   docker-compose -f docker-compose.full.yml restart"
    echo "  • Check status:       docker-compose -f docker-compose.full.yml ps"
    echo ""
    
    echo -e "${BLUE}🚀 Quick Start:${NC}"
    echo "  1. Test API:          curl http://localhost:8000/health"
    echo "  2. Login:             curl -X POST http://localhost:8000/api/v1/auth/login \\"
    echo "                        -H \"Content-Type: application/json\" \\"
    echo "                        -d '{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}'"
    echo "  3. Detect paths:      python -m cli.main paths detect"
    echo "  4. View dashboard:    python -m cli.main realtime dashboard"
    echo ""
    
    echo -e "${YELLOW}⚠️  Important:${NC}"
    echo "  • Set up cloud provider credentials in .env file"
    echo "  • Configure alerting channels for notifications"
    echo "  • Set up SIEM integrations for enterprise use"
    echo "  • Schedule regular compliance checks"
    echo ""
}

# Main deployment flow
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    PATH PREDICT FULL DEPLOYMENT       ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    check_prerequisites
    generate_config
    build_images
    start_services
    wait_for_services
    initialize_system
    show_info
}

# Run main function
main
