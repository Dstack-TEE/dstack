#!/bin/bash
# Dstack GCP Deployment Script
# Deploys Dstack with Intel TDX on Google Cloud Platform

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           DSTACK GCP DEPLOYMENT (Intel TDX)                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
check_prereqs() {
    echo "Checking prerequisites..."
    
    if ! command -v gcloud &> /dev/null; then
        echo -e "${RED}✗ gcloud CLI not found${NC}"
        echo "Install from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    echo -e "${GREEN}✓ gcloud CLI installed${NC}"
    
    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}✗ Terraform not found${NC}"
        echo "Install from: https://terraform.io"
        exit 1
    fi
    echo -e "${GREEN}✓ Terraform installed${NC}"
    
    ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [ -z "$ACCOUNT" ]; then
        echo -e "${RED}✗ Not authenticated with gcloud${NC}"
        echo "Run: gcloud auth login"
        exit 1
    fi
    echo -e "${GREEN}✓ Authenticated as: $ACCOUNT${NC}"
}

# Deploy
deploy() {
    cd "$TERRAFORM_DIR"
    
    if [ ! -f terraform.tfvars ]; then
        echo -e "${YELLOW}No terraform.tfvars found. Creating from example...${NC}"
        cp terraform.tfvars.example terraform.tfvars
        echo -e "${YELLOW}Please edit terraform.tfvars with your project ID${NC}"
        exit 1
    fi
    
    echo ""
    echo "Initializing Terraform..."
    terraform init
    
    echo ""
    echo "Planning deployment..."
    terraform plan -out=tfplan
    
    echo ""
    read -p "Apply this plan? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        terraform apply tfplan
        
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    DEPLOYMENT COMPLETE"
        echo "═══════════════════════════════════════════════════════════════"
        terraform output
        
        echo ""
        echo "To verify TDX is working:"
        echo "  $(terraform output -raw tdx_verification)"
    fi
}

# Destroy
destroy() {
    cd "$TERRAFORM_DIR"
    terraform destroy
}

# Main
case "${1:-deploy}" in
    deploy)
        check_prereqs
        deploy
        ;;
    destroy)
        destroy
        ;;
    *)
        echo "Usage: $0 [deploy|destroy]"
        exit 1
        ;;
esac

