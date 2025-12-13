#!/bin/bash
# Dstack GCP Deployment Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/terraform"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

check_prereqs() {
    command -v gcloud &>/dev/null || { echo -e "${RED}gcloud CLI not found${NC}"; exit 1; }
    command -v terraform &>/dev/null || { echo -e "${RED}Terraform not found${NC}"; exit 1; }
    
    ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    [ -z "$ACCOUNT" ] && { echo -e "${RED}Not authenticated. Run: gcloud auth login${NC}"; exit 1; }
    echo -e "${GREEN}Authenticated as: $ACCOUNT${NC}"
}

deploy() {
    cd "$TERRAFORM_DIR"
    
    [ ! -f terraform.tfvars ] && {
        cp terraform.tfvars.example terraform.tfvars
        echo "Edit terraform.tfvars with your project ID, then re-run."
        exit 1
    }
    
    terraform init
    terraform plan -out=tfplan
    
    read -p "Apply? (y/N) " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]] && terraform apply tfplan && terraform output
}

destroy() {
    cd "$TERRAFORM_DIR"
    terraform destroy
}

case "${1:-deploy}" in
    deploy)  check_prereqs; deploy ;;
    destroy) destroy ;;
    *)       echo "Usage: $0 [deploy|destroy]"; exit 1 ;;
esac
