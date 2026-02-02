#!/bin/bash
# KE Analyzer Startup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting KE Analyzer...${NC}"

# Check if .env file exists
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo -e "${YELLOW}Warning: .env file not found. Copying from .env.example${NC}"
        cp .env.example .env
        echo -e "${RED}Please edit .env file with your configuration before continuing.${NC}"
        exit 1
    else
        echo -e "${RED}Error: .env file not found and .env.example is missing.${NC}"
        exit 1
    fi
fi

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo -e "${RED}Error: Python $required_version+ required, found $python_version${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -q -r requirements.txt

# Create necessary directories
mkdir -p /tmp/ke-analyzer
mkdir -p logs

# Check if required tools are available
echo -e "${YELLOW}Checking required tools...${NC}"

if command -v crash &>/dev/null; then
    echo -e "${GREEN}✓ crash utility found${NC}"
else
    echo -e "${YELLOW}⚠ crash utility not found (optional but recommended)${NC}"
fi

if command -v gdb &>/dev/null; then
    echo -e "${GREEN}✓ gdb found${NC}"
else
    echo -e "${YELLOW}⚠ gdb not found (optional but recommended)${NC}"
fi

if command -v addr2line &>/dev/null; then
    echo -e "${GREEN}✓ addr2line found${NC}"
else
    echo -e "${YELLOW}⚠ addr2line not found (optional but recommended)${NC}"
fi

# Check environment variables
echo -e "${YELLOW}Checking configuration...${NC}"

if grep -q "your-jira.atlassian.net" .env; then
    echo -e "${YELLOW}⚠ Jira URL not configured in .env${NC}"
fi

if grep -q "your-dashscope-api-key" .env; then
    echo -e "${YELLOW}⚠ Qwen API Key not configured in .env${NC}"
fi

echo ""
echo -e "${GREEN}Starting server on http://localhost:8000${NC}"
echo -e "${GREEN}Health check: http://localhost:8000/health${NC}"
echo ""

# Run the server
exec python -m uvicorn orchestrator.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info \
    --access-log
