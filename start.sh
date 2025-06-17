#!/bin/bash

#==============================================================================
# LLM Guard Service Startup Script
#==============================================================================
#
# DESCRIPTION:
#   This script manages the LLM Guard Security Service for the ORBIT platform.
#   It provides a simple interface to start the FastAPI-based security service
#   with different configurations for development, production, or Docker
#   environments.
#
# WHAT IT DOES:
#   1. Checks for required dependencies (Python, pip, virtual environment)
#   2. Ensures all Python packages are installed
#   3. Starts the uvicorn server with appropriate settings
#   4. Handles graceful shutdown on Ctrl+C
#
# CONFIGURATION:
#   All application settings (host, port, Redis URL, etc.) are loaded from
#   environment files (.env.local or .env) by the application itself.
#   This script only controls how the server runs, not what it serves.
#
# USAGE EXAMPLES:
#   
#   # Start in production mode with default settings
#   ./start.sh
#   
#   # Start in development mode with auto-reload enabled
#   # (Best for local development - automatically restarts on code changes)
#   ./start.sh -m development
#   
#   # Start with 4 worker processes for high traffic
#   # (Recommended for production deployments)
#   ./start.sh -w 4
#   
#   # Start in Docker container mode
#   # (Used in Dockerfile - binds to 0.0.0.0 automatically)
#   ./start.sh -m docker
#   
#   # Development with specific number of workers (workers ignored, uses 1)
#   ./start.sh -m development -w 4
#
# OPTIONS:
#   -w, --workers NUM    Number of worker processes (default: 1)
#                        Note: Multiple workers improve performance but disable reload
#   
#   -r, --reload         Enable auto-reload on code changes
#                        Note: Automatically enabled in development mode
#   
#   -m, --mode MODE      Execution mode: development|production|docker
#                        - development: Single worker, auto-reload, verbose logging
#                        - production:  Multiple workers, no reload, optimized
#                        - docker:      Container-optimized settings
#   
#   --help               Display help message and exit
#
# REQUIREMENTS:
#   - Python 3.11
#   - Virtual environment (automatically created if missing)
#   - Dependencies from requirements.txt
#   - .env.local or .env file for configuration
#
# AUTHOR: Remsy Schmilinsky
# VERSION: 1.0.0
#==============================================================================

# Default values (minimal - let the app handle config from .env.local)
WORKERS="1"
RELOAD="false"
MODE="production"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -w, --workers NUM        Number of worker processes (default: 1)"
    echo "  -r, --reload             Enable auto-reload (development mode)"
    echo "  -m, --mode MODE          Run mode (development|production|docker) (default: production)"
    echo "  --help                   Display this help message"
    echo ""
    echo "Environment configuration is loaded from .env.local (or .env)"
    echo ""
    echo "Examples:"
    echo "  $0                       # Run in production mode"
    echo "  $0 -m development -r     # Run in development mode with reload"
    echo "  $0 -w 4                  # Run with 4 workers"
    echo "  $0 -m docker            # Run in Docker mode"
    exit 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check dependencies
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"
    
    # Check Python
    if ! command_exists python3; then
        echo -e "${RED}Error: Python 3 is not installed${NC}"
        exit 1
    fi
    
    # Check pip
    if ! command_exists pip3; then
        echo -e "${RED}Error: pip3 is not installed${NC}"
        exit 1
    fi
    
    # Check if virtual environment exists (skip in docker mode)
    if [[ "$MODE" != "docker" ]] && [[ ! -d "venv" ]]; then
        echo -e "${YELLOW}Virtual environment not found. Creating one...${NC}"
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    elif [[ "$MODE" != "docker" ]]; then
        source venv/bin/activate
    fi
    
    # Check if uvicorn is installed
    if ! command_exists uvicorn; then
        echo -e "${YELLOW}Uvicorn not found. Installing dependencies...${NC}"
        pip install -r requirements.txt
    fi
    
    # Check if environment file exists
    if [[ -f ".env.local" ]]; then
        echo -e "${GREEN}Found .env.local${NC}"
    elif [[ -f ".env" ]]; then
        echo -e "${GREEN}Found .env${NC}"
    else
        echo -e "${YELLOW}Warning: No .env.local or .env file found. Using defaults.${NC}"
    fi
    
    echo -e "${GREEN}Dependencies checked${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        -r|--reload)
            RELOAD="true"
            shift
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Validate inputs
if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
    echo -e "${RED}Error: Invalid number of workers: $WORKERS${NC}"
    exit 1
fi

if [[ ! "$MODE" =~ ^(development|production|docker)$ ]]; then
    echo -e "${RED}Error: Invalid mode: $MODE${NC}"
    exit 1
fi

# Check dependencies
check_dependencies

# Build uvicorn command - let the app handle host/port from env
UVICORN_CMD="uvicorn app.main:app"

# Mode-specific settings
case $MODE in
    development)
        echo -e "${YELLOW}Starting in DEVELOPMENT mode${NC}"
        RELOAD="true"
        WORKERS="1"  # Force single worker in development
        ;;
    production)
        echo -e "${GREEN}Starting in PRODUCTION mode${NC}"
        if [ "$WORKERS" -gt 1 ]; then
            UVICORN_CMD="$UVICORN_CMD --workers $WORKERS"
        fi
        ;;
    docker)
        echo -e "${GREEN}Starting in DOCKER mode${NC}"
        # Docker mode - single worker, bind to 0.0.0.0
        WORKERS="1"
        UVICORN_CMD="$UVICORN_CMD --host 0.0.0.0"
        ;;
esac

# Add reload flag if specified
if [ "$RELOAD" = "true" ] && [ "$WORKERS" -eq 1 ]; then
    UVICORN_CMD="$UVICORN_CMD --reload"
elif [ "$RELOAD" = "true" ] && [ "$WORKERS" -gt 1 ]; then
    echo -e "${YELLOW}Warning: --reload is incompatible with multiple workers. Disabling reload.${NC}"
fi

# Display configuration
echo ""
echo -e "${GREEN}=== LLM Guard Service ===${NC}"
echo "Mode: $MODE"
echo "Workers: $WORKERS"
echo "Auto-reload: $RELOAD"
echo "Config: .env.local (or .env)"
echo -e "${GREEN}=========================${NC}"
echo ""

# Function to handle shutdown
cleanup() {
    echo -e "\n${YELLOW}Shutting down LLM Guard Service...${NC}"
    kill $UVICORN_PID 2>/dev/null
    wait $UVICORN_PID 2>/dev/null
    echo -e "${GREEN}Service stopped${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start the service
echo -e "${GREEN}Starting LLM Guard Service...${NC}"
echo -e "${YELLOW}Command: $UVICORN_CMD${NC}"
echo ""

# Run uvicorn
if [ "$MODE" = "docker" ]; then
    # In Docker mode, run in foreground
    exec $UVICORN_CMD
else
    # In other modes, run with signal handling
    $UVICORN_CMD &
    UVICORN_PID=$!
    
    # Wait for the process
    wait $UVICORN_PID
fi