#!/bin/bash

#==============================================================================
# LLM Guard Service Management Script
#==============================================================================
#
# DESCRIPTION:
#   This script manages the LLM Guard Security Service for the ORBIT platform.
#   It provides a simple interface to start, stop, and check the status of the
#   FastAPI-based security service with different configurations for development,
#   production, or Docker environments.
#
# WHAT IT DOES:
#   1. Checks for required dependencies (Python, pip, virtual environment)
#   2. Ensures all Python packages are installed
#   3. Starts the uvicorn server in the background with appropriate settings
#   4. Allows stopping the background service
#   5. Allows checking the running status of the service
#
# CONFIGURATION:
#   All application settings (host, port, Redis URL, etc.) are loaded from
#   environment files (.env.local or .env) by the application itself.
#   This script only controls how the server runs, not what it serves.
#
# USAGE EXAMPLES:
#
#   # Start in production mode with default settings (background)
#   ./llm-guard.sh start
#
#   # Start in dev mode with auto-reload enabled (background)
#   ./llm-guard.sh start -m dev -r
#
#   # Start with 4 worker processes for high traffic (background)
#   ./llm-guard.sh start -w 4
#
#   # Start in Docker container mode (background)
#   ./llm-guard.sh start -m docker
#
#   # Stop the running service
#   ./llm-guard.sh stop
#
#   # Check if the service is running
#   ./llm-guard.sh status
#
#   # (You can also omit 'start' for default background start)
#   ./llm-guard.sh -m prod -w 2
#
# COMMANDS:
#   start      Start the service in the background (default if omitted)
#   stop       Stop the background service
#   status     Show service status
#
# OPTIONS (for start only):
#   -w, --workers NUM    Number of worker processes (default: 1)
#                        Note: Multiple workers improve performance but disable reload
#   -r, --reload         Enable auto-reload on code changes
#                        Note: Automatically enabled in development mode
#   -m, --mode MODE      Execution mode: dev|prod|docker
#                        - dev:         Single worker, auto-reload, verbose logging
#                        - prod:        Multiple workers, no reload, optimized
#                        - docker:      Container-optimized settings
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
MODE="prod"
PID_FILE="llm-guard-service.pid"
ACTION="start"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 [start|stop|status] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start                    Start the service in background (default)"
    echo "  stop                     Stop the background service"
    echo "  status                   Show service status"
    echo ""
    echo "Options (for start only):"
    echo "  -w, --workers NUM        Number of worker processes (default: 1)"
    echo "  -r, --reload             Enable auto-reload (development mode)"
    echo "  -m, --mode MODE          Run mode (dev|prod|docker) (default: prod)"
    echo "  --help                   Display this help message"
    echo ""
    echo "Examples:"
    echo "  ./llm-guard.sh start -m dev -r       # Start in dev mode with reload"
    echo "  ./llm-guard.sh stop                  # Stop the service"
    echo "  ./llm-guard.sh status                # Show status"
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

# Parse subcommand (start/stop/status)
if [[ "$1" =~ ^(start|stop|status)$ ]]; then
    ACTION="$1"
    shift
fi

# Only parse options for start
if [[ "$ACTION" == "start" ]]; then
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
fi

# Validate inputs (only for start)
if [[ "$ACTION" == "start" ]]; then
    if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || [ "$WORKERS" -lt 1 ]; then
        echo -e "${RED}Error: Invalid number of workers: $WORKERS${NC}"
        exit 1
    fi
    if [[ ! "$MODE" =~ ^(dev|prod|docker)$ ]]; then
        echo -e "${RED}Error: Invalid mode: $MODE${NC}"
        exit 1
    fi
fi

# Check if already running
if [[ "$ACTION" == "start" ]]; then
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo -e "${YELLOW}LLM Guard Service is already running (PID $PID)${NC}"
            exit 0
        else
            echo -e "${YELLOW}Removing stale PID file${NC}"
            rm -f "$PID_FILE"
        fi
    fi
fi

# Only start service if action is start
if [[ "$ACTION" == "start" ]]; then
    # Check dependencies
    check_dependencies

    # Build uvicorn command - let the app handle host/port from env
    UVICORN_CMD="uvicorn app.main:app"

    # Mode-specific settings
    case $MODE in
        dev)
            echo -e "${YELLOW}Starting in DEV mode${NC}"
            RELOAD="true"
            WORKERS="1"  # Force single worker in dev
            UVICORN_CMD="$UVICORN_CMD --host 0.0.0.0"
            ;;
        prod)
            echo -e "${GREEN}Starting in PROD mode${NC}"
            UVICORN_CMD="$UVICORN_CMD --host 0.0.0.0"
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

    # Disable uvicorn access logs to rely on application logging
    UVICORN_CMD="$UVICORN_CMD --no-access-log"

    # Display configuration
    echo ""
    echo -e "${GREEN}=== LLM Guard Service ===${NC}"
    echo "Mode: $MODE"
    echo "Workers: $WORKERS"
    echo "Auto-reload: $RELOAD"
    echo "Config: .env.local (or .env)"
    echo -e "${GREEN}=========================${NC}"
    echo ""

    # Start the service in background
    echo -e "${GREEN}Starting LLM Guard Service in background...${NC}"
    echo -e "${YELLOW}Command: $UVICORN_CMD${NC}"
    echo ""
    nohup $UVICORN_CMD > /dev/null 2>&1 &
    echo $! > "$PID_FILE"
    echo -e "${GREEN}Service started with PID $(cat $PID_FILE)${NC}"
    exit 0
fi

# Stop command
if [[ "$ACTION" == "stop" ]]; then
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo -e "${YELLOW}Stopping LLM Guard Service (PID $PID)...${NC}"
            kill $PID
            rm -f "$PID_FILE"
            echo -e "${GREEN}Service stopped${NC}"
        else
            echo -e "${YELLOW}Service not running, removing stale PID file${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${YELLOW}No PID file found. Service not running?${NC}"
    fi
    exit 0
fi

# Status command
if [[ "$ACTION" == "status" ]]; then
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo -e "${GREEN}LLM Guard Service is running (PID $PID)${NC}"
            exit 0
        else
            echo -e "${YELLOW}PID file exists but process not running. Removing stale PID file.${NC}"
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo -e "${YELLOW}LLM Guard Service is not running${NC}"
        exit 1
    fi
fi