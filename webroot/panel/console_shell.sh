#!/bin/sh
# Persistent shell wrapper for console
# This script maintains a persistent shell session

SESSION_ID="$1"
CWD="$2"
PIPE_DIR="/tmp/console_${SESSION_ID}"

# Create pipe directory
mkdir -p "$PIPE_DIR"

# Create communication files
CMD_FILE="$PIPE_DIR/cmd"
OUT_FILE="$PIPE_DIR/out"
ERR_FILE="$PIPE_DIR/err"
PID_FILE="$PIPE_DIR/pid"

# Change to initial directory
cd "$CWD" 2>/dev/null || cd "$HOME"

# Write PID immediately (before loop)
echo $$ > "$PID_FILE"

# Trap signals to cleanup
trap 'rm -f "$PID_FILE"; exit' INT TERM EXIT

# Main loop: read commands from file and execute in persistent shell context
while true; do
    # Wait for command file to be created/updated
    if [ -f "$CMD_FILE" ] && [ -s "$CMD_FILE" ]; then
        # Read command (first line only, trim whitespace)
        COMMAND=$(head -n 1 "$CMD_FILE" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        if [ -n "$COMMAND" ]; then
            # Clear output files first
            > "$OUT_FILE"
            > "$ERR_FILE"
            rm -f "$PIPE_DIR/done"
            
            # Clear command file (so we don't re-execute)
            > "$CMD_FILE"
            
            # Execute command in current shell context (maintains environment, cwd, etc.)
            # Use eval to maintain shell state (cd, export, etc. persist)
            # Redirect both stdout and stderr, and capture exit code
            # Use exec to ensure proper redirection
            (eval "$COMMAND") > "$OUT_FILE" 2> "$ERR_FILE"
            EXIT_CODE=$?
            
            # Write exit code to output if non-zero
            if [ $EXIT_CODE -ne 0 ]; then
                echo "[Exit code: $EXIT_CODE]" >> "$ERR_FILE"
            fi
            
            # Signal completion (create a marker file)
            touch "$PIPE_DIR/done"
        fi
        
        # Small delay to prevent busy loop
        sleep 0.05
    else
        # Small delay if no command
        sleep 0.1
    fi
    
    # Check if we should exit (if PID file is removed)
    if [ ! -f "$PID_FILE" ]; then
        break
    fi
done

