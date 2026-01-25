#!/bin/bash

# Check if the file exists
if [ ! -f "working_ips.txt" ]; then
    echo "Error: working_ips.txt not found!"
    exit 1
fi

# Extract the 3rd column (IP), remove potential whitespace, and join with commas
ips=$(awk -F '|' '{print $3}' working_ips.txt | sed 's/ //g' | paste -sd "," -)

# Output to terminal
echo "$ips"

# Optional: Save to a file
echo "$ips" > formatted_ips.txt