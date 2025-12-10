#!/bin/bash

# Script to extract benchmark results as CSV from Criterion target directory
# Usage: ./extract_benchmark_csv.sh [target_dir]

# Set default target directory if not provided
TARGET_DIR="${1:-target/criterion}"

# Check if target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory $TARGET_DIR does not exist" >&2
    exit 1
fi

# Function to convert nanoseconds to seconds with proper formatting
ns_to_seconds() {
    local ns=$1
    printf "%.3f" "$(echo "scale=6; $ns / 1000000000" | bc -l)"
}

# Function to extract mean estimate from estimates.json
extract_mean() {
    local json_file=$1
    if [ -f "$json_file" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.mean.point_estimate' "$json_file"
        else
            grep -o '"point_estimate":[0-9.]*' "$json_file" | head -1 | sed 's/"point_estimate"://'
        fi
    else
        echo "0"
    fi
}

# Function to clean up benchmark names and categorize
clean_and_categorize() {
    local name=$1
    local category=""
    local clean_name=""
    
    if [[ "$name" == Traditional_* ]]; then
        category="Traditional"
        clean_name=$(echo "$name" | sed 's/Traditional_MLS_//' | sed 's/_/ /g')
    elif [[ "$name" == PQ_Conf_Auth_* ]]; then
        category="PQ Conf+Auth"
        clean_name=$(echo "$name" | sed 's/PQ_Conf_Auth_MLS_//' | sed 's/_/ /g')
    elif [[ "$name" == PQ_Conf_* ]]; then
        category="PQ Conf"
        clean_name=$(echo "$name" | sed 's/PQ_Conf_MLS_//' | sed 's/_/ /g')
    elif [[ "$name" == Hybrid_MLS_* ]]; then
        category="Hybrid"
        clean_name=$(echo "$name" | sed 's/Hybrid_MLS_//' | sed 's/_/ /g')
    elif [[ "$name" == Hybrid_Combiner_Conf_Auth* ]]; then
        category="Hybrid Combiner Auth"
        clean_name=$(echo "$name" | sed 's/Hybrid_Combiner_Conf_Auth_//' | sed 's/__/ + /g' | sed 's/_/ /g')
    elif [[ "$name" == Hybrid_Combiner_Conf* ]]; then
        category="Hybrid Combiner"
        clean_name=$(echo "$name" | sed 's/Hybrid_Combiner_Conf_//' | sed 's/__/ + /g' | sed 's/_/ /g')
    else
        category="Other"
        clean_name=$(echo "$name" | sed 's/_/ /g')
    fi
    
    echo "$category,$clean_name"
}

# CSV Header
echo "Category,Benchmark Name,Average Time (s)"

# Process each benchmark directory
for benchmark_dir in "$TARGET_DIR"/*; do
    if [ -d "$benchmark_dir" ]; then
        benchmark_name=$(basename "$benchmark_dir")
        
        # Skip the report directory
        if [ "$benchmark_name" = "report" ]; then
            continue
        fi
        
        # Check if this is a simple benchmark (single result)
        if [ -d "$benchmark_dir/2/new" ]; then
            estimates_file="$benchmark_dir/2/new/estimates.json"
            mean_ns=$(extract_mean "$estimates_file")
            if [ "$mean_ns" != "0" ] && [ -n "$mean_ns" ]; then
                mean_s=$(ns_to_seconds "$mean_ns")
                category_and_name=$(clean_and_categorize "$benchmark_name")
                echo "$category_and_name,$mean_s"
            fi
        else
            # This is a multi-parameter benchmark (like hybrid combiner with ratios)
            for sub_dir in "$benchmark_dir"/*; do
                if [ -d "$sub_dir" ] && [ "$(basename "$sub_dir")" != "report" ]; then
                    sub_name=$(basename "$sub_dir")
                    
                    # Check for nested structure (ratio_X_clients_Y/2/new/)
                    if [ -d "$sub_dir/2/new" ]; then
                        estimates_file="$sub_dir/2/new/estimates.json"
                        mean_ns=$(extract_mean "$estimates_file")
                        if [ "$mean_ns" != "0" ] && [ -n "$mean_ns" ]; then
                            mean_s=$(ns_to_seconds "$mean_ns")
                            category_and_name=$(clean_and_categorize "$benchmark_name")
                            category=$(echo "$category_and_name" | cut -d',' -f1)
                            base_name=$(echo "$category_and_name" | cut -d',' -f2)
                            clean_sub_name=$(echo "$sub_name" | sed 's/_/ /g')
                            full_name="$base_name ($clean_sub_name)"
                            echo "$category,\"$full_name\",$mean_s"
                        fi
                    fi
                fi
            done
        fi
    fi
done
