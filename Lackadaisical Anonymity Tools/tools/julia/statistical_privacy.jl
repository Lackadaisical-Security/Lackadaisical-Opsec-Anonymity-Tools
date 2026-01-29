#!/usr/bin/env julia

"""
Statistical Privacy Tools - Julia Implementation
Part of Lackadaisical Anonymity Toolkit

Implements differential privacy and statistical disclosure control
"""

using Random
using Statistics
using DataFrames
using CSV
using Distributions
using LinearAlgebra
using JSON

# Set random seed for reproducibility
Random.seed!(42)

"""
Laplace mechanism for differential privacy
"""
function laplace_mechanism(true_value::Real, sensitivity::Real, epsilon::Real)
    scale = sensitivity / epsilon
    noise = rand(Laplace(0, scale))
    return true_value + noise
end

"""
Gaussian mechanism for differential privacy
"""
function gaussian_mechanism(true_value::Real, sensitivity::Real, epsilon::Real, delta::Real)
    sigma = sensitivity * sqrt(2 * log(1.25 / delta)) / epsilon
    noise = rand(Normal(0, sigma))
    return true_value + noise
end

"""
Exponential mechanism for selecting from discrete outputs
"""
function exponential_mechanism(scores::Vector{Float64}, sensitivity::Real, epsilon::Real)
    probabilities = exp.((epsilon .* scores) ./ (2 * sensitivity))
    probabilities ./= sum(probabilities)
    
    # Sample from categorical distribution
    cumsum_probs = cumsum(probabilities)
    r = rand()
    return findfirst(x -> x >= r, cumsum_probs)
end

"""
Add differential privacy to query results
"""
struct DifferentialPrivacy
    epsilon::Float64
    delta::Float64
    
    function DifferentialPrivacy(epsilon::Float64, delta::Float64=1e-5)
        @assert epsilon > 0 "Epsilon must be positive"
        @assert 0 <= delta <= 1 "Delta must be between 0 and 1"
        new(epsilon, delta)
    end
end

"""
Private count query
"""
function private_count(data::Vector, dp::DifferentialPrivacy)
    true_count = length(data)
    sensitivity = 1.0  # Adding/removing one record changes count by 1
    return round(Int, laplace_mechanism(true_count, sensitivity, dp.epsilon))
end

"""
Private mean query
"""
function private_mean(data::Vector{<:Real}, bounds::Tuple{Real,Real}, dp::DifferentialPrivacy)
    true_mean = mean(data)
    sensitivity = (bounds[2] - bounds[1]) / length(data)
    return laplace_mechanism(true_mean, sensitivity, dp.epsilon)
end

"""
Private histogram
"""
function private_histogram(data::Vector, bins::Vector, dp::DifferentialPrivacy)
    # Count items in each bin
    counts = zeros(Int, length(bins) - 1)
    for i in 1:(length(bins) - 1)
        counts[i] = sum(bins[i] .<= data .< bins[i+1])
    end
    
    # Add noise to each bin
    sensitivity = 1.0
    epsilon_per_bin = dp.epsilon / length(counts)
    
    private_counts = [round(Int, max(0, laplace_mechanism(c, sensitivity, epsilon_per_bin))) 
                     for c in counts]
    
    return private_counts
end

"""
k-Anonymity implementation
"""
function k_anonymity(df::DataFrame, quasi_identifiers::Vector{Symbol}, k::Int)
    # Group by quasi-identifiers
    grouped = groupby(df, quasi_identifiers)
    
    # Filter groups with at least k records
    anonymized = DataFrame()
    
    for group in grouped
        if nrow(group) >= k
            append!(anonymized, group)
        end
    end
    
    return anonymized
end

"""
l-Diversity check
"""
function check_l_diversity(df::DataFrame, quasi_identifiers::Vector{Symbol}, 
                          sensitive_attr::Symbol, l::Int)
    grouped = groupby(df, quasi_identifiers)
    
    for group in grouped
        unique_values = length(unique(group[!, sensitive_attr]))
        if unique_values < l
            return false
        end
    end
    
    return true
end

"""
t-Closeness implementation
"""
function t_closeness(df::DataFrame, quasi_identifiers::Vector{Symbol}, 
                    sensitive_attr::Symbol, t::Float64)
    # Global distribution of sensitive attribute
    global_dist = proportions(df[!, sensitive_attr])
    
    grouped = groupby(df, quasi_identifiers)
    max_distance = 0.0
    
    for group in grouped
        if nrow(group) < 2
            continue
        end
        
        # Local distribution
        local_dist = proportions(group[!, sensitive_attr])
        
        # Calculate Earth Mover's Distance (simplified)
        distance = sum(abs.(values(global_dist) .- values(local_dist))) / 2
        max_distance = max(max_distance, distance)
    end
    
    return max_distance <= t
end

"""
Microaggregation for numerical attributes
"""
function microaggregation(data::Vector{Float64}, k::Int)
    n = length(data)
    sorted_indices = sortperm(data)
    aggregated = copy(data)
    
    # Process groups of size k
    for i in 1:k:n
        group_end = min(i + k - 1, n)
        group_indices = sorted_indices[i:group_end]
        
        # Replace with group mean
        group_mean = mean(data[group_indices])
        for idx in group_indices
            aggregated[idx] = group_mean
        end
    end
    
    return aggregated
end

"""
Add random noise for continuous variables
"""
function add_noise(data::Vector{Float64}, noise_level::Float64=0.1)
    std_dev = std(data) * noise_level
    noise = rand(Normal(0, std_dev), length(data))
    return data .+ noise
end

"""
Synthetic data generation using copulas
"""
function generate_synthetic_data(original_df::DataFrame, n_synthetic::Int)
    # Simple implementation - in practice would use copulas
    synthetic_df = DataFrame()
    
    for col in names(original_df)
        if eltype(original_df[!, col]) <: Number
            # For numeric columns, sample from fitted distribution
            col_data = original_df[!, col]
            mu, sigma = mean(col_data), std(col_data)
            synthetic_df[!, col] = rand(Normal(mu, sigma), n_synthetic)
        else
            # For categorical, sample from empirical distribution
            values = unique(original_df[!, col])
            probs = [count(==(v), original_df[!, col]) / nrow(original_df) for v in values]
            synthetic_df[!, col] = sample(values, Weights(probs), n_synthetic)
        end
    end
    
    return synthetic_df
end

"""
Privacy-preserving data release
"""
mutable struct PrivateDataRelease
    original_data::DataFrame
    epsilon_budget::Float64
    used_epsilon::Float64
    
    function PrivateDataRelease(data::DataFrame, total_epsilon::Float64)
        new(data, total_epsilon, 0.0)
    end
end

function release_statistics(pdr::PrivateDataRelease, queries::Vector{Symbol}, epsilon_per_query::Float64)
    results = Dict{Symbol, Any}()
    
    for query in queries
        if pdr.used_epsilon + epsilon_per_query > pdr.epsilon_budget
            @warn "Epsilon budget exceeded for query $query"
            continue
        end
        
        dp = DifferentialPrivacy(epsilon_per_query)
        
        if query == :count
            results[query] = private_count(pdr.original_data[!, 1], dp)
        elseif query == :mean_age
            age_data = pdr.original_data[!, :age]
            results[query] = private_mean(age_data, (0, 120), dp)
        elseif query == :histogram_income
            income_data = pdr.original_data[!, :income]
            bins = [0, 20000, 40000, 60000, 80000, 100000, Inf]
            results[query] = private_histogram(income_data, bins, dp)
        end
        
        pdr.used_epsilon += epsilon_per_query
    end
    
    results[:remaining_budget] = pdr.epsilon_budget - pdr.used_epsilon
    return results
end

"""
Utility metrics for privacy-preserved data
"""
function calculate_utility_loss(original::DataFrame, anonymized::DataFrame, 
                              columns::Vector{Symbol})
    utility_scores = Dict{Symbol, Float64}()
    
    for col in columns
        if eltype(original[!, col]) <: Number
            # For numeric: relative error in mean and variance
            orig_mean, anon_mean = mean(original[!, col]), mean(anonymized[!, col])
            orig_var, anon_var = var(original[!, col]), var(anonymized[!, col])
            
            mean_error = abs(orig_mean - anon_mean) / (abs(orig_mean) + 1e-10)
            var_error = abs(orig_var - anon_var) / (abs(orig_var) + 1e-10)
            
            utility_scores[col] = 1 - (mean_error + var_error) / 2
        else
            # For categorical: compare distributions
            orig_dist = proportions(original[!, col])
            anon_dist = proportions(anonymized[!, col])
            
            # Calculate total variation distance
            tvd = sum(abs.(values(orig_dist) .- values(anon_dist))) / 2
            utility_scores[col] = 1 - tvd
        end
    end
    
    return utility_scores
end

"""
Main CLI interface
"""
function main()
    if length(ARGS) == 0
        print_usage()
        return
    end
    
    command = ARGS[1]
    
    if command == "dp-query"
        # Differential privacy queries
        if length(ARGS) < 4
            println("Usage: dp-query <data.csv> <epsilon> <query_type>")
            return
        end
        
        data = CSV.read(ARGS[2], DataFrame)
        epsilon = parse(Float64, ARGS[3])
        query_type = ARGS[4]
        
        dp = DifferentialPrivacy(epsilon)
        
        if query_type == "count"
            result = private_count(data[!, 1], dp)
            println("Private count: $result")
        elseif query_type == "mean"
            col = Symbol(ARGS[5])
            bounds = (parse(Float64, ARGS[6]), parse(Float64, ARGS[7]))
            result = private_mean(data[!, col], bounds, dp)
            println("Private mean: $result")
        end
        
    elseif command == "k-anon"
        # K-anonymity
        if length(ARGS) < 4
            println("Usage: k-anon <data.csv> <k> <output.csv> <quasi_ids...>")
            return
        end
        
        data = CSV.read(ARGS[2], DataFrame)
        k = parse(Int, ARGS[3])
        output_file = ARGS[4]
        quasi_ids = Symbol.(ARGS[5:end])
        
        anonymized = k_anonymity(data, quasi_ids, k)
        CSV.write(output_file, anonymized)
        
        println("K-anonymized data saved to $output_file")
        println("Original records: $(nrow(data))")
        println("Anonymized records: $(nrow(anonymized))")
        println("Records suppressed: $(nrow(data) - nrow(anonymized))")
        
    elseif command == "synthetic"
        # Generate synthetic data
        if length(ARGS) < 4
            println("Usage: synthetic <data.csv> <n_records> <output.csv>")
            return
        end
        
        data = CSV.read(ARGS[2], DataFrame)
        n_synthetic = parse(Int, ARGS[3])
        output_file = ARGS[4]
        
        synthetic = generate_synthetic_data(data, n_synthetic)
        CSV.write(output_file, synthetic)
        
        println("Generated $n_synthetic synthetic records")
        println("Saved to $output_file")
        
    elseif command == "utility"
        # Calculate utility metrics
        if length(ARGS) < 3
            println("Usage: utility <original.csv> <anonymized.csv>")
            return
        end
        
        original = CSV.read(ARGS[2], DataFrame)
        anonymized = CSV.read(ARGS[3], DataFrame)
        
        columns = Symbol.(names(original))
        utility = calculate_utility_loss(original, anonymized, columns)
        
        println("Utility Scores (1.0 = perfect preservation):")
        for (col, score) in utility
            println("  $col: $(round(score, digits=3))")
        end
        
        avg_utility = mean(values(utility))
        println("\nAverage utility: $(round(avg_utility, digits=3))")
        
    else
        println("Unknown command: $command")
        print_usage()
    end
end

function print_usage()
    println("""
    Lackadaisical Statistical Privacy Tools
    ======================================
    
    Usage:
      dp-query <data.csv> <epsilon> <query_type> [params...]
        - Run differentially private queries
        - Query types: count, mean, histogram
      
      k-anon <data.csv> <k> <output.csv> <quasi_ids...>
        - Apply k-anonymity to dataset
      
      synthetic <data.csv> <n_records> <output.csv>
        - Generate synthetic data
      
      utility <original.csv> <anonymized.csv>
        - Calculate utility preservation metrics
    
    Examples:
      julia statistical_privacy.jl dp-query data.csv 1.0 count
      julia statistical_privacy.jl k-anon data.csv 5 anon.csv age gender zipcode
      julia statistical_privacy.jl synthetic data.csv 10000 synthetic.csv
    """)
end

# Utility functions
function proportions(v::Vector)
    counts = Dict{eltype(v), Int}()
    for item in v
        counts[item] = get(counts, item, 0) + 1
    end
    
    total = length(v)
    return Dict(k => v/total for (k, v) in counts)
end

# Run main if script is executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
