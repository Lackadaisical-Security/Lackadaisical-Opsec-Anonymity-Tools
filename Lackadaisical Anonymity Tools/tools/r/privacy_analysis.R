#!/usr/bin/env Rscript

# Privacy Analysis Tools - R Implementation
# Part of Lackadaisical Anonymity Toolkit

# Load required packages
library(sdcMicro)
library(dplyr)
library(tidyr)
library(readr)
library(jsonlite)

# Privacy Risk Assessment
assess_privacy_risk <- function(data, quasi_identifiers, sensitive_attrs = NULL) {
  cat("Privacy Risk Assessment\n")
  cat("======================\n\n")
  
  # Create sdcMicro object
  sdc_obj <- createSdcObj(
    dat = data,
    keyVars = quasi_identifiers,
    sensibleVar = sensitive_attrs
  )
  
  # Calculate risk measures
  cat("1. Individual Risk:\n")
  individual_risk <- sdc_obj@risk$individual
  cat(sprintf("   Mean risk: %.4f\n", mean(individual_risk[,1])))
  cat(sprintf("   Max risk: %.4f\n", max(individual_risk[,1])))
  cat(sprintf("   Records with risk > 0.1: %d (%.2f%%)\n",
              sum(individual_risk[,1] > 0.1),
              100 * sum(individual_risk[,1] > 0.1) / nrow(data)))
  
  # K-anonymity
  cat("\n2. K-Anonymity:\n")
  freqs <- freqCalc(data, keyVars = quasi_identifiers)
  k_anon <- min(freqs$fk)
  cat(sprintf("   Minimum k: %d\n", k_anon))
  cat(sprintf("   Records violating k=5: %d (%.2f%%)\n",
              sum(freqs$fk < 5),
              100 * sum(freqs$fk < 5) / nrow(data)))
  
  # L-diversity
  if (!is.null(sensitive_attrs)) {
    cat("\n3. L-Diversity:\n")
    for (sens_var in sensitive_attrs) {
      l_div <- ldiversity(data, keyVars = quasi_identifiers, 
                         sensibleVar = sens_var)
      cat(sprintf("   %s: minimum l = %d\n", sens_var, l_div))
    }
  }
  
  # Utility metrics
  cat("\n4. Utility Metrics:\n")
  cat(sprintf("   Number of quasi-identifiers: %d\n", length(quasi_identifiers)))
  cat(sprintf("   Total combinations: %d\n", nrow(unique(data[quasi_identifiers]))))
  
  return(sdc_obj)
}

# Anonymization Functions
anonymize_data <- function(data, quasi_identifiers, sensitive_attrs = NULL, 
                          k_threshold = 5, method = "microaggregation") {
  
  # Create sdcMicro object
  sdc_obj <- createSdcObj(
    dat = data,
    keyVars = quasi_identifiers,
    sensibleVar = sensitive_attrs
  )
  
  # Apply anonymization based on method
  if (method == "microaggregation") {
    # Microaggregation for numerical variables
    num_vars <- names(data)[sapply(data, is.numeric)]
    num_vars <- intersect(num_vars, quasi_identifiers)
    
    if (length(num_vars) > 0) {
      sdc_obj <- microaggregation(sdc_obj, variables = num_vars, 
                                 aggr = k_threshold)
    }
  } else if (method == "recoding") {
    # Global recoding for categorical variables
    cat_vars <- names(data)[!sapply(data, is.numeric)]
    cat_vars <- intersect(cat_vars, quasi_identifiers)
    
    for (var in cat_vars) {
      sdc_obj <- globalRecode(sdc_obj, variable = var)
    }
  } else if (method == "local_suppression") {
    # Local suppression
    sdc_obj <- localSuppression(sdc_obj, k = k_threshold)
  }
  
  # Add noise to continuous variables
  num_vars <- names(data)[sapply(data, is.numeric)]
  num_vars <- setdiff(num_vars, quasi_identifiers)
  
  for (var in num_vars) {
    sdc_obj <- addNoise(sdc_obj, variables = var, noise = 0.1)
  }
  
  return(sdc_obj)
}

# Synthetic Data Generation
generate_synthetic_data <- function(data, method = "cart", k = 5) {
  
  # Remove any identifiers
  data_clean <- data %>%
    select(-any_of(c("id", "ID", "name", "email", "phone")))
  
  # Generate synthetic data
  if (method == "cart") {
    syn_data <- syn(data_clean, method = "cart", k = k)
  } else if (method == "parametric") {
    syn_data <- syn(data_clean, method = "parametric", k = k)
  } else if (method == "sample") {
    syn_data <- syn(data_clean, method = "sample", k = k)
  }
  
  return(syn_data$syn)
}

# Privacy-Preserving Analytics
differential_privacy_mean <- function(values, epsilon = 1.0, sensitivity = NULL) {
  n <- length(values)
  true_mean <- mean(values)
  
  # Calculate sensitivity if not provided
  if (is.null(sensitivity)) {
    sensitivity <- (max(values) - min(values)) / n
  }
  
  # Add Laplace noise
  scale <- sensitivity / epsilon
  noise <- rlaplace(1, location = 0, scale = scale)
  
  private_mean <- true_mean + noise
  
  return(list(
    true_mean = true_mean,
    private_mean = private_mean,
    noise = noise,
    epsilon = epsilon
  ))
}

# Generate privacy report
generate_privacy_report <- function(original_data, anonymized_data, 
                                  quasi_identifiers, sensitive_attrs = NULL,
                                  output_file = "privacy_report.html") {
  
  # Start HTML report
  report <- c(
    "<html><head><title>Privacy Analysis Report</title>",
    "<style>",
    "body { font-family: Arial, sans-serif; margin: 40px; }",
    "table { border-collapse: collapse; width: 100%; margin: 20px 0; }",
    "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
    "th { background-color: #4CAF50; color: white; }",
    ".warning { color: #ff9800; }",
    ".danger { color: #f44336; }",
    ".success { color: #4CAF50; }",
    "</style></head><body>",
    "<h1>Lackadaisical Privacy Analysis Report</h1>",
    paste0("<p>Generated: ", Sys.time(), "</p>")
  )
  
  # Dataset overview
  report <- c(report,
    "<h2>Dataset Overview</h2>",
    "<table>",
    paste0("<tr><td>Original Records</td><td>", nrow(original_data), "</td></tr>"),
    paste0("<tr><td>Anonymized Records</td><td>", nrow(anonymized_data), "</td></tr>"),
    paste0("<tr><td>Quasi-identifiers</td><td>", paste(quasi_identifiers, collapse=", "), "</td></tr>"),
    paste0("<tr><td>Sensitive Attributes</td><td>", 
           ifelse(is.null(sensitive_attrs), "None", paste(sensitive_attrs, collapse=", ")), "</td></tr>"),
    "</table>"
  )
  
  # Risk assessment
  orig_risk <- assess_privacy_risk(original_data, quasi_identifiers, sensitive_attrs)
  anon_risk <- assess_privacy_risk(anonymized_data, quasi_identifiers, sensitive_attrs)
  
  report <- c(report,
    "<h2>Risk Comparison</h2>",
    "<table>",
    "<tr><th>Metric</th><th>Original</th><th>Anonymized</th><th>Change</th></tr>",
    sprintf("<tr><td>Mean Individual Risk</td><td>%.4f</td><td>%.4f</td><td class='%s'>%.1f%%</td></tr>",
            mean(orig_risk@risk$individual[,1]),
            mean(anon_risk@risk$individual[,1]),
            ifelse(mean(anon_risk@risk$individual[,1]) < mean(orig_risk@risk$individual[,1]), "success", "danger"),
            100 * (mean(anon_risk@risk$individual[,1]) - mean(orig_risk@risk$individual[,1])) / mean(orig_risk@risk$individual[,1])
    ),
    "</table>"
  )
  
  # Information loss
  info_loss <- calculate_information_loss(original_data, anonymized_data, quasi_identifiers)
  
  report <- c(report,
    "<h2>Information Loss</h2>",
    "<table>",
    sprintf("<tr><td>Overall Information Loss</td><td>%.2f%%</td></tr>", info_loss$overall * 100),
    "</table>"
  )
  
  # Close report
  report <- c(report, "</body></html>")
  
  # Write to file
  writeLines(report, output_file)
  cat(paste0("Privacy report saved to: ", output_file, "\n"))
}

# Calculate information loss
calculate_information_loss <- function(original, anonymized, vars) {
  losses <- sapply(vars, function(var) {
    if (is.numeric(original[[var]])) {
      # For numeric variables, use variance ratio
      1 - var(anonymized[[var]]) / var(original[[var]])
    } else {
      # For categorical, use entropy ratio
      orig_entropy <- entropy(table(original[[var]]))
      anon_entropy <- entropy(table(anonymized[[var]]))
      1 - anon_entropy / orig_entropy
    }
  })
  
  return(list(
    by_variable = losses,
    overall = mean(losses)
  ))
}

# Entropy calculation
entropy <- function(x) {
  p <- x / sum(x)
  p <- p[p > 0]
  -sum(p * log2(p))
}

# Laplace distribution
rlaplace <- function(n, location = 0, scale = 1) {
  u <- runif(n, -0.5, 0.5)
  location - scale * sign(u) * log(1 - 2 * abs(u))
}

# Main function
main <- function() {
  if (is.null(opt$input) || is.null(opt$analysis)) {
    print_help(opt_parser)
    quit(status = 1)
  }
  
  # Read data
  data <- read_data(opt$input)
  
  # Parse quasi-identifiers
  quasi_ids <- strsplit(opt$quasi, ",")[[1]]
  sensitive <- if (!is.null(opt$sensitive)) strsplit(opt$sensitive, ",")[[1]] else NULL
  
  # Perform analysis
  if (opt$analysis == "risk") {
    assess_privacy_risk(data, quasi_ids, sensitive)
    
  } else if (opt$analysis == "anonymize") {
    sdc_obj <- anonymize_data(data, quasi_ids, sensitive, 
                             k_threshold = opt$k_anon)
    anon_data <- extractManipData(sdc_obj)
    
    if (!is.null(opt$output)) {
      write_csv(anon_data, opt$output)
      cat(paste0("Anonymized data saved to: ", opt$output, "\n"))
    }
    
    # Generate report
    generate_privacy_report(data, anon_data, quasi_ids, sensitive)
    
  } else if (opt$analysis == "synthetic") {
    syn_data <- generate_synthetic_data(data)
    
    if (!is.null(opt$output)) {
      write_csv(syn_data, opt$output)
      cat(paste0("Synthetic data saved to: ", opt$output, "\n"))
    }
    
  } else if (opt$analysis == "quality") {
    # Compare utility between original and anonymized
    anon_data <- read_data(opt$output)
    info_loss <- calculate_information_loss(data, anon_data, quasi_ids)
    
    cat("\nInformation Loss by Variable:\n")
    for (i in seq_along(info_loss$by_variable)) {
      cat(sprintf("  %s: %.2f%%\n", 
                  names(info_loss$by_variable)[i], 
                  info_loss$by_variable[i] * 100))
    }
    cat(sprintf("\nOverall Information Loss: %.2f%%\n", info_loss$overall * 100))
  }
}

# Run main function
if (!interactive()) {
  main()
}