############################################################
# VARIABLES — override via terraform.tfvars or -var flags
############################################################
variable "resource_group_name" {
  type        = string
  description = "Name of the resource group containing VM and DCR"
}

variable "location" {
  type        = string
  description = "Azure region for DCR and alerts"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource ID of your existing Log Analytics workspace"
}

variable "vm_resource_id" {
  type        = string
  description = "Resource ID of the Windows VM to monitor"
}

variable "action_group_id" {
  type        = string
  description = "Resource ID of the Action Group to fire on alerts"
}

############################################################
# 1) INSTALL AGENT & DATA COLLECTION RULE
############################################################
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = var.vm_resource_id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  settings                   = "{}"
}

resource "azurerm_monitor_data_collection_rule" "dcr" {
  name                = "windowsBaselineDCR"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Collect Windows baseline Perf counters and platform metrics"

  data_sources {
    # ─── Perf Counters ──────────────────────────────────────────────
    performance_counter {
      name                          = "windowsBaselinePerf"
      streams                       = ["Microsoft-Perf", "Microsoft-InsightsMetrics"]
      sampling_frequency_in_seconds = 60
      counter_specifiers = [
        # CPU
        "\\Processor Information(_Total)\\% Processor Time",
        "\\Processor Information(_Total)\\% Privileged Time",
        "\\Processor Information(_Total)\\% User Time",
        "\\System\\Processes",
        "\\System\\Processor Queue Length",

        # Memory
        "\\Memory\\Available Bytes",
        "\\Memory\\% Committed Bytes In Use",

        # Disk
        "\\LogicalDisk(_Total)\\% Disk Time",
        "\\LogicalDisk(_Total)\\Free Megabytes",
        "\\LogicalDisk(_Total)\\Avg. Disk sec/Read",
        "\\LogicalDisk(_Total)\\Avg. Disk sec/Write",

        # Network
        "\\Network Interface(*)\\Bytes Received/sec",
        "\\Network Interface(*)\\Bytes Sent/sec",
      ]
    }
  }

  destinations {
    log_analytics {
      name                  = "la"
      workspace_resource_id = var.log_analytics_workspace_id
    }
    # Optionally, to stream into Azure Monitor Metrics as well:
    # azure_monitor_metrics {
    #   name = "metricsDestination"
    # }
  }

  data_flow {
    streams      = ["Microsoft-Perf", "Microsoft-InsightsMetrics"]
    destinations = ["la"]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "assoc" {
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  resource_id             = var.vm_resource_id
}
