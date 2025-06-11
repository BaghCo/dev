############################################################
# VARIABLES — override via terraform.tfvars or -var flags
############################################################
variable "resource_group_name" {
  type        = string
  description = "Name of the resource group containing VM and alerts"
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
# 1) DATA COLLECTION RULE — Windows baseline Perf counters
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
  description         = "Collect Windows baseline Perf counters every 60s"

  data_sources {
    performance_counter {
      name                          = "windowsBaseline"
      streams                       = ["Microsoft-Perf"]
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

        # Disk (OS + data)
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
  }

  data_flow {
    streams      = ["Microsoft-Perf"]
    destinations = ["la"]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "assoc" {
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dcr.id
  resource_id             = var.vm_resource_id
}

############################################################
# 2) LOG‐SEARCH ALERTS (scheduled query rules v2)
############################################################
locals {
  vm_log_alerts = [
    {
      alertRuleDescription = "High CPU usage on virtual machine"
      alertRuleDisplayName = "VM High CPU Usage"
      alertRuleName        = "VMHighCPUAlert"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Processor Information" and CounterName == "% Processor Time"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 85
      KQL
    },
    {
      alertRuleDescription = "Low available memory on virtual machine"
      alertRuleDisplayName = "VM Low Memory"
      alertRuleName        = "VMLowMemoryAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Memory" and CounterName == "% Committed Bytes In Use"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 90
      KQL
    },
    {
      alertRuleDescription = "High data disk read latency on virtual machine"
      alertRuleDisplayName = "VM High Data Disk Read Latency"
      alertRuleName        = "VMHighDataDiskReadLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "High data disk write latency on virtual machine"
      alertRuleDisplayName = "VM High Data Disk Write Latency"
      alertRuleName        = "VMHighDataDiskWriteLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "Low data-disk free space on virtual machine"
      alertRuleDisplayName = "VM Low Data Disk Space"
      alertRuleName        = "VMLowDataDiskSpaceAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer, InstanceName
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleDescription = "High OS-disk read latency on virtual machine"
      alertRuleDisplayName = "VM High OS Disk Read Latency"
      alertRuleName        = "VMHighOSDiskReadLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "High OS-disk write latency on virtual machine"
      alertRuleDisplayName = "VM High OS Disk Write Latency"
      alertRuleName        = "VMHighOSDiskWriteLatencyAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleDescription = "Low OS-disk free space on virtual machine"
      alertRuleDisplayName = "VM Low OS Disk Space"
      alertRuleName        = "VMLowOSDiskSpaceAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleDescription = "High network ingress on virtual machine"
      alertRuleDisplayName = "VM High Network In"
      alertRuleName        = "VMHighNetworkInAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Received/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleDescription = "High network egress on virtual machine"
      alertRuleDisplayName = "VM High Network Out"
      alertRuleName        = "VMHighNetworkOutAlert"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Sent/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleDescription = "Agent heartbeat missing on virtual machine"
      alertRuleDisplayName = "VM Heartbeat Alert"
      alertRuleName        = "VMHeartBeatAlert"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowSize           = "PT6H"
      query = <<-KQL
        Heartbeat
        | where TimeGenerated > ago(6h)
        | summarize Count = count() by Computer
        | where Count < 10
      KQL
    },
  ]
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "vm_log" {
  for_each            = { for r in local.vm_log_alerts : r.alertRuleName => r }
  name                = each.value.alertRuleName
  resource_group_name = var.resource_group_name
  location            = var.location

  description   = each.value.alertRuleDescription
  display_name  = each.value.alertRuleDisplayName
  severity      = each.value.alertRuleSeverity
  enabled       = true
  auto_mitigate = each.value.autoMitigate
  frequency     = each.value.evaluationFrequency
  window_size   = each.value.windowSize

  criteria {
    query            = each.value.query
    time_aggregation = "Count"
  }

  action {
    azurerm_action_group_id = var.action_group_id
  }
}

############################################################
# 3) METRIC ALERTS — static & dynamic thresholds
############################################################
locals {
  vm_metric_alerts_static = [
    {
      alertRuleName        = "AvailableMemoryBytesAlert"
      alertRuleDisplayName = "VM Available Memory Bytes"
      alertRuleDescription = "Low available memory bytes on VM"
      alertRuleSeverity    = 2
      autoMitigate         = false
      evaluationFrequency  = "PT1M"
      windowSize           = "PT5M"
      metricName           = "Available Memory Bytes"
      metricNamespace      = "Microsoft.Compute/virtualMachines"
      operator             = "LessThan"
      threshold            = 1000000000
      timeAggregation      = "Average"
    },
  ]

  vm_metric_alerts_dynamic = [
    {
      alertRuleName        = "VMDataDiskReadOpsDynamic"
      alertRuleDisplayName = "VM Data Disk Read Ops Anomaly"
      alertRuleDescription = "Anomalous data disk read I/O on VM"
      alertRuleSeverity    = 2
      autoMitigate         = false
      evaluationFrequency  = "PT5M"
      windowSize           = "PT5M"
      metricName           = "Disk Read Operations/Sec"
      metricNamespace      = "Microsoft.Compute/virtualMachines"
      operator             = "GreaterOrLessThan"
      timeAggregation      = "Average"
      dynamicSettings = {
        sensitivity                   = "Low"
        minFailingPeriodsToAlert      = 4
        numberOfEvaluationPeriods     = 4
      }
    },
    {
      alertRuleName        = "VMDataDiskWriteOpsDynamic"
      alertRuleDisplayName = "VM Data Disk Write Ops Anomaly"
      alertRuleDescription = "Anomalous data disk write I/O on VM"
      alertRuleSeverity    = 2
      autoMitigate         = false
      evaluationFrequency  = "PT5M"
      windowSize           = "PT5M"
      metricName           = "Disk Write Operations/Sec"
      metricNamespace      = "Microsoft.Compute/virtualMachines"
      operator             = "GreaterOrLessThan"
      timeAggregation      = "Average"
      dynamicSettings = {
        sensitivity                   = "Low"
        minFailingPeriodsToAlert      = 4
        numberOfEvaluationPeriods     = 4
      }
    },
  ]
}

# Static‐threshold metric alert
resource "azurerm_monitor_metric_alert" "vm_static_metric" {
  for_each            = { for r in local.vm_metric_alerts_static      : r.alertRuleName => r }
  name                = each.value.alertRuleName
  resource_group_name = var.resource_group_name
  scopes              = [ var.vm_resource_id ]

  description   = each.value.alertRuleDescription
  severity      = each.value.alertRuleSeverity
  enabled       = true
  auto_mitigate = each.value.autoMitigate

  frequency     = each.value.evaluationFrequency
  window_size   = each.value.windowSize

  criteria {
    metric_namespace = each.value.metricNamespace
    metric_name      = each.value.metricName
    aggregation      = each.value.timeAggregation
    operator         = each.value.operator
    threshold        = each.value.threshold
  }

  action {
    azurerm_action_group_id = var.action_group_id
  }
}

# Dynamic‐threshold metric alerts
resource "azurerm_monitor_metric_alert" "vm_dynamic_metric" {
  for_each            = { for r in local.vm_metric_alerts_dynamic     : r.alertRuleName => r }
  name                = each.value.alertRuleName
  resource_group_name = var.resource_group_name
  scopes              = [ var.vm_resource_id ]

  description   = each.value.alertRuleDescription
  severity      = each.value.alertRuleSeverity
  enabled       = true
  auto_mitigate = each.value.autoMitigate

  frequency     = each.value.evaluationFrequency
  window_size   = each.value.windowSize

  criteria {
    metric_namespace = each.value.metricNamespace
    metric_name      = each.value.metricName
    aggregation      = each.value.timeAggregation
    operator         = each.value.operator

    dynamic_criteria {
      sensitivity = each.value.dynamicSettings.sensitivity

      failing_periods {
        min_failing_periods_to_alert = each.value.dynamicSettings.minFailingPeriodsToAlert
        number_of_evaluation_periods = each.value.dynamicSettings.numberOfEvaluationPeriods
      }
    }
  }

  action {
    azurerm_action_group_id = var.action_group_id
  }
}
