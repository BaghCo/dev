############################################################
# VARIABLES — override via terraform.tfvars or -var flags
############################################################
variable "resource_group_name" {
  type        = string
  description = "Name of the resource group for the alerts"
}

variable "location" {
  type        = string
  description = "Azure region for the scheduled-query rule resources"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource ID of your global Log Analytics workspace"
}

variable "action_group_id" {
  type        = string
  description = "Resource ID of the Action Group to call when an alert fires"
}

############################################################
# 1) DEFINE YOUR LOG-SEARCH ALERTS AS A LOCAL LIST
############################################################
locals {
  vm_log_alerts = [
    {
      alertRuleName        = "VMHighCPUAlert"
      alertRuleDisplayName = "VM High CPU Usage"
      alertRuleDescription = "Virtual machine CPU % > 85% over 15m"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Processor Information" and CounterName == "% Processor Time"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 85
      KQL
    },
    {
      alertRuleName        = "VMLowMemoryAlert"
      alertRuleDisplayName = "VM Low Memory"
      alertRuleDescription = "Virtual machine committed memory > 90% over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Memory" and CounterName == "% Committed Bytes In Use"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 90
      KQL
    },
    {
      alertRuleName        = "VMHighDataDiskReadLatencyAlert"
      alertRuleDisplayName = "VM High Data Disk Read Latency"
      alertRuleDescription = "Data disk read latency > 30ms over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleName        = "VMHighDataDiskWriteLatencyAlert"
      alertRuleDisplayName = "VM High Data Disk Write Latency"
      alertRuleDescription = "Data disk write latency > 30ms over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleName        = "VMLowDataDiskSpaceAlert"
      alertRuleDisplayName = "VM Low Data Disk Space"
      alertRuleDescription = "Data disk free space < 10% over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName != "_Total"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleName        = "VMHighOSDiskReadLatencyAlert"
      alertRuleDisplayName = "VM High OS Disk Read Latency"
      alertRuleDescription = "OS disk read latency > 30ms over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Read" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleName        = "VMHighOSDiskWriteLatencyAlert"
      alertRuleDisplayName = "VM High OS Disk Write Latency"
      alertRuleDescription = "OS disk write latency > 30ms over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "Avg. Disk sec/Write" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 0.03
      KQL
    },
    {
      alertRuleName        = "VMLowOSDiskSpaceAlert"
      alertRuleDisplayName = "VM Low OS Disk Space"
      alertRuleDescription = "OS disk free space < 10% over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "LogicalDisk" and CounterName == "% Free Space" and InstanceName == "C:"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue < 10
      KQL
    },
    {
      alertRuleName        = "VMHighNetworkInAlert"
      alertRuleDisplayName = "VM High Network In"
      alertRuleDescription = "Network in > 10 MB/s over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Received/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleName        = "VMHighNetworkOutAlert"
      alertRuleDisplayName = "VM High Network Out"
      alertRuleDescription = "Network out > 10 MB/s over 15m"
      alertRuleSeverity    = 2
      autoMitigate         = true
      evaluationFrequency  = "PT5M"
      windowDuration       = "PT15M"
      query = <<-KQL
        Perf
        | where ObjectName == "Network Interface" and CounterName == "Bytes Sent/sec"
        | summarize avg(CounterValue) by bin(TimeGenerated,5m), Computer
        | where avg_CounterValue > 10000000
      KQL
    },
    {
      alertRuleName        = "VMHeartBeatAlert"
      alertRuleDisplayName = "VM Heartbeat Missing"
      alertRuleDescription = "Fewer than 10 heartbeats in 6h"
      alertRuleSeverity    = 3
      autoMitigate         = true
      evaluationFrequency  = "PT1H"
      windowDuration       = "PT6H"
      query = <<-KQL
        Heartbeat
        | where TimeGenerated > ago(6h)
        | summarize Count = count() by Computer
        | where Count < 10
      KQL
    },
  ]
}

############################################################
# 2) CREATE A SCHEDULED-QUERY RULE FOR EACH ENTRY
############################################################
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "vm_log" {
  for_each            = { for r in local.vm_log_alerts : r.alertRuleName => r }
  name                = each.value.alertRuleName
  resource_group_name = var.resource_group_name
  location            = var.location

  description              = each.value.alertRuleDescription
  display_name             = each.value.alertRuleDisplayName
  severity                 = each.value.alertRuleSeverity
  enabled                  = true
  evaluation_frequency     = each.value.evaluationFrequency
  window_duration          = each.value.windowDuration
  scopes                   = [ var.log_analytics_workspace_id ]
  auto_mitigation_enabled  = each.value.autoMitigate
  skip_query_validation    = true

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [ var.action_group_id ]
  }
}
