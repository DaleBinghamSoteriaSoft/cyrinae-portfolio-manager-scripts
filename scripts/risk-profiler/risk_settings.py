RISK_SETTINGS = {
    "maxChecklistOpenHighVulnLowRisk": 20,
    "maxChecklistOpenHighVulnMediumRisk": 50,
    "maxChecklistOpenMediumVulnLowRisk": 100,
    "maxChecklistOpenMediumVulnMediumRisk": 200,
    "maxChecklistOpenLowVulnLowRisk": 100,
    "maxChecklistOpenLowVulnMediumRisk": 200,
    "maxChecklistNotReviewedHighVulnLowRisk": 100,
    "maxChecklistNotReviewedHighVulnMediumRisk": 502,
    "maxPatchOpenCriticalVulnLowRisk": 0,
    "maxPatchOpenCriticalVulnMediumRisk": 1,
    "maxPatchOpenHighVulnLowRisk": 0,
    "maxPatchOpenHighVulnMediumRisk": 5,
    "maxPatchOpenMediumVulnLowRisk": 0,
    "maxPatchOpenMediumVulnMediumRisk": 5,
    "maxPatchOpenLowVulnLowRisk": 0,
    "maxPatchOpenLowVulnMediumRisk": 5,
    
    "minCompliancePercentOpenHighRisk": 50,
    "minCompliancePercentCompleteHighRisk": 50,
    "minCompliancePercentCompleteMediumRisk": 75,
    "minCompliancePercentCompleteLowRisk": 90,
    "allowedCompliancePercentCompleteZero": false, # if they hit this, it is HIGH
    "allowedCompliancePercentOpenZero": false, # if they hit this, it is HIGH
    "allowedScheduledCompletionPastDue": false, # if they hit this, it is HIGH
}