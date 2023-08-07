# TODO:
# Do we want to use this to create another json file?
# Maybe something that maps GPOs and their findings to affected users

# alternately, we could add yet another field to GPOs to illustrate finding impacts
# If we're not using some kind of DB might be fine to use this

# Note: probably best to use a different JSON file that just specifies information 
# that will be useful in reporting.

# Scoutsuite uses a schema that looks something like:
# a map of findings for each AWS service

"""
 "iam-managed-policy-allows-full-privileges": {
    "checked_items": 11,
    "compliance": [
        {
            "name": "CIS Amazon Web Services Foundations",
            "reference": "1.24",
            "version": "1.1.0"
        },
        {
            "name": "CIS Amazon Web Services Foundations",
            "reference": "1.22",
            "version": "1.2.0"
        }
    ],
    "dashboard_name": "Statements",
    "description": "Managed Policy Allows All Actions",
    "display_path": "iam.policies.id",
    "flagged_items": 1,
    "items": [
        "iam.policies.ANPAIWMBCKSKIEE64ZLYK.PolicyDocument.Statement.0"
    ],
    "level": "danger",
    "path": "iam.policies.id.PolicyDocument.Statement.id",
    "rationale": "Providing full privileges instead of restricting to the minimum set of permissions that the principal requires exposes the resources to potentially unwanted actions.",
    "references": [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "https://aws.amazon.com/blogs/security/back-to-school-understanding-the-iam-policy-grammar/"
    ],
    "remediation": "Ensure no managed policies are configured with <samp>Effect: Allow</samp>, <samp>Action: *</samp> and <samp>Resource: *</samp>",
    "service": "IAM"
},
"""

# Similarly, we can map findings (potentially across categories), then set up a map of findings
# to each of these along a similar schema.

# This would probably involve iterating over each finding and doing a query over our data
# to see if it's present (TODO: check how scoutsuite does this, see if there's some better algorithm)

# ---- 
# 
# ScoutSuite collects findings as a directory of JSON files 