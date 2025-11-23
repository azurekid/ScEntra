# Breaking the Tenant: How Directory.ReadWrite.All Opens the Door to Global Admin

Every few weeks I run an internal red-team rehearsal where someone inevitably says, “Directory.ReadWrite.All just lets you edit users.” That assumption is how tenants fall. This single Graph application permission lets you mint secrets for **any** service principal, including the ones already wearing Global Administrator. Once you add a credential, you inherit every role that principal has. No phishing. No MFA prompts. Just an API call.

## A Forgotten Permission with Tier-Zero Reach

The path is painfully short:

1. **Compromise an app already holding Directory.ReadWrite.All.** Think legacy automation, a vendor connector, or a lab tenant that drifted into production.
2. **Call `POST /servicePrincipals/{id}/addPassword`.** Microsoft’s own docs list Directory.ReadWrite.All as a valid application scope for that endpoint. No extra roles, no conditional access exceptions.
3. **Swap the new secret for a client_credentials token.** You now **are** the target app.
4. **Ride the inherited roles.** If the victim service principal has Global Admin, the `roles` claim in your token includes it. Same story for Privileged Role Administrator, Intune Admin, or anything else assigned.

That’s the entire kill chain. Consent lives on the service principal object, not on the credential. Change the credential, you hijack the consent.

## Field Notes from Real Environments

While building the ScEntra sample data set I stumbled over several “double-privilege” service principals. Two looked eerily familiar:

- **Device Management Platform** (ID `02fae85f-3f4e-4b9f-a841-ef710c8df650`) held Global Administrator and Graph scopes like `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All`, and `Application.ReadWrite.All`.
- **HR Integration Service** (ID `82a0ae81-55a2-451c-b149-ceb9082f1317`) mixed Privileged Role Administrator with `Application.ReadWrite.All` and `User.ReadWrite.All`.

They read like anonymized versions of incidents I investigated this year:

### MSP Automation Account
An MSP built a provisioning script six years ago and gave it Directory.ReadWrite.All “temporarily.” Later, someone granted the same app Global Administrator so it could toggle licensing. During a penetration test we compromised the automation host, ran `addPassword`, and owned the tenant in under half an hour. The only log entry was “Add application password.” Nobody received an alert.

### Legacy HR Connector
Another customer synced HR data with Entra. The connector had Directory.ReadWrite.All from a migration project and later gained Privileged Role Administrator to automate PIM activations. A developer stored the client secret in plain text on a laptop. When that machine was stolen, the thief didn’t need to escalate anything—`addPassword` turned the connector into a skeleton key for every privileged role in the estate.

Every story follows the same curve: Directory.ReadWrite.All lets you tamper with **other** service principals, and privileged roles follow credentials.

## “Can’t We Just Use a Smaller Scope?”

The only lighter application permission that can still add credentials is `Application.ReadWrite.All`. The [servicePrincipal:addPassword documentation](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword?view=graph-rest-1.0&tabs=http#permissions) explicitly lists both scopes for app-only flows. Application.ReadWrite.All doesn’t let you rewrite user objects, but it still lets you manage **any** service principal—including the ones with Global Admin. So yes, you reduce blast radius slightly, but you’re still handing attackers a credential-minting machine. Treat both permissions as tier-zero.

## The Ownership Myth

A common misunderstanding: “We’ll make App A the owner of App B and rely on `Application.ReadWrite.OwnedBy` so App A can rotate B’s secrets.” That trick doesn’t work. `Application.ReadWrite.OwnedBy` is a **delegated** permission. It only shows up in tokens for actual users (or on-behalf-of flows) who are listed as owners. Service principals can’t request it via client_credentials, even if you mark them as owners in the portal. So no, an app registration can’t own another app registration and quietly escalate with that scope. If you want full automation, you’ll still end up granting Application.ReadWrite.All or Directory.ReadWrite.All—and we’re back where we started.

## “Fine, I’ll Just Assign More Permissions via Graph”

Directory.ReadWrite.All does **not** let you grant new Graph permissions to other apps or to users. Those APIs enforce their own heavy scopes:

- `POST /servicePrincipals/{id}/appRoleAssignments` requires `AppRoleAssignment.ReadWrite.All`.
- `POST /directoryRoles/{role-id}/members/$ref` requires `RoleManagement.ReadWrite.Directory`.

You still need those permissions if you want to change app roles or directory role membership. Unfortunately you don’t need them to take over an existing privileged app—you just change its password and reuse the roles it already owns.

## How to Spot the Attack

What I look for in customer tenants:

- **Audit events titled “Add application password.”** That’s the Graph `addPassword` call. If you didn’t approve it, assume compromise.
- **Unusual client_credentials volume.** A privileged service principal that normally runs once per hour suddenly authenticates every minute.
- **Service principals combining Graph tier-zero scopes and Entra roles.** Those objects are eligible for hijacking and should live on their own detection list.

## Containment Playbook

1. **Strip Directory.ReadWrite.All wherever possible.** Replace it with resource-scoped permissions (`User.ReadWrite.All`, `Group.Read.All`, etc.).
2. **Keep privileged roles and Graph write scopes apart.** If an automation account truly needs Global Admin, it should not also have Directory.ReadWrite.All.
3. **Rotate secrets when you remove scopes.** Attackers may already have created hidden credentials. Delete every credential on the service principal, recreate only the ones you trust, and verify the timestamps.
4. **Alert on `addPassword` immediately.** Treat every new credential on a privileged app as a security incident unless it happened in a documented change window.

## Final Thought

Graph permissions often feel abstract, so people underestimate them. Directory.ReadWrite.All isn’t just “write users”—it’s “write **the apps that run your tenant**.” Once that door opens, Global Administrator is two API calls away. Audit the service principals in your environment, purge the broad scopes, and monitor every credential change. The alternative is learning about this attack from somebody else’s incident report.
