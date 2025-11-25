# ScEntra: Why I Built a PowerShell Module to Map Entra Identity Risk

*By Rogier Dijkman*

I've spent enough time in Entra ID consoles to know the feeling: you're halfway through a security review, cross-referencing role assignments across three different Graph queries, and you realize the "clean" tenant you were promised has a service principal sitting two hops away from Global Administrator. The customer didn't lie—they just had no visibility into the chain.

That gap is why ScEntra exists. I needed a tool that could walk into any Entra tenant, pull every identity thread that matters, trace the relationships between users, groups, apps, and roles, then hand me something I could actually show people. Not a CSV dump. Not a raw Graph response. A map.

## What ScEntra Actually Does

At its core, ScEntra is an orchestration layer over Microsoft Graph. When you run `Invoke-ScEntraAnalysis`, it:

1. **Collects the inventory** – every user, group, service principal, and app registration, enriched with ownership data, creation dates, PIM flags, and whether a group can be assigned to roles.

2. **Enumerates privilege** – direct role assignments plus every PIM schedule, both eligibility and active assignments, normalized so they look the same in the output.

3. **Builds a graph** – nodes for identities, edges for memberships and ownership, with special nodes representing API permissions that workload identities carry.

4. **Analyzes escalation paths** – walks the graph to find privilege chains: "User A owns App B, which has `RoleManagement.ReadWrite.Directory`, which can activate PIM on Group C, which holds Global Administrator."

5. **Spits out HTML + JSON** – the HTML loads an interactive visualization you can filter and explore; the JSON captures everything so you can diff it later or pipe it into other tooling.

That's the mechanical answer. The real answer is that ScEntra turns "I wonder if we have a problem" into "here's the exact path an attacker would take, and here's who to call."

## Why I Wrote It

I got tired of stitching together Graph queries by hand. Every review followed the same pattern: pull users, pull groups, check memberships, check owners, fetch service principals, enumerate their permissions, cross-reference role assignments, hunt for PIM schedules, then try to explain it all in PowerPoint. Half the time I'd miss a nested group or forget that a particular app registration had `AppRoleAssignment.ReadWrite.All` buried in its manifest.

ScEntra automates the boring parts and does the correlation I used to do in my head. It knows that a user owning an app matters more when that app has dangerous permissions. It flags PIM-enabled groups that are also role-assignable because that's a shortcut to privileged access. It highlights service principals with `PrivilegedAccess.ReadWrite.AzureAD` because those can rewrite PIM itself.

The first time I ran it on a production tenant, it surfaced three escalation paths the customer didn't know existed. One involved a managed identity for a Logic App that had Directory.ReadWrite.All—totally valid for the workflow it supported, but nobody had documented that it could also modify admin accounts. The graph made that connection visible in seconds.

## How the Report Works

When you open the HTML report, you see a node-and-edge graph rendered with Vis.js. Users are circles, groups are boxes (diamonds if they're PIM-enabled), service principals are hexagons, API permissions get their own shape. High-privilege roles—Global Administrator, Privileged Role Administrator—are highlighted so you can trace backwards to see who can reach them.

Hover any node and a tooltip shows the details: if it's a group, you see the owners and whether it's role-assignable. If it's a service principal, you see the app roles it holds and the delegated permissions it's been granted. If it's an API permission, you see which workloads carry it and why that matters.

*[Placeholder: insert full-graph screenshot showing users → groups → roles]*

*[Placeholder: insert zoomed view of a service principal node with permission tooltip]*

The "Escalation Risks" panel at the top lists findings sorted by severity. Each one includes:

- **The identity chain** – who or what starts the path
- **The attack narrative** – exactly how you'd abuse it ("add credentials to this app, authenticate as it, assign yourself Global Reader")
- **A reference** – often a link to research from Datadog, Semperis, or Microsoft's own guidance
- **A recommendation** – the least-privilege fix

I wrote those narratives the way I'd explain them in a customer meeting. No jargon unless it's necessary, no "CVE-XYZ-123" unless it actually clarifies the risk.

## Walking Through a Real Scenario

Let's say you run ScEntra and it flags a user named `marketing-automation@contoso.com`. The graph shows:

- This user owns an app registration called `Marketing-Workflow`.
- That app registration has a service principal with `Application.ReadWrite.All` and `AppRoleAssignment.ReadWrite.All`.
- The app is used by a Logic App to provision new marketing accounts, which explains why it needs those permissions.

ScEntra's finding explains: "An identity with `Application.ReadWrite.All` can add credentials to any app, including high-privilege service principals. Combined with `AppRoleAssignment.ReadWrite.All`, this identity can grant itself any role in the directory, effectively becoming Global Administrator."

The remediation recommendation: move the app to a managed identity, scope it with administrative units or custom roles, and remove the owner assignment from the regular user account. That's the conversation I need to have with the customer, and ScEntra just handed me the proof.

## ScEntra vs. BloodHound

People ask how this compares to BloodHound. I use BloodHound on engagements where I need deep, custom graph queries—especially in hybrid environments where I'm bridging on-prem AD and Entra. It's a phenomenal tool, and AzureHound's Entra collection is rock-solid.

ScEntra is narrower and opinionated. It's PowerShell-only, runs entirely against Graph, produces a standalone HTML report, and focuses on administrator-facing narratives rather than offensive modeling. I don't need Neo4j running, I don't need to teach a customer Cypher, and the artifacts I generate fit directly into compliance workflows.

If you're a red teamer, BloodHound is probably still your first choice. If you're a tenant administrator who wants a repeatable monthly assessment that non-technical stakeholders can read, ScEntra is built for you.

## Technical Details That Matter

ScEntra talks to Graph using the same scopes you'd grant to any privileged reader:

- `User.Read.All`, `Group.Read.All`, `Application.Read.All` for inventory
- `RoleManagement.Read.Directory` for role assignments
- `RoleEligibilitySchedule.Read.Directory` and `RoleAssignmentSchedule.Read.Directory` for PIM
- `PrivilegedAccess.Read.AzureADGroup` for PIM-enabled group discovery

If you're missing one of the core scopes—say, `RoleManagement.Read.Directory`—the module detects it early and aborts with a clear message. I spent time tightening those checks recently because nothing's worse than running an analysis for fifteen minutes only to realize half the data is missing.

The graph builder (`New-ScEntraGraphData`) normalizes everything into nodes and edges, then layers on metadata so the visualization can highlight privilege paths. The escalation analyzer walks the graph looking for known-bad patterns:

- Service principals with `Domain.ReadWrite.All` (SAML token forgery risk)
- Apps with `RoleManagement.ReadWrite.Directory` (can self-elevate)
- PIM-enabled groups owned by non-admins (activation without oversight)
- Workload identities with `DeviceManagementConfiguration.ReadWrite.All` (Intune script injection on PAWs)

Each pattern ties back to a real-world attack technique, usually something I've seen abused or read about in incident reports.

## What's Next

I'm actively expanding the dataset. Conditional access policies should show up in the graph so you can see which privilege paths are actually gated. Intune device compliance might layer in so you understand which workload identities can touch privileged-access workstations. I'm also considering a VS Code webview so you can explore the graph without leaving your editor.

The permission handling just got a major overhaul—if you run the latest commit, you'll see cleaner warnings and early exits when critical scopes are missing. I'm also working on better diff tooling so you can compare two reports and see exactly what changed month-over-month.

If you want to contribute, the repository structure is straightforward: `Public/` for exported cmdlets, `Private/` for helpers, and everything talks through `GraphHelpers.ps1` for consistency. I accept pull requests and I'm responsive in issues—I built this because I needed it, but I want it to work for everyone doing Entra security.

## How to Get Started

Clone the repo, import the module, authenticate:

```powershell
Import-Module ./ScEntra.psd1
Connect-ScEntraGraph -UseDeviceCode
Invoke-ScEntraAnalysis -OutputPath ./Reports/MyTenant.html
```

The device code flow opens a browser, you consent to the scopes, and the module caches the token for the session. The analysis takes anywhere from two to ten minutes depending on tenant size. When it finishes, open the HTML file and start exploring.

If you find an escalation path I didn't anticipate, screenshot it and send it to me—either via [LinkedIn](https://www.linkedin.com/in/rogierdijkman) or in the repo issues. The best way to improve ScEntra is to see how it performs against tenants I've never touched.

---

ScEntra isn't trying to replace every identity security tool on the market. It's the tool I wish I'd had three years ago when I was manually assembling privilege maps in OneNote. If you're responsible for an Entra tenant and you've ever wondered "who can actually become an admin here," this module will answer that question faster and more accurately than any spreadsheet. And if the graph reveals something alarming, at least you'll have the visual evidence to justify the remediation budget.

*Rogier Dijkman*  
[LinkedIn](https://www.linkedin.com/in/rogierdijkman) • [Medium](https://medium.com/@rogierdijkman)
