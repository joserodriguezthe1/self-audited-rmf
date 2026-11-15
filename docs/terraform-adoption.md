# Adopting the live system into Terraform

The system was first built by hand in the console and CLI, recorded step by step in build notes. This runbook brings every live resource under Terraform without recreating anything, so `terraform plan` becomes the CM-2 baseline check: any difference between code and account is drift.

Run everything in AWS CloudShell (us-east-1) as the administrator. No access keys are needed.

## 1. Install Terraform and get the repo

```bash
mkdir -p ~/bin && cd /tmp
curl -sSLO https://releases.hashicorp.com/terraform/1.13.4/terraform_1.13.4_linux_amd64.zip
unzip -o terraform_1.13.4_linux_amd64.zip -d ~/bin && ~/bin/terraform version
export PATH=~/bin:$PATH
# The AWS provider is several hundred MB; keep it out of the 1 GB CloudShell home folder
export TF_DATA_DIR=/tmp/tfdata
```

Upload the repo zip (Actions, Upload file), then `cd ~ && unzip -o self-audited-rmf.zip && cd self-audited-rmf`.

## 2. Set your values and read the account

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
nano terraform/terraform.tfvars          # admin user, emails, phone, your name
python3 scripts/discover.py              # writes imports.tf, discovered.auto.tfvars.json, backend.hcl
```

`discover.py` only reads. It exits with warnings if something it expects is missing; fix those first.

## 3. Plan

```bash
cd terraform
terraform init -backend-config=backend.hcl
terraform plan -out tfplan | tee /tmp/plan.txt
grep -E "Plan:|to import" /tmp/plan.txt
```

Expect every resource to show as an import. Then work through anything marked `~ update`, `+ create`, `-/+ replace`, or `- destroy`:

| What you see | Usually means | Fix |
| --- | --- | --- |
| `~ update` on a setting | The console default differs from the code | Change the code to match the account (the account is the as-built baseline) unless the account is wrong |
| `~ update` on Lambda `source_code_hash` or `filename` | Terraform zips the code differently from the console upload | Expected once; same code |
| `~ update` on `aws_s3_object` | No stored hash yet for the imported object | Expected once |
| `~ update` adding tags | A resource was created without the two tags | Expected; Terraform adds them |
| `+ create` | A resource has no import block or a different name | Check `imports.tf` and the name in the account |
| `-/+ replace` | A setting that cannot change in place differs | Stop. Fix the code before applying |
| `- destroy` | Never expected | Stop |

Re-run `terraform plan -out tfplan` after each fix.

## 4. Apply once, then prove zero drift

When the plan shows only imports and the expected one-time updates:

```bash
terraform apply tfplan
terraform plan          # must say: No changes. Your infrastructure matches the configuration.
rm imports.tf           # imports are done; keep the code clean
```

Save the final `No changes` output in the build record. That line is the CM-2 evidence.
