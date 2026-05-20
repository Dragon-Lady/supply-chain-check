# Maintainer Notes

Repository: https://github.com/Dragon-Lady/supply-chain-check

`supply-chain-check` is the pre-execution package/source review lane. Keep host
incident response in its own repository.

## Local Validation

```powershell
npm test
node bin\supply-chain-check.js C:\path\to\project --report report.json
node bin\supply-chain-check.js C:\path\to\project --json
```

## Adding Indicators

- Add exact package names and versions under `data/packages/`.
- Use `"*"` only when the package name itself is reported malicious for all
  observed versions in the campaign.
- Add source/behavior strings under `data/indicators.json`.
- Add or update smoke tests for every new indicator family.
- Keep docs short, defensive, and free of exploit reproduction steps.

This tool must remain read-only and dependency-free.
