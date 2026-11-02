## Summary

What problem does this pull request solve?

## Changes

- 
- 

## Testing

Command used:

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest app/tests/ -q -p no:cacheprovider
```

Result:

## Screenshots / evidence

For UI changes, include screenshots using synthetic data only.

## Checklist

- [ ] The change keeps local scans offline.
- [ ] Public lookups still require an explicit user action.
- [ ] Unavailable data is reported as a coverage gap, not as "nothing found".
- [ ] Tests were added or updated for the changed behaviour.
- [ ] Documentation was updated if needed.
- [ ] No personal data, secrets, or generated scan databases are included.
