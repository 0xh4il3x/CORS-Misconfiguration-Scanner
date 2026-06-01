### Install dependency
```python
pip install requests
```

### Scan a single target
```python
python cors_scanner.py -u https://api.example.com
```

### Verbose output (shows evidence + remediation)
```python
python cors_scanner.py -u https://api.example.com --verbose
```

### Bulk scan from file, 20 threads, save JSON report
```python
python cors_scanner.py -f targets.txt --threads 20 --output report.json
```

### Only show vulnerable targets (CI/CD mode)
```python
python cors_scanner.py -f targets.txt --quiet
```

### Skip SSL verification (for internal/staging targets)
```python
python cors_scanner.py -u https://internal.corp --no-ssl-verify
```
