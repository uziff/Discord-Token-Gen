def chrome_v():
    out = subprocess.run(
        r'reg query "HKEY_CURRENT_USER\Software\Google\Chrome\BLBeacon" /v version',
        capture_output=True, text=True, shell=True
    ).stdout
    m = re.search(r"(\d+)\.", out)
    return int(m.group(1)) if m else None