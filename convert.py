from datetime import datetime

import idna
import requests

lists = {
    'AdguardMobileAds': 'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt',
    'AdguardMobileSpyware': 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt',
    'AdguardDNS': 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
    'AdguardCNAMEAds': 'https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt',
    'AdguardCNAMEClickthroughs': 'https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt',
    'AdguardCNAMEMicrosites': 'https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt',
    'AdguardCNAME': 'https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt',
    'AdguardTracking': 'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt',
    'EasyPrivacySpecific': 'https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt',
    'EasyPrivacy3rdParty': 'https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt',
    'EasyPrivacyCNAME': 'https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific_cname.txt',
    'FutaFilter_hosts': 'https://filter.futa.gg/hosts.txt',
    'FutaFilter_nofarm_hosts': 'https://filter.futa.gg/nofarm_hosts.txt',
    'FutaFilter_TW165': 'https://filter.futa.gg/TW165.txt',
    'anti-AD': 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-adguard.txt'
}

for name, url in lists.items():
    print(f"Converting {name}...")

    # Fetch filter list and split into lines.
    response = requests.get(url)
    lines = response.text.split('\n')

    # HOSTS header.
    hosts = f"# {name}\n"
    hosts += f"# Converted from - {url}\n"
    hosts += f"# Last converted - {datetime.now().strftime('%d %b %Y')}\n"
    hosts += "#\n\n"

    domains = []
    exceptions = []

    for f in lines:
        # Skip filter if it matches certain conditions.
        if '.' not in f:
            continue
        if any(c in f for c in ["*", "/", "#", " ", "abp?"]):
            continue
        # Skip exclusion rules.
        if '~' in f:
            continue

        # Skip Adguard HTML filtering syntax.
        if '$$' in f or '$@$' in f:
            continue

        # For $domain syntax, strip domain rules.
        if '$domain' in f and '@@' not in f:
            f = f[:f.find('$domain')]
        elif '=' in f:
            continue

        # Replace filter syntax with HOSTS syntax.
        f = f.replace('||', '').replace('^third-party', '').replace('^', '').replace('$third-party', '') \
            .replace(',third-party', '').replace('$all', '').replace(',all', '') \
            .replace('$image', '').replace(',image', '') \
            .replace(',important', '').replace('$script', '').replace(',script', '').replace('$object', '') \
            .replace(',object', '').replace('$popup', '').replace(',popup', '').replace('$empty', '') \
            .replace('$object-subrequest', '').replace('$document', '').replace('$subdocument', '') \
            .replace(',subdocument', '').replace('$ping', '').replace('$important', '').replace('$badfilter', '') \
            .replace(',badfilter', '').replace('$websocket', '').replace('$cookie', '').replace('$other', '')

        # Workarounds.
        if 'soundcloud.com' == f or 'global.ssl.fastly.net' == f:
            continue

        # Skip rules matching 'xmlhttprequest' for now.
        if 'xmlhttprequest' in f:
            continue

        # Trim whitespace.
        f = f.strip()

        # If starting or ending with '.', skip.
        if f.startswith('.') or f.endswith('.'):
            continue

        # If starting with '-' or '_' or '!', skip.
        if f.startswith(('-', '_', '!')):
            continue

        # Strip trailing |.
        if f.endswith('|'):
            f = f[:-1]

        # Skip file extensions.
        if f.endswith(('.jpg', '.gif')):
            continue

        # Strip port numbers.
        if ':' in f:
            f = f[:f.find(':')]

        # Convert internationalized domain names to punycode.
        if idna and any(ord(char) > 127 for char in f):
            f = idna.encode(f).decode()

        # If empty, skip.
        if not f:
            continue

        # Save exception
        if f.startswith('@@'):
            exceptions.append(f"0.0.0.0 {f.replace('@@', '')}")
            continue

        domains.append(f"0.0.0.0 {f}")

    # Generate the hosts list.
    if domains:
        # Filter out duplicates.
        domains = list(set(domains))

        # Remove exceptions.
        if exceptions:
            domains = list(set(domains) - set(exceptions))

        domains.sort()
        hosts += '\n'.join(domains)
        del domains

    # Output the file.
    with open(f"{name}.txt", "w") as file:
        file.write(hosts)
    print(f"{name} converted to HOSTS file - {name}.txt\n")
