# aggrescan.py

##  API Aggregation script to scan URLs / IPs / email addresses for malicious indicators

Created by Daniel Casey

---
### Current Version: *v0.6.0*
### Features
 - Loads API keys from *.apis* file in working directory
 - Scans URLs or IPs (email address scanning functionality not yet implemented)
 - Detects type of scan (URL / IP) automatically
 - Generates summary of completed scans in report format

### Integrated APIs
| API | Scan Type | API Limit(s) | Notes |
|--|--|--|--|
| [AbuseIPDB.com](https://docs.abuseipdb.com/#introduction) | IP | 1000 scans/day
|[Fraudguard.io](https://docs.fraudguard.io/)|IP| 1000 scans/month | API key is split into "username" and "password" components (*see step 4 of Installation section*)
|[Google Safe Browsing](https://developers.google.com/safe-browsing/v4/lookup-api)| URL | ? |
|[Polyswarm.network](https://docs.polyswarm.io/consumers) | URL / IP | 250 scans/day |
|[Promptapi.com](https://promptapi.com/marketplace/description/whois-api#documentation-tab) (Whois)| URL | 100 scans/day |
|[Threatminer.org](https://www.threatminer.org/api.php)|URL / IP|10 scans/min | No registration / key required
|[Urlscan.io](https://urlscan.io/docs/api/)|URL / Email Address| 100 unlisted scans/hr, 1000/day|
|[Virustotal.com](https://developers.virustotal.com/reference/overview)|URL|2 scans/min, 500/day|

*[Useful list of other tools / APIs](https://zeltser.com/lookup-malicious-websites/)*

___

## Installation (for Windows)
*Note: aggrescan has only been tested (so far) in Windows environments. While it should be functional in Linux or MacOS, installation instructions will differ, and will be added in a subsequent release.*

### Step 1: Download and extract latest source code.
Find the latest release from the main page or the Releases page, then download as a .zip archive. Extract the archive to your desired location.

### Step 2 (optional): Create a virtual environment using venv.

Using a virtual environment will allow you to create a copy of your desired python binary and install packages that will be isolated from your main python installation. While this is not strictly necessary, it promotes project organization and dependency management, and doesn't take long to configure.

Once the source files are extracted to the directory you want them in, open a terminal and move to that directory, then enter the following:

    python -m venv .


This will initialize a virtual environment in the current working directory. In order to use this virtual environment, you must activate it by executing one of the activation scripts in the newly created Scripts directory. If you are already in a powershell terminal, you can execute the activation script like so:

    .\Scripts\Activate.ps1

After activation, your prompt should be prefixed with the name of your virtual environment in parentheses. Now, any packages you install with pip will be isolated to your virtual environment until you deactivate it with:

    deactivate

See also the [official documentation for venv](https://docs.python.org/3/library/venv.html).

### Step 3: Install required packages.
You can use pip and the provided requirements.txt file to quickly and easily install all required packages:

    python -m pip install -r requirements.txt

*Note: if you are using a virtual environment, make sure it's activated before installing packages via pip.*

### Step 4: Create and configure API keys.
See the *Integrated APIs* table above for links to register for API access and create your keys.

Once you have a key, uncomment (remove the leading "#" from) the corresponding line in the *apis.txt* file in your working directory and replace the "KEY" placeholder with your actual key.

For example, to configure your key for urlscan.io, change this line:

    #urlscan KEY

to

    urlscan 12345678-ffff-abcd-1234-aabbccdd

---
The Fraudguard API line looks slightly different:

    fraud-guard username|password

These placeholders do not correspond to your actual Fraudguard.io account credentials, they are separate API keys that are passed via HTTP Basic Auth in each request as the username and password respectively, hence the misnomers. You will find them on the API Keys section of your Fraudguard account page. Make sure to leave no whitespace between your keys and the "|" character.

*Note: You can use any combination of keys. Configured keys will be automatically loaded and activate their corresponding scan.*




___

## Usage


    python aggrescan.py [-h] [-q] [-v] target

| argument | description |
|--|--|
| -h, --help | display usage information and exit |
| -q, --quiet | quiet mode: strip color formatting from output (useful for redirection) |
| -v, --verbose | display verbose output |
| target | The URL or IP address to scan

___
