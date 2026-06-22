# CYRINAE Python3 Scripts

This area contains Python, Pandas and other libraries to do higher level processing of cyber compliance, hygiene, and security data. The main scripts are listed below. And there are additional supplemental python scripts to support the higher level features we are generating here as well. 

Feel free to fork the repo, extend these, add on to them, and submit back for the entire community to use. 

## Install Requests Python Package

You will need to run `pip3 install requests` in order to load that library into your folder. Then you can start with the authentication.py script.

## Install prettytable Python Package

You will need to run `pip3 install prettytable` in order to load that library into your folder. Then you can start with the authentication.py script.

## Optional ReportLab Python Package

The system package overview PDF script can create a basic PDF without extra packages. For a richer PDF layout, install ReportLab.

```
python3 -m pip install reportlab
```

## Optional MatPlotPlb Python Package

The Risk Profiler PDF script and others add histogram charts for grouping of data using this package.

```
python3 -m pip install matplotlib
```

## Example running the System Package Overview PDF

Create a PDF overview report for a system package. The script calls `system-package/get_systempackage_by_systemkey_json.py` with the same required parameters, then writes `OpenRMFPro-System-Package-Overview-<systemKey>.pdf` using the returned `systemKey` value.

```
python3 system-package/get_systempackage_by_systemkey_overview_pdf.py \
  https://example.openrmfpro.local \
  my-application-key \
  my-authorization-token \
  <systemKey>
```

A lot of the examples are used like this to point at a System Package within OpenRMF Professional and create the result.

## MacOS Installation

You may need to run this to setup requests and call the Python3 scripts correctly in a virtual environment.

```
python3 -m venv {{ path/to/venv }}
source {{ path/to/venv/}}bin/activate
python3 -m pip install requests
```

An example is below

```
➜  scripts git:(main) ✗ python3 -m venv ./.env/

➜  scripts git:(main) ✗ source ./.env/bin/activate

(.env) ➜  scripts git:(main) ✗ python3 -m pip install requests prettytable
Collecting requests
  Downloading requests-2.32.5-py3-none-any.whl.metadata (4.9 kB)
Collecting charset_normalizer<4,>=2 (from requests)
  Downloading charset_normalizer-3.4.6-cp313-cp313-macosx_10_13_universal2.whl.metadata (40 kB)
Collecting idna<4,>=2.5 (from requests)
  Downloading idna-3.11-py3-none-any.whl.metadata (8.4 kB)
Collecting urllib3<3,>=1.21.1 (from requests)
  Downloading urllib3-2.6.3-py3-none-any.whl.metadata (6.9 kB)
Collecting certifi>=2017.4.17 (from requests)
  Downloading certifi-2026.2.25-py3-none-any.whl.metadata (2.5 kB)
Downloading requests-2.32.5-py3-none-any.whl (64 kB)
Downloading certifi-2026.2.25-py3-none-any.whl (153 kB)
Downloading charset_normalizer-3.4.6-cp313-cp313-macosx_10_13_universal2.whl (294 kB)
Downloading idna-3.11-py3-none-any.whl (71 kB)
Downloading urllib3-2.6.3-py3-none-any.whl (131 kB)
Installing collected packages: urllib3, idna, charset_normalizer, certifi, requests
Successfully installed certifi-2026.2.25 charset_normalizer-3.4.6 idna-3.11 requests-2.32.5 urllib3-2.6.3

[notice] A new release of pip is available: 25.0 -> 26.0.1
[notice] To update, run: pip install --upgrade pip
(.env) ➜  scripts git:(main) ✗ 
```


## MacOS Sonoma

You may need to run this to setup requests and call the Python3 scripts correctly. Or just use `.env/bin/python` when running your python scripts.

```
python3 -m venv .env
source .env/bin/activate
python3 -m pip install requests
python3 -m pip install pandas
python3 -m pip install reportlab
python3 -m pip install matplotlib
```