# Create the master CVE Database CSV file

* Download all *.json data from the various *.zip files at https://nvd.nist.gov/vuln/data-feeds for the years
* put into this ./example-data/files/cve/ folder
* run the script to create the `master_cve_database.csv` with the python script `/scripts/patch-vulnerability/combine_cve_data.py`
* verify the file was created
* then you can run the `/scripts/patch-vulnerability/` CVE generation python script to use


Update the CVE data as required and re-run for the latest results.