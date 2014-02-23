Read the blog entry about project sonar
--------
https://community.rapid7.com/community/infosec/sonar/blog/2013/09/26/welcome-to-project-sonar

Where to grab the 15G of compressed cert data files
--------
https://scans.io/study/sonar.ssl

Prepping your environment for python module install
-----
sudo apt-get install python-pip

sudo pip install --upgrade setuptools

Built-in python module bz2 can not decode multi-stream files, which is
how pbzip2 encodes them.  Project Sonar encoded the cert files with pbzip2,
so we need to install the bz2file module from PyPI. 

Read about the module
-----
https://github.com/nvawda/bz2file

Install the module
-----
sudo pip install bz2file

To support MaxMind GeoIP reading, I used this module:
-----
https://github.com/appliedsec/pygeoip

To install it
-----
sudo pip install pygeoip

About the cert files
-----
Each pbzip2-compressed file contains the information about one host on one line, in JSON format (see example cert in z-example-sonar-cert-record-unzipped.txt).  Within the JSON string is an array of certificates, with the first being the host certificate, and others, when provided being certificates in the CA chain.  Within each certificate section, the certificate is Base64 encoded.  Inside the Base64 encoding, the certificate is x509 encoded.  Within the x509 encoding is information about the Issuer and Subject (among other things).  I used the Issuer.organizationName and Subject.organizationName data in a comparison and when these two data elements matched, am making the non-deterministic decision that the certificate is self-signed.  While the vast majority (~19 million) of records parse correctly, some relatively small number (~12 thousand) do not, and those are counted within the error numbers in the log file.  Also, when reviewing the output data, some limited number of records apprear to have either gibberish entries or certificate creation mistake entries (e.g., Subject of --, or -*-, or 1234567).

Note about self-signed certs
-----
It is VERY common for large organizations to manage their own Certificate Authority, issue all their own certs, etc. An example of this is the US Government (.mil, .gov, etc), Google, various large ISPs, etc.  These large issuers actually do have processes that include root certs, signing certs, and individually signed CSRs, CRL/OCSP management, etc.  These cases should be considered differently tha one-off self-signed certificate that gets generated by an individual or software install, which of course, has no CA, CRL, etc. 

Github limitations
-----
It was my intention to (improperly) use Github to post the full output of z-ssc-hostIp-commonName-organizationName.txt, which included 10,780,056 records.  However, uncompressed it's 474MB, and gzip compressed it's 143MB.  Github warns at 50MB upload size and barfs at 100MB, so I removed that file from the repo and instead provided a sample file containing the first 10,000 entries from it as z-example-10000-ssc-hostIp-commonName-organizationName-piped.txt.  If you want the entire file, download the Project Sonar data, load a few Python module dependencies (listed above), and run my sonar-ssc-info-harvester.py script.

Some commands used 
-----

./sonar-ssc-info-harvester.py

cut -d\| -f1 z-ssc-hostIp-commonName-organizationName.txt | ./address-2-geoip-country-name.py | sort | uniq -c > z-ssc-count-by-cn.txt

sed 's/^\s*//'  z-ssc-count-by-cc.txt | sed 's/ /|/' > z-ssc-count-by-cc-piped.txt

grep '^23.' z-ssc-hostIp-commonName-organizationName.txt | less

cut -d\| -f2 z-ssc-hostIp-commonName-organizationName.txt | grep '.com$' > z-ssc-dot-com.txt

grep '^1|' z-org-name-counts-piped.txt > z-org-name-counts-piped-one-counts.txt

sed 's/ /|/' z-org-name-counts.txt > z-org-name-counts-piped.txt
