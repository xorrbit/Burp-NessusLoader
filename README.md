# Burp-NessusLoader
Burp Suite extension to import detected web servers from a Nessus scan xml file (.nessus)

Intended Workflow
-----------------
This extension will parse a .nessus file and extract any ports that were identified as web servers, including those encapsulated with TLS. Right now the Burp Suite API does not allow an extension to spider/crawl multiple targets in one task, so instead of spidering/crawling these targets and creating a ton of tasks, it just adds each of them to the current target site map. You can then start scans as required.

Building the extension
---------------------
First thing you'll need to do is export the Burp Extender API Interface files somewhere and then copy them all into the src/burp/ directory. This is done from within Burp Suite itself on the Extender/APIs tab.

After that all you need is Apache Ant installed (it is likely called just 'ant' in your package manager) and running 'ant' will build the jar.
