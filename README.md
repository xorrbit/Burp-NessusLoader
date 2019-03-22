# Burp-NessusLoader
Burp Suite extension to import detected web servers from a Nessus scan xml file (.nessus)

Building
--------
First thing you'll need to do is export the Burp Extender API Interface files somewhere and then copy them all into the src/burp/ directory. This is done from within Burp Suite itself on the Extender/APIs tab.

After that all you need is Apache Ant installed (it is likely called just 'ant' in your package manager) and running 'ant' will build the jar.
