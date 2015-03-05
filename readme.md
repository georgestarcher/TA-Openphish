# TA-Openphish : Splunk Add-on for Openphish.com Feeds

Author: George Starcher (starcher)
Email: george@georgestarcher.com

**All materials in this project are provided under the MIT software license. See license.txt for details.**

Openphish is a trademark of Openphish.com. Use of their API is subject to their terms of service.

#Description:

The Splunk Add-on for Openphish is a modular input. Please do not schedule the feed to poll any more frequently than every five minutes per Openphish's policy.

#Requirements:

You will need a Openphish.com login and to know which feed type you were assigned. Extended or Complete.

#SETUP:

1. Create an index such as intel_openphish to receive the feed contents. 

2. Install the TA-Openphish

3. Configure a new Modular Input
    a. Name the Input Feed
    b. Enter your Openphish username
    c. Enter your Openphish password
    d. Enter your feed type: Complete or Extended
    e. If you want to Mimedefang the URLs being indexed enter 1 for MIMEDefang, otherwise enter 0. MIMEDefang replaces the HTTP with HXXP to make it less likely you will click an active hostile link.
    f. *Optional* if you wish to filter on an ASN enter the number such as AS714. You may only enter one ASN. This will cause ONLY data from the feed found at that ASN to be indexed. This is useful if you do not wish to index any data but perhaps your own Network to detect compromised systems hosting phishing sites.
    g. *Optional* if you wish to filter on Brand name enter a keyword such as Apple. This will match Apple, Apple, Inc. etc in the Brand field on the feed. This is useful if you wish to only index data for your Brand. Note you can combine the ASN and Brand filter but is a logical AND combination.
    h. Check the box for More settings.
    
		1. Enter a cron schedule such as the following for every five minutes: */5 * * * *
			
        2. Set the sourcetype of Manual and enter openphish
        	
        3. I recommend using openphish.com as the host value.
        	
        4. Choose the index you created in step 1 at the beginning of the setup. 


#COMMENTS:

1. Do not make more than the one Modular Input for the feed Openphish provided you.
2. The feed data size is fairly small at this time. I recommend just indexing the full feed without filtering on ASN or Brand.
3. This is an early version. I will add login validation later for setting up the Modular Input
4. I have provided Splunk Enterprise Security App threatlist Modular Inputs. They are disabled by default. You need to enable them if you wish the data IP, URL, and Domain to enter into the Threat Intel correlation system. 
5. I have the Scheduled Searches that generate the LOOKUP tables for IP, URL, and Domain set to run hourly. You may choose to make this run more often to help with timely ES correlation.
6. At this time everything relies on the feed data to be indexed. I will make an update that allows you to go straight to Lookup without indexing in the future.


